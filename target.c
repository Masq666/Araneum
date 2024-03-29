/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License. For a copy,
 * see http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include "global.h"
#include "alternative.h"
#include "libstr.h"
#include "libfs.h"
#include "target.h"
#include "httpauth.h"
#include "log.h"
#include "cgi.h"
#include "send.h"
#ifdef HAVE_CACHE
#include "cache.h"
#endif

#define MAX_VOLATILE_SIZE      1 * MEGABYTE
#define FILE_BUFFER_SIZE      32 * KILOBYTE
#define MAX_CGI_HEADER        16 * KILOBYTE
#define CGI_BUFFER_SIZE       32 * KILOBYTE
#define MAX_TRACE_HEADER       2 * KILOBYTE
#define VALUE_SIZE            64
#define WAIT_FOR_LOCK          3
#define FILESIZE_BUFFER_SIZE  30

#define rs_QUIT       -1
#define rs_DISCONNECT -2
#define rs_FORCE_QUIT -3

#define NEW_FILE -1

char *hs_chunked = "Transfer-Encoding: chunked\r\n";
char *hs_allow   = "Allow: GET, HEAD, OPTIONS";
char *hs_post    = ", POST";
char *hs_trace   = ", TRACE";
char *hs_alter   = ", PUT, DELETE";

extern char *fb_filesystem;
extern char *fb_symlink;
extern char *fb_alterlist;
extern char *hs_eol;
extern char *hs_conlen;
extern char *hs_contyp;

/**
    Read a file from disk and send it to the client.
*/
int send_file(t_session *session) {
    char *referer, *buffer = NULL, value[VALUE_SIZE + 1], *pos, *date, *range, *range_begin, *range_end, *new_fod;
    long bytes_read, total_bytes, size, speed;
    off_t file_size, send_begin, send_end, send_size;
    int  retval, handle;
    bool invalid_referer, prot_oke;
    struct stat status;
    struct tm *fdate;
#ifdef HAVE_CACHE
    t_cached_object *cached_object;
#endif

    session->mimetype = get_mimetype(session->extension, session->config->mimetype);

    /* Check the referer */
    if ((session->host->image_referer.size > 0) && (session->mimetype != NULL)) {
        if (strncmp(session->mimetype, "image/", 6) == 0) {
            invalid_referer = true;
            if ((referer = get_headerfield("Referer:", session->headerfields)) != NULL) {
                if (strncmp(referer, "http://", 7) == 0) {
                    prot_oke = true;
                    referer += 7;
                } else if (strncmp(referer, "https://", 8) == 0) {
                    prot_oke = true;
                    referer += 8;
                } else {
                    prot_oke = false;
                }

                if (prot_oke) {
                    if ((pos = strchr(referer, '/')) != NULL) {
                        *pos = '\0';
                    }
                    for (size = 0; size < session->host->image_referer.size; size++) {
                        if (strstr(referer, *(session->host->image_referer.item + size)) != NULL) {
                            invalid_referer = false;
                            break;
                        }
                    }
                    if (pos != NULL) {
                        *pos = '/';
                    }
                }
            }

            if (invalid_referer) {
                if ((new_fod = (char*)malloc(strlen(session->host->imgref_replacement) + 4)) != NULL) { /* + 3 for ".gz" (gzip encoding) */
                    free(session->file_on_disk);
                    session->file_on_disk = new_fod;

                    strcpy(session->file_on_disk, session->host->imgref_replacement);

                    if (get_target_extension(session) == -1) {
                        return 500;
                    }

                    session->mimetype = get_mimetype(session->extension, session->config->mimetype);
                } else {
                    return 500;
                }
            }
        }
    }

    handle = -1;

    /* gzip content encoding */
    if (session->host->use_gz_file) {
        if ((pos = get_headerfield("Accept-Encoding:", session->headerfields)) != NULL) {
            if ((strstr(pos, "gzip")) != NULL) {
                size = strlen(session->file_on_disk);
                memcpy(session->file_on_disk + size, ".gz\0", 4);
                if ((handle = open(session->file_on_disk, O_RDONLY)) != -1) {
                    session->encode_gzip = true;
                } else {
                    *(session->file_on_disk + size) = '\0';
                }
            }
        }
    }

    /* Open the file for reading */
    if (handle == -1) {
        if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
            if (errno == EACCES) {
                log_error(session, fb_filesystem);
                return 403;
            }
            return 404;
        }
    }

    /* Symlink check */
    if (session->host->follow_symlinks == false) {
        switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
        case error:
            close(handle);
            log_error(session, "error while scanning file for symlinks");
            return 500;
        case not_found:
            close(handle);
            return 404;
        case no_access:
        case yes:
            close(handle);
            log_error(session, fb_symlink);
            return 403;
        case no:
            break;
        }
    }

    /* Modified-Since */
    if (session->handling_error == false) {
        if ((date = get_headerfield("If-Modified-Since:", session->headerfields)) != NULL) {
            if (if_modified_since(handle, date) == 0) {
                close(handle);
                return 304;
            }
        } else if ((date = get_headerfield("If-Unmodified-Since:", session->headerfields)) != NULL) {
            if (if_modified_since(handle, date) == 1) {
                close(handle);
                return 412;
            }
        }
    }

    /* Set throttlespeed */
    pos = session->uri + session->uri_len;
    while ((*pos != '.') && (pos != session->uri)) {
        pos--;
    }
    if (*pos == '.') {
        if ((speed = get_throttlespeed(pos, session->config->throttle)) != 0) {
            if ((session->throttle == 0) || (speed < session->throttle)) {
                session->throttle = speed;
            }
        }
        if ((speed = get_throttlespeed(session->mimetype, session->config->throttle)) != 0) {
            if ((session->throttle == 0) || (speed < session->throttle)) {
                session->throttle = speed;
            }
        }
    }

    if ((file_size = filesize(session->file_on_disk)) == -1) {
        close(handle);
        log_error(session, "error while determining filesize");
        return 500;
    }
    send_begin = 0;
    send_end = file_size - 1;
    send_size = file_size;

    /* Range */
    if ((*(session->http_version + 7) == '1') && (session->handling_error == false)) {
        if ((range = get_headerfield("Range:", session->headerfields)) != NULL) {
            if (strncmp(range, "bytes=", 6) == 0) {
                if ((range = strdup(range + 6)) == NULL) {
                    close(handle);
                    return 500;
                }

                if (split_string(range, &range_begin, &range_end, '-') == 0) {

                    if (*range_begin != '\0') {
                        if ((send_begin = str2int(range_begin)) >= 0) {
                            if (*range_end != '\0') {
                                if ((send_end = str2int(range_end)) >= 0) {
                                    /* bytes=XX-XX */
                                    session->return_code = 206;
                                }
                            } else {
                                /* bytes=XX- */
                                session->return_code = 206;
                            }
                        }
                    } else {
                        if ((send_begin = str2int(range_end)) >= 0) {
                            /* bytes=-XX */
                            send_begin = file_size - send_begin;
                            session->return_code = 206;
                        }
                    }

                    if (session->return_code == 206) {
                        if (send_begin >= file_size) {
                            close(handle);
                            free(range);
                            return 416;
                        }
                        if (send_begin < 0) {
                            send_begin = 0;
                        }
                        if (send_end >= file_size) {
                            send_end = file_size - 1;
                        }
                        if (send_begin <= send_end) {
                            send_size = send_end - send_begin + 1;
                        } else {
                            close(handle);
                            free(range);
                            return 416;
                        }
                    }

                    /* Change filepointer offset */
                    if (send_begin > 0) {
                        if (lseek(handle, send_begin, SEEK_SET) == -1) {
                            session->return_code = 200;
                        }
                    }

                    if (session->return_code == 200) {
                        send_begin = 0;
                        send_end = file_size - 1;
                        send_size = file_size;
                    }
                }
                free(range);
            }
        }
    }

    do {
        retval = -1;
        if (send_header(session) == -1) {
            break;
        }
        if (session->return_code == 401) {
            if (session->host->auth_method == basic) {
                send_basic_auth(session);
            } else {
                send_digest_auth(session);
            }
        }

        value[VALUE_SIZE] = '\0';

        /* Last-Modified */
        if (fstat(handle, &status) == -1) {
            break;
        } else if ((fdate = gmtime(&(status.st_mtime))) == NULL) {
            break;
        } else if (send_buffer(session, "Last-Modified: ", 15) == -1) {
            break;
        } else if (strftime(value, VALUE_SIZE, "%a, %d %b %Y %X GMT\r\n", fdate) == 0) {
            break;
        } else if (send_buffer(session, value, strlen(value)) == -1) {
            break;
        }

        /* Content-Range */
        if (session->return_code == 206) {
            if (send_buffer(session, "Content-Range: bytes ", 21) == -1) {
                break;
            } else if (snprintf(value, VALUE_SIZE, "%lld-%lld/%lld\r\n", (long long)send_begin, (long long)send_end, (long long)file_size) == -1) {
                break;
            } else if (send_buffer(session, value, strlen(value)) == -1) {
                break;
            }
        }

        if (send_buffer(session, hs_conlen, 16) == -1) {
            break;
        } else if (snprintf(value, VALUE_SIZE, "%lld\r\n\r\n", (long long)send_size) == -1) {
            break;
        } else if (send_buffer(session, value, strlen(value)) == -1) {
            break;
        }
        session->header_sent = true;

        retval = 200;
        if (session->request_method != HEAD) {
            if (is_volatile_object(session) && (file_size <= MAX_VOLATILE_SIZE)) {
                /* volatile object */
                if ((buffer = (char*)malloc(send_size)) != NULL) {
                    total_bytes = 0;
                    do {
                        if ((bytes_read = read(handle, buffer + total_bytes, send_size - total_bytes)) == -1) {
                            if (errno == EINTR) {
                                bytes_read = 0;
                            }
                        } else {
                            total_bytes += bytes_read;
                        }
                    } while ((bytes_read != -1) && (total_bytes < send_size));
                    if (bytes_read != -1) {
                        if (send_buffer(session, buffer, send_size) == -1) {
                            retval = -1;
                        }
                    } else {
                        retval = -1;
                    }
                } else {
                    retval = -1;
                }
            } else {
                /* Normal file */
#ifdef HAVE_CACHE
                if ((cached_object = search_cache(session, session->file_on_disk)) == NULL) {
                    cached_object = add_to_cache(session, session->file_on_disk);
                }

                if (cached_object != NULL) {
                    if (send_begin + send_size > cached_object->size) {
                        done_with_cached_object(cached_object, true);
                        cached_object = NULL;
                    }
                }

                if (cached_object != NULL) {
                    if (send_buffer(session, cached_object->data + send_begin, send_size) == -1) {
                        retval = -1;
                    }
                    done_with_cached_object(cached_object, false);
                } else
#endif
                    if ((buffer = (char*)malloc(FILE_BUFFER_SIZE)) != NULL) {
                        while ((send_size > 0) && (retval == 200)) {
                            switch ((bytes_read = read(handle, buffer, FILE_BUFFER_SIZE))) {
                            case -1:
                                if (errno != EINTR) {
                                    retval = -1;
                                }
                                break;
                            case 0:
                                send_size = 0;
                                break;
                            default:
                                if (bytes_read > send_size) {
                                    bytes_read = send_size;
                                }
                                if (send_buffer(session, buffer, bytes_read) == -1) {
                                    retval = -1;
                                }
                                send_size -= bytes_read;
                            }
                        }
                    } else {
                        retval = -1;
                    }
            }
            if (buffer != NULL) {
                free(buffer);
            }
        }
    } while (false);
    close(handle);

    return retval;
}

/**
    Run a CGI program and send output to the client.
*/
int execute_cgi(t_session *session) {
    int retval = 200, result, handle, len;
    char *line, *new_line, *contyp_start, *contyp_end, *code, c;
    bool in_body = false, send_in_chunks = true, wrap_cgi;
#ifdef CYGWIN
    char *old_path, *win32_path;
#endif
    t_cgi_result cgi_result;
    t_connect_to *connect_to;
    t_cgi_info cgi_info;
    pid_t cgi_pid = -1;

    if (session->cgi_type != fastcgi) {
        wrap_cgi = (session->host->wrap_cgi != NULL) ||
                   ((session->local_user != NULL) && session->config->wrap_user_cgi);
    } else {
        wrap_cgi = false;
    }

    /* HTTP/1.0 does not support chunked Transfer-Encoding. */
    if (*(session->http_version + 7) == '0') {
        session->keep_alive = false;
    }

    if ((wrap_cgi == false) && (session->cgi_type != fastcgi)) {
        if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
            if (errno == EACCES) {
                log_error(session, fb_filesystem);
                return 403;
            }
            return 404;
        } else {
            close(handle);
        }
    }

    if (session->host->execute_cgi == false) {
        log_error(session, "CGI execution not allowed");
        return 403;
    }

#ifdef CYGWIN
    if ((session->config->platform == windows) && (session->cgi_type == binary)) {
        chmod(session->file_on_disk, 0755);
    }
#endif

    if ((wrap_cgi == false) && (session->cgi_type != fastcgi)) {
        if (session->cgi_type == binary) {
            switch (can_execute(session->file_on_disk, session->config->server_uid, session->config->server_gid, &(session->config->groups))) {
            case error:
                log_error(session, "error during CGI preprocess");
                return 500;
            case not_found:
                return 404;
            case no_access:
            case no:
                log_error(session, fb_filesystem);
                return 403;
            case yes:
                break;
            }
        }

        if (session->host->follow_symlinks == false) {
            switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
            case error:
                log_error(session, "error while searching for symlinks in CGI path");
                return 500;
            case not_found:
                return 404;
            case no_access:
            case yes:
                log_error(session, fb_symlink);
                return 403;
            case no:
                break;
            }
        }
    }

    /* Prevent Cross-site Scripting */
    if (session->host->prevent_xss) {
        prevent_xss(session);
    }

    /* Prevent Cross-site Request Forgery */
    if (session->host->prevent_csrf) {
        prevent_csrf(session);
    }

    if (session->host->prevent_sqli) {
        /* Prevent SQL injection */
        if (session->vars != NULL) {
            switch (prevent_sqli(session, session->vars, strlen(session->vars), &line)) {
            case -1:
                return 500;
            case 0:
                break;
            default:
                if (session->config->ban_on_sqli > 0) {
                    free(line);
                    return rr_SQL_INJECTION;
                }
                if (register_tempdata(&(session->tempdata), line, tc_data) == -1) {
                    free(line);
                    return -1;
                }
                session->vars = line;
            }
        }

        if (session->body != NULL) {
            switch (result = prevent_sqli(session, session->body, session->content_length, &line)) {
            case -1:
                return 500;
            case 0:
                break;
            default:
                if (session->config->ban_on_sqli > 0) {
                    free(line);
                    return rr_SQL_INJECTION;
                }
                if (register_tempdata(&(session->tempdata), line, tc_data) == -1) {
                    free(line);
                    return -1;
                }
                session->body = line;
                session->content_length = result;
            }
        }

        if (session->cookie != NULL) {
            switch (prevent_sqli(session, session->cookie, strlen(session->cookie), &line)) {
            case -1:
                return 500;
            case 0:
                break;
            default:
                if (session->config->ban_on_sqli > 0) {
                    free(line);
                    return rr_SQL_INJECTION;
                }
                if (register_tempdata(&(session->tempdata), line, tc_data) == -1) {
                    free(line);
                    return -1;
                }
                session->cookie = line;
            }
        }
    }

    cgi_info.type = session->cgi_type;
    cgi_info.input_buffer_size = cgi_info.error_buffer_size = CGI_BUFFER_SIZE;
    cgi_info.input_len = cgi_info.error_len = 0;

#ifdef CYGWIN
    if ((session->config->platform == windows) && ((session->cgi_type == fastcgi) || (session->cgi_type == script))) {
        if ((old_path = strdup(session->file_on_disk)) == NULL) {
            return -1;
        }
        if ((win32_path = strdup(cygwin_to_windows(old_path))) == NULL) {
            free(old_path);
            return -1;
        }
        free(session->file_on_disk);
        session->file_on_disk = win32_path;
        free(old_path);
    }
#endif

    if (session->cgi_type == fastcgi) {
        cgi_info.read_header = true;
        if ((connect_to = select_connect_to(session->fcgi_server, &(session->ip_address))) == NULL) {
            return 503;
        } else if ((cgi_info.from_cgi = connect_to_fcgi_server(connect_to)) == -1) {
            connect_to->available = false;
            log_string(session->config->system_logfile, "can't connect to FastCGI server %s", session->fcgi_server->fcgi_id);
            return 503;
        } else {
            connect_to->available = true;
            if (send_fcgi_request(session, cgi_info.from_cgi) == -1) {
                log_error(session, "error while sending data to FastCGI server");
                return 500;
            }
        }
    } else {
        cgi_info.wrap_cgi = wrap_cgi;
        if ((cgi_pid = fork_cgi_process(session, &cgi_info)) == -1) {
            log_error(session, "error while forking CGI process");
            return 500;
        }
    }

    if ((cgi_info.input_buffer = (char*)malloc(cgi_info.input_buffer_size + 1)) == NULL) {
        retval = -1;
    } else if ((cgi_info.error_buffer = (char*)malloc(cgi_info.error_buffer_size + 1)) == NULL) {
        free(cgi_info.input_buffer);
        retval = -1;
    }

    if (retval != 200) {
        if (session->cgi_type == fastcgi) {
            close(cgi_info.from_cgi);
        } else {
            close(cgi_info.to_cgi);
            close(cgi_info.from_cgi);
            close(cgi_info.cgi_error);
        }
        return retval;
    }

    cgi_info.deadline = session->time + session->host->time_for_cgi;

    do {
        if (time(NULL) > cgi_info.deadline) {
            cgi_result = cgi_TIMEOUT;
        } else if (session->cgi_type == fastcgi) {
            cgi_result = read_from_fcgi_server(session, &cgi_info);
        } else {
            cgi_result = read_from_cgi_process(session, &cgi_info);
        }

        switch (cgi_result) {
        case cgi_ERROR:
            log_error(session, "error while executing CGI");
            retval = 500;
            break;
        case cgi_TIMEOUT:
            log_error(session, "CGI timeout");
            if (in_body) {
                retval = rs_DISCONNECT;
            } else {
                retval = 500;
            }
            if (session->config->kill_timedout_cgi && (session->cgi_type != fastcgi)) {
                if (kill(cgi_pid, SIGTERM) != -1) {
                    sleep(1);
                    kill(cgi_pid, SIGKILL);
                }
            }
            break;
        case cgi_FORCE_QUIT:
            retval = rs_FORCE_QUIT;
            break;
        case cgi_OKE:
            if (cgi_info.error_len > 0) {
                /* Error received from CGI */
                *(cgi_info.error_buffer + cgi_info.error_len) = '\0';
                log_cgi_error(session, cgi_info.error_buffer);
                cgi_info.error_len = 0;
            }

            if (cgi_info.input_len > 0) {
                /* Data received from CGI */
                if (in_body) {
                    /* Read content */
                    if (session->request_method != HEAD) {
                        if (send_in_chunks) {
                            result = send_chunk(session, cgi_info.input_buffer, cgi_info.input_len);
                        } else {
                            result = send_buffer(session, cgi_info.input_buffer, cgi_info.input_len);
                        }
                        if (result == -1) {
                            retval = rs_DISCONNECT;
                        }
                    }
                    cgi_info.input_len = 0;
                } else {
                    /* Read HTTP header */
                    *(cgi_info.input_buffer + cgi_info.input_len) = '\0';

                    if ((new_line = strstr(cgi_info.input_buffer, "\r\n\r\n")) == NULL) {
                        /* Fix crappy CGI headers */
                        if ((result = fix_crappy_cgi_headers(&cgi_info)) == -1) {
                            retval = 500;
                            break;
                        } else if (result == 0) {
                            new_line = strstr(cgi_info.input_buffer, "\r\n\r\n");
                        }
                    }

                    if (new_line != NULL) {
                        *(new_line + 2) = '\0';
                        if (session->throttle == 0) {
                            if ((contyp_start = strcasestr(cgi_info.input_buffer, hs_contyp)) != NULL) {
                                if ((contyp_end = strchr(contyp_start, '\r')) != NULL) {
                                    contyp_start += 14;
                                    c = *contyp_end;
                                    *contyp_end = '\0';
                                    session->throttle = get_throttlespeed(contyp_start, session->config->throttle);
                                    *contyp_end = c;
                                }
                            }
                        }

                        if (session->expires > -1) {
                            if (strcasestr(cgi_info.input_buffer, "\nExpires:") != NULL) {
                                session->expires = -1;
                            }
                        }

                        if (strcasestr(cgi_info.input_buffer, "\nLocation:") != NULL) {
                            session->return_code = 302;
                            if (send_header(session) == -1) {
                                retval = rs_DISCONNECT;
                                break;
                            }
                        } else if (session->host->trigger_on_cgi_status && ((code = strcasestr(cgi_info.input_buffer, "Status: ")) != NULL)) {
                            line = code += 8;

                            retval = -1;
                            while (*line != '\0') {
                                if ((*line == '\r') || (*line == ' ')) {
                                    c = *line;
                                    *line = '\0';
                                    retval = str2int(code);
                                    *line = c;

                                    *(new_line + 2) = '\r';
                                    break;
                                }
                                line++;
                            }

                            if (retval <= 0) {
                                log_error(session, "invalid status code received from CGI");
                                retval = 500;
                                break;
                            }
                            session->return_code = retval;
                            if (retval == 200) {
                                if (send_header(session) == -1) {
                                    retval = rs_DISCONNECT;
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else if (send_header(session) == -1) {
                            retval = rs_DISCONNECT;
                            break;
                        }
                        if (session->return_code == 401) {
                            if (session->host->auth_method == basic) {
                                send_basic_auth(session);
                            } else {
                                send_digest_auth(session);
                            }
                        }
                        if ((strcasestr(cgi_info.input_buffer, hs_conlen) != NULL) || (session->keep_alive == false)) {
                            send_in_chunks = false;
                        } else if (send_buffer(session, hs_chunked, 28) == -1) {
                            retval = rs_DISCONNECT;
                            break;
                        }
                        *(new_line + 2) = '\r';

                        /* Send the header. */
                        new_line += 4;
                        len = new_line - cgi_info.input_buffer;
                        if (send_buffer(session, cgi_info.input_buffer, len) == -1) {
                            retval = rs_DISCONNECT;
                            break;
                        }
                        if (send_buffer(session, NULL, 0) == -1) {
                            retval = rs_DISCONNECT;
                            break;
                        }
                        session->header_sent = true;

                        /* Send first part of the body */
                        if (session->request_method != HEAD) {
                            if ((len = cgi_info.input_len - len) > 0) {
                                if (send_in_chunks) {
                                    result = send_chunk(session, new_line, len);
                                } else {
                                    result = send_buffer(session, new_line, len);
                                }
                                if (result == -1) {
                                    retval = rs_DISCONNECT;
                                    break;
                                }
                            }
                            /*
                            							} else {
                            								// This will speed up things, but also disrupt the CGI process.
                            								retval = rs_QUIT;
                            								break;
                            */
                        }

                        in_body = true;
                        cgi_info.input_len = 0;
                    } else if (cgi_info.input_len > MAX_CGI_HEADER) {
                        log_error(session, "CGI's HTTP header too large");
                        retval = 500;
                        break;
                    }
                }
            }
            break;
        case cgi_END_OF_DATA:
            if (in_body) {
                retval = rs_QUIT;
                if (send_in_chunks) {
                    if (send_chunk(session, NULL, 0) == -1) {
                        retval = rs_DISCONNECT;
                    }
                }
            } else {
                if (cgi_info.input_len == 0) {
                    log_error(session, "no output");
                } else {
                    log_error(session, "CGI only printed a HTTP header, no content");
                }
                retval = 500;
            }
        } /* switch */
    } while (retval == 200);

    if (session->cgi_type == fastcgi) {
        close(cgi_info.from_cgi);
    } else {
        close(cgi_info.to_cgi);
        if (cgi_info.from_cgi != -1) {
            close(cgi_info.from_cgi);
        }
        if (cgi_info.cgi_error != -1) {
            close(cgi_info.cgi_error);
        }
    }

    if (session->config->wait_for_cgi && (cgi_pid != -1)) {
        waitpid(cgi_pid, NULL, 0);
    }

    switch (retval) {
    case rs_DISCONNECT:
    case rs_FORCE_QUIT:
        session->keep_alive = false;
    case rs_QUIT:
        retval = 200;
    }

    free(cgi_info.input_buffer);
    free(cgi_info.error_buffer);

    return retval;
}

/**
    Send the result of an OPTIONS request method to the client.
*/
int handle_options_request(t_session *session) {
    int code = 200, handle;

    if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
        if (errno == EACCES) {
            log_error(session, fb_filesystem);
            code = 403;
        } else if (session->uri_is_dir) {
            code = 501;
        } else {
            code = 404;
        }
    } else {
        close(handle);
    }
    if (session->host->follow_symlinks == false) {
        switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
        case error:
            log_error(session, "error while scanning file for symlinks");
            code = 500;
            break;
        case not_found:
            code = 404;
            break;
        case no_access:
        case yes:
            log_error(session, fb_symlink);
            code = 403;
            break;
        case no:
            break;
        }
    }

    session->return_code = code;
    if (send_header(session) == -1) {
        return -1;
    } else if (send_buffer(session, hs_allow, 25) == -1) {
        return -1;
    } else if (session->cgi_type != no_cgi) {
        if (send_buffer(session, hs_post, 6) == -1) {
            return -1;
        }
    }

    if (session->binding->enable_trace) {
        if (send_buffer(session, hs_trace, 7) == -1) {
            return -1;
        }
    }

    if (session->binding->enable_alter) {
        if (send_buffer(session, hs_alter, 13) == -1) {
            return -1;
        }
    }

    if (send_buffer(session, hs_eol, 2) == -1) {
        return -1;
    } else if (send_buffer(session, hs_conlen, 16) == -1) {
        return -1;
    } else if (send_buffer(session, "0\r\n\r\n", 5) == -1) {
        return -1;
    }
    session->header_sent = true;

    return 200;
}

int handle_trace_request(t_session *session) {
    int result = -1, code, body_size;
    size_t len;
    char buffer[MAX_TRACE_HEADER + 1];
    t_headerfield *header;

    body_size = 3;
    body_size += strlen(session->method) + session->uri_len;
    if (session->vars != NULL) {
        body_size += 1 + strlen(session->vars);
    }
    body_size += strlen(session->http_version);

    header = session->headerfields;
    while (header != NULL) {
        body_size += strlen(header->data) + 1;
        header = header->next;
    }

    buffer[MAX_TRACE_HEADER] = '\0';

    do {
        /* Header */
        if (snprintf(buffer, MAX_TRACE_HEADER, "%d\r\nContent-Type: message/http\r\n\r\n", body_size) < 0) {
            break;
        } else if (send_header(session) == -1) {
            break;
        } else if (send_buffer(session, hs_conlen, 16) == -1) {
            break;
        } else if (send_buffer(session, buffer, strlen(buffer)) == -1) {
            break;
        }
        session->header_sent = true;

        /* Body */
        if ((code = snprintf(buffer, MAX_TRACE_HEADER, "%s %s", session->method, session->uri)) < 0) {
            break;
        } else if (code >= MAX_TRACE_HEADER) {
            break;
        } else if (session->vars != NULL) {
            len = strlen(buffer);
            if ((code = snprintf(buffer + len, MAX_TRACE_HEADER - len, "?%s", session->vars)) < 0) {
                break;
            } else if (code >= MAX_TRACE_HEADER) {
                break;
            }
        }
        len = strlen(buffer);
        if ((code = snprintf(buffer + len, MAX_TRACE_HEADER - len, " %s\r\n", session->http_version)) < 0) {
            break;
        } else if (send_buffer(session, buffer, strlen(buffer)) == -1) {
            break;
        }

        header = session->headerfields;
        while (header != NULL) {
            len = strlen(header->data);
            *(header->data + len) = '\n';
            if (send_buffer(session, header->data, len + 1) == -1) {
                *(header->data + len) = '\0';
                result = -2;
                break;
            }
            *(header->data + len) = '\0';
            header = header->next;
        }
        if (result == -2) {
            break;
        }

        result = 200;
    } while (false);

    return result;
}

static t_access allow_alter(t_session *session) {
    char *x_forwarded_for;
    t_ip_addr forwarded_ip;
    t_access access;

    if ((access = ip_allowed(&(session->ip_address), session->host->alter_list)) != allow) {
        return access;
    } else if ((x_forwarded_for = get_headerfield("X-Forwarded-For:", session->headerfields)) == NULL) {
        return allow;
    } else if (parse_ip(x_forwarded_for, &forwarded_ip) == -1) {
        return allow;
    } else if (ip_allowed(&forwarded_ip, session->host->alter_list) == deny) {
        return deny;
    }

    return unspecified;
}

int handle_put_request(t_session *session) {
    int handle_write, handle_read = -1, result = -1, total_written = 0, lock_timeout;
    off_t write_begin, write_end, total_size, file_size;
    ssize_t bytes_read;
    char *range, *value, *rest, *buffer;
    bool range_found;
    struct flock file_lock;

    if (session->uploaded_file == NULL) {
        return 500;
    }

    /* Access check */
    switch (allow_alter(session)) {
    case deny:
    case unspecified:
        log_error(session, fb_alterlist);
        return 403;
    case allow:
        break;
    case pwd:
        if (http_authentication_oke(session, false) == false) {
            return 401;
        }
        if (group_oke(session, session->remote_user, &(session->host->alter_group)) == false) {
            return 403;
        }
        break;
    }

    if (session->uri_is_dir) {
        return 405;
    }

    range = get_headerfield("Content-Range:", session->headerfields);
    range_found = (range != NULL);

    /* Open file for writing */
    if ((handle_write = open(session->file_on_disk, O_WRONLY)) == -1) {
        /* New file */
        if (range_found) {
            return 416;
        }
        if ((handle_write = open(session->file_on_disk, O_CREAT|O_WRONLY, session->host->alter_fmode)) == -1) {
            log_error(session, fb_filesystem);
            return 403;
        }
        file_size = NEW_FILE;
        result = 201;
    } else {
        /* Existing file */
        if ((file_size = filesize(session->file_on_disk)) == -1) {
            close(handle_write);
            return 500;
        }
        result = 204;
    }

    /* Lock file for writing */
    file_lock.l_type = F_WRLCK;
    file_lock.l_whence = SEEK_SET;
    file_lock.l_start = 0;
    file_lock.l_len = 0;
    file_lock.l_pid = 0;
    lock_timeout = WAIT_FOR_LOCK;

    while (fcntl(handle_write, F_SETLK, &file_lock) == -1) {
        if (errno == EINTR) {
            continue;
        } else if ((lock_timeout > 0) && ((errno == EACCES) || (errno == EAGAIN))) {
            lock_timeout--;
            sleep(1);
        } else {
            log_error(session, "can't lock file for writing (PUT)");
            close(handle_write);
            if (file_size == NEW_FILE) {
                unlink(session->file_on_disk);
            }
            return 500;
        }
    }

    file_lock.l_type = F_UNLCK;

    /* Handle upload range */
    if (range_found) {
        if (strncmp(range, "bytes ", 6) != 0) {
            result = 416;
        } else {
            range = strdup(range + 6);

            if (split_string(range, &value, &rest, '-') == -1) {
                result = 416;
            } else if (strlen(value) > 9) {
                result = 416;
            } else if ((write_begin = str2int(value)) == -1) {
                result = 416;
            } else if (split_string(rest, &value, &rest, '/') == -1) {
                result = 416;
            } else if ((write_end = str2int(value)) == -1) {
                result = 416;
            } else if ((total_size = str2int(rest)) == -1) {
                result = 416;
            } else if (total_size != file_size) {
                result = 416;
            } else if (write_begin > write_end) {
                result = 416;
            } else if (write_begin > file_size) {
                result = 416;
            } else if (session->uploaded_size != (write_end - write_begin + 1)) {
                result = 416;
            } else if (write_begin > 0) {
                if (lseek(handle_write, write_begin, SEEK_SET) == -1) {
                    result = 500;
                }
            }

            free(range);
        }
    }

    /* Open temporary file for reading */
    if ((result == 201) || (result == 204)) {
        if ((handle_read = open(session->uploaded_file, O_RDONLY)) == -1) {
            fcntl(handle_write, F_SETLK, &file_lock);
            close(handle_write);
            if (file_size == NEW_FILE) {
                unlink(session->file_on_disk);
            }
            return 500;
        }

        if ((file_size != NEW_FILE) && (range_found == false)) {
            if (ftruncate(handle_write, session->uploaded_size) == -1) {
                result = 500;
            }
        }

        /* Write content */
        if (result != 500) {
            if ((buffer = (char*)malloc(FILE_BUFFER_SIZE)) != NULL) {
                while (total_written < session->uploaded_size) {
                    if ((bytes_read = read(handle_read, buffer, FILE_BUFFER_SIZE)) != -1) {
                        if (bytes_read == 0) {
                            break;
                        } else if (write_buffer(handle_write, buffer, bytes_read) != -1) {
                            total_written += bytes_read;
                        } else {
                            result = 500;
                            break;
                        }
                    } else if (errno != EINTR) {
                        result = 500;
                        break;
                    }
                }
                free(buffer);
            } else {
                result = 500;
            }
        }
    }

    /* Finish upload */
    if (handle_read != -1) {
        close(handle_read);
    }
    fcntl(handle_write, F_SETLK, &file_lock);
    fsync(handle_write);
    close(handle_write);
    if ((result != 201) && (result != 204) && (file_size == NEW_FILE)) {
        unlink(session->file_on_disk);
    }

    return result;
}

int handle_delete_request(t_session *session) {
    /* Access check */
    switch (allow_alter(session)) {
    case deny:
    case unspecified:
        log_error(session, fb_alterlist);
        return 403;
    case allow:
        break;
    case pwd:
        if (http_authentication_oke(session, false) == false) {
            return 401;
        }
        if (group_oke(session, session->remote_user, &(session->host->alter_group)) == false) {
            return 403;
        }
        break;
    }

    /* Don't delete directories */
    if (session->uri_is_dir) {
        return 405;
    }

    /* Delete file */
    if (unlink(session->file_on_disk) == -1) {
        switch (errno) {
        case EACCES:
            log_error(session, fb_filesystem);
            return 403;
        case ENOENT:
            return 404;
        case EISDIR:
        case ENOTDIR:
            return 405;
        default:
            return 500;
        }
    }

    return 204;
}
