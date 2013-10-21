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
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <grp.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "alternative.h"
#include "mimetype.h"
#include "serverconfig.h"
#include "libfs.h"
#include "liblist.h"
#include "libstr.h"
#include "cgi.h"
#include "userconfig.h"
#include "session.h"
#include "httpauth.h"
#include "send.h"
#include "client.h"
#include "target.h"
#include "log.h"
#include "envir.h"
#include "global.h"

#ifdef HAVE_SSL
#include "libssl.h"
#endif
#ifdef HAVE_CACHE
#include "cache.h"
#endif
#ifdef HAVE_TOOLKIT
#include "toolkit.h"
#endif

#define REQUEST_BUFFER_CHUNK     4 * KILOBYTE

#define fe_MAX_REQUESTSIZE      -2
#define fe_TIMEOUT              -3
#define fe_CLIENT_DISCONNECTED  -4
#define fe_READ_ERROR           -5
#define fe_FORCE_QUIT           -6

#define rs_NONE                  0
#define rs_QUIT_SERVER           1
#define rs_UNBAN_CLIENTS         2
#define rs_UNLOCK_LOGFILES       3
#define rs_CLEAR_CACHE           4

#define RANDOM_BUFFER_SIZE     512

#define NO_REQUEST_LIMIT_TIME  300
#define NO_REQUEST_LIMIT_SIZE   16 * MEGABYTE

typedef struct {
    char *config_dir;
    bool daemon;
    bool config_check;
} t_settings;

volatile int received_signal = rs_NONE;
bool must_quit = false;

char *hs_conlen			= "Content-Length: ";
char *fb_filesystem		= "access denied via filesystem";
char *fb_symlink		= "symlink not allowed";
char *fb_accesslist		= "access denied via accesslist";
char *fb_alterlist		= "access denied via alterlist";

/**
	Create all logfiles with the right ownership and accessrights
*/
void touch_logfiles(t_config *config, char *dir) {
    t_host *host;

    touch_logfile(dir, config->system_logfile, 0640, config->server_uid, config->server_gid);

    if(config->garbage_logfile != NULL) {
        touch_logfile(dir, config->garbage_logfile, 0640, config->server_uid, config->server_gid);
    }

    if(config->exploit_logfile != NULL) {
        touch_logfile(dir, config->exploit_logfile, 0640, config->server_uid, config->server_gid);
    }

#ifdef DEBUG
    touch_logfile(dir, LOG_DIR "/debug.log", 0640, config->server_uid, config->server_gid);
#endif

    host = config->first_host;
    while(host != NULL) {
        if(host->access_fileptr != NULL) {
            fflush(host->access_fileptr);
        }

        touch_logfile(dir, host->access_logfile, 0640, config->server_uid, config->server_gid);
        touch_logfile(dir, host->error_logfile, 0640, config->server_uid, config->server_gid);
        host = host->next;
    }
}

/**
    Check if the requested file is a CGI program.
*/
t_cgi_type check_target_is_cgi(t_session *session) {
    t_cgi_handler *cgi;

    session->cgi_handler = NULL;
#ifdef HAVE_TOOLKIT
    if((session->fcgi_server = find_fcgi_server(session->config->fcgi_server, session->toolkit_fastcgi)) != NULL) {
        session->cgi_type = fastcgi;
        session->host->execute_cgi = true;
    } else
#endif
        if((session->fcgi_server = fcgi_server_match(session->config->fcgi_server, &(session->host->fast_cgi), session->extension)) != NULL) {
            session->cgi_type = fastcgi;
        } else if(in_charlist(session->extension, &(session->config->cgi_extension))) {
            session->cgi_type = binary;
        } else {
            session->cgi_type = no_cgi;
            cgi = session->config->cgi_handler;
            while(cgi != NULL) {
                if (in_charlist(session->extension, &(cgi->extension))) {
                    session->cgi_handler = cgi->handler;
                    session->cgi_type = script;
                    break;
                }
                cgi = cgi->next;
            }
        }

    return session->cgi_type;
}

/**
    Handle a HTTP error.
*/
int handle_error(t_session *session, int error_code) {
    t_error_handler *error_handler = session->host->error_handlers;

    while(error_handler != NULL) {
        if(error_handler->code == error_code) {
            break;
        }
        error_handler = error_handler->next;
    }

    if(error_handler == NULL) {
        return 0;
    }

    session->return_code = error_code;
    session->error_code = error_code;
    session->handling_error = true;
    session->mimetype = NULL;
    session->vars = error_handler->parameters;

    char *new_fod;
    int result = -1;

    if((new_fod = (char*)malloc(session->host->website_root_len + strlen(error_handler->handler) + 4)) == NULL) { /* + 3 for .gz (gzip encoding) */
        result = 500;
    } else {
        if(session->file_on_disk != NULL) {
            free(session->file_on_disk);
        }

        session->file_on_disk = new_fod;

        memcpy(session->file_on_disk, session->host->website_root, session->host->website_root_len);
        strcpy(session->file_on_disk + session->host->website_root_len, error_handler->handler);

        if(get_target_extension(session) == -1) {
            return 500;
        }

        check_target_is_cgi(session);

        if(session->cgi_type != no_cgi) {
            result = execute_cgi(session);
        } else switch (is_directory(session->file_on_disk)) {
            case error:
                result = 500;
                break;
            case yes:
                result = 301;
                break;
            case no:
                result = send_file(session);
                break;
            case no_access:
                result = 403;
                break;
            case not_found:
                result = 404;
                break;
            }
    }

    switch(result) {
    case 301:
        log_error(session, "ErrorHandler is a directory");
        break;
    case 403:
        log_error(session, "no access to ErrorHandler");
        break;
    case 404:
        log_error(session, "ErrorHandler not found");
        break;
    case 500:
        log_file_error(session, error_handler->handler, "internal error for ErrorHandler");
        session->keep_alive = false;
        break;
    case 503:
        log_file_error(session, error_handler->handler, "FastCGI for ErrorHandler not available");
        break;
    }

    return result;
}

/**
    Run a program
*/
int run_program(t_session *session, char *program, int return_code) {
    pid_t pid;
    char ip[MAX_IP_STR_LEN], value[10], *pos, slash = '/';
    int result;

    switch(pid = fork()) {
    case -1:
        log_file_error(session, program, "fork() error");
        return -1;
    case 0:
        if (setsid() == -1) {
            log_file_error(session, program, "setsid() error");
        } else {
            /* Close all other open filedescriptors. */
            close_bindings(session->config->binding);
            close_client_sockets_for_cgi_run();
            close_logfiles_for_cgi_run(session->config->first_host);

            /* Set environment variables */
            setenv("REQUEST_METHOD", session->method, 1);
            setenv("DOCUMENT_ROOT", session->host->website_root, 1);
            setenv("REQUEST_URI", session->request_uri, 1);

            if(session->remote_user != NULL) {
                setenv("REMOTE_USER", session->remote_user, 1);
            }

            if(inet_ntop(session->ip_address.family, &(session->ip_address.value), ip, MAX_IP_STR_LEN) != NULL) {
                setenv("REMOTE_ADDR", ip, 1);
            }

            snprintf(value, 9, "%d", return_code);
            setenv("HTTP_RETURN_CODE", value, 1);

            headerfield_to_environment(session, NULL, "Range:", "HTTP_RANGE");
            headerfield_to_environment(session, NULL, "Referer:", "HTTP_REFERER");
            headerfield_to_environment(session, NULL, "User-Agent:", "HTTP_USER_AGENT");

            /* Change directory to program's directory */
            pos = strrchr(program, slash);
#ifdef CYGWIN
            if((pos == NULL) && (session->config->platform == windows)) {
                slash = '\\';
                pos = strrchr(program, slash);
            }
#endif
            if(pos != NULL) {
                *pos = '\0';
                result = chdir(program);
                *pos = slash;
            }

            /* Execute program */
            execlp(program, program, (char*)NULL);
            log_file_error(session, program, "exec() error");
        }

        exit(EXIT_FAILURE);

    default:
        if(session->config->wait_for_cgi) {
            waitpid(pid, NULL, 0);
        }
    }

    return 0;
}

/**
    Read the request from a client socket.
*/
int fetch_request(t_session *session) {
    char *new_reqbuf, *strstart, *strend;
    long max_request_size, bytes_read, header_length = -1, content_length = -1;
    int result = 200, write_bytes;
    time_t deadline;
    fd_set read_fds;
    struct timeval select_timeout;

    if(session->request_limit == false) {
        deadline = session->time + NO_REQUEST_LIMIT_TIME;
        max_request_size = NO_REQUEST_LIMIT_SIZE;
    } else if(session->kept_alive == 0) {
        deadline = session->time + session->binding->time_for_1st_request;
        max_request_size = session->binding->max_request_size;
    } else {
        deadline = session->time + session->binding->time_for_request;
        max_request_size = session->binding->max_request_size;
    }

    bool keep_reading = true, store_on_disk = false;
    int upload_handle = -1;

    do {
        /* Check if requestbuffer contains a complete request. */
        if(session->request != NULL) {
            if(header_length == -1) {
                if((strstart = strstr(session->request, "\r\n\r\n")) != NULL) {
                    *(strstart + 2) = '\0';
                    header_length = strstart + 4 - session->request;
                    session->header_length = header_length;

                    determine_request_method(session);
                    store_on_disk = (session->request_method == PUT) && session->binding->enable_alter;

                    if(store_on_disk) {
                        if((session->uploaded_file = (char*)malloc(session->config->upload_directory_len + 15)) != NULL) {
                            strcpy(session->uploaded_file, session->config->upload_directory);
                            strcpy(session->uploaded_file + session->config->upload_directory_len, "/upload_XXXXXX");
                            if((upload_handle = mkstemp(session->uploaded_file)) == -1) {
                                free(session->uploaded_file);
                                session->uploaded_file = NULL;
                            }
                        }

                        if(session->uploaded_file == NULL) {
                            log_error(session, "can't create tempfile for PUT request");
                            result = 500;
                            break;
                        }

                        session->uploaded_size = session->bytes_in_buffer - header_length;

                        if(write_buffer(upload_handle, session->request + header_length, session->uploaded_size) == -1) {
                            result = 500;
                            break;
                        }

                        session->bytes_in_buffer = header_length;
                    }

                }
            }

            if(header_length != -1) {
                if(content_length == -1) {
                    if((strstart = strcasestr(session->request, hs_conlen)) != NULL) {
                        strstart += 16;

                        if((strend = strstr(strstart, "\r\n")) != NULL) {
                            *strend = '\0';
                            content_length = str2int(strstart);
                            *strend = '\r';

                            if(content_length < 0) {
                                result = 400;
                                break;
                            }

                            if(store_on_disk) {
                                session->content_length = 0;
                                if(content_length > session->binding->max_upload_size) {
                                    result = 413;
                                    break;
                                }

                                session->buffer_size = header_length + REQUEST_BUFFER_CHUNK;

                                if((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
                                    session->request = new_reqbuf;
                                } else {
                                    result = fe_READ_ERROR;
                                    break;
                                }
                            } else {
                                session->content_length = content_length;
                                if(header_length + content_length > max_request_size) {
                                    result = fe_MAX_REQUESTSIZE;
                                    break;
                                }

                                if(header_length + content_length > session->buffer_size) {
                                    session->buffer_size = header_length + content_length;
                                    if((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
                                        session->request = new_reqbuf;
                                    } else {
                                        result = fe_READ_ERROR;
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        session->content_length = 0;
                        if(store_on_disk) {
                            result = 411;
                        }
                        break;
                    }
                }

                if(content_length > -1) {
                    if(store_on_disk) {
                        if(session->uploaded_size == content_length) {
                            break;
                        }
                    } else {
                        if(session->bytes_in_buffer >= header_length + content_length) {
                            /* Received a complete request */
                            break;
                        }
                    }
                }
            }
        }

        FD_ZERO(&read_fds);
        FD_SET(session->client_socket, &read_fds);

        select_timeout.tv_sec = 1;
        select_timeout.tv_usec = 0;

        switch(select(session->client_socket + 1, &read_fds, NULL, NULL, &select_timeout)) {
        case -1:
            if(errno != EINTR) {
                result = fe_READ_ERROR;
                keep_reading = false;
            }
            break;
        case 0:
            if(session->force_quit) {
                result = fe_FORCE_QUIT;
                keep_reading = false;
            } else if(time(NULL) > deadline) {
                result = fe_TIMEOUT;
                keep_reading = false;
            }
            break;
        default:
            if((content_length == -1) && ((session->buffer_size - session->bytes_in_buffer) < 256)) {
                session->buffer_size += REQUEST_BUFFER_CHUNK;
                if((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
                    session->request = new_reqbuf;
                } else {
                    result = fe_READ_ERROR;
                    keep_reading = false;
                    break;
                }
            }

            /* Read from socket. */
#ifdef HAVE_SSL
            if(session->binding->use_ssl) {
                bytes_read = ssl_receive(session->ssl_data, session->request + session->bytes_in_buffer,
                                         session->buffer_size - session->bytes_in_buffer);
            } else
#endif
                bytes_read = recv(session->client_socket, session->request + session->bytes_in_buffer,
                                  session->buffer_size - session->bytes_in_buffer, 0);

            switch (bytes_read) {
            case -1:
                if(errno != EINTR) {
                    result = fe_READ_ERROR;
                    keep_reading = false;
                }
                break;
            case 0:
                result = fe_CLIENT_DISCONNECTED;
                keep_reading = false;
                break;
            default:
                if(store_on_disk) {
                    /* Write to file on disk */
                    write_bytes = bytes_read;
                    if(session->uploaded_size + bytes_read > content_length) {
                        write_bytes -= ((session->uploaded_size + bytes_read) - content_length);
                    }
                    if(write_buffer(upload_handle, session->request + header_length, write_bytes) == -1) {
                        result = 500;
                        keep_reading = false;
                        break;
                    }
                    if((session->uploaded_size += write_bytes) > session->binding->max_upload_size) {
                        result = 413;
                        keep_reading = false;
                        break;
                    }
                    if(write_bytes < bytes_read) {
                        memmove(session->request + header_length, session->request + header_length + write_bytes, bytes_read - write_bytes);
                        session->bytes_in_buffer += bytes_read - write_bytes;
                        keep_reading = false;
                    }
                } else {
                    /* Read into memory */
                    session->bytes_in_buffer += bytes_read;
                    *(session->request + session->bytes_in_buffer) = '\0';

                    if(session->bytes_in_buffer > max_request_size) {
                        keep_reading = false;
                        result = fe_MAX_REQUESTSIZE;
                        break;
                    }
                }
            }
        }
    } while(keep_reading);

    if(upload_handle != -1) {
        fsync(upload_handle);
        close(upload_handle);
    }

    return result;
}

/**
    Convert the requestbuffer to a session record.
*/
int parse_request(t_session *session, int total_bytes) {
    /* retval will never be negative so make it unsigned */
    unsigned int retval = 200;
    char *request_end = session->request + total_bytes, *str_end;

    /*request_end = session->request + total_bytes;*/

    /* Request method */
    session->method = str_end = session->request;
    while ((*str_end != ' ') && (str_end != request_end)) {
        str_end++;
    }
    if (str_end == request_end) {
        return 400;
    }
    *str_end = '\0';
    session->uri = ++str_end;

    /* URI */
    while ((*str_end != ' ') && (str_end != request_end)) {
        str_end++;
    }
    if (str_end == request_end) {
        return 400;
    }
    *(str_end++) = '\0';
    session->uri_len = strlen(session->uri);
    if (strncmp(session->uri, "http://", 7) == 0) {
        return 400;
    } else if ((session->request_uri = strdup(session->uri)) == NULL) {
        return -1;
    }

    /* Protocol version */
    if ((min_strlen(str_end, 10) == false) || (memcmp(str_end, "HTTP/", 5) != 0)) {
        return 400;
    }

    session->http_version = str_end;
    str_end += 7;

    if ((*(str_end - 1) != '.') || (*(str_end + 1) != '\r') || (*(str_end + 2) != '\n')) {
        return 400;
    } else if (*(str_end - 2) != '1') {
        return 505;
    }
    *(str_end + 1) = '\0';

    /* Body and other request headerlines */
    if (session->content_length > 0) {
        session->body = session->request + session->header_length;
    }
    session->headerfields = parse_headerfields(str_end + 3);
    session->hostname = strlower(get_headerfield("Host:", session->headerfields));
    session->cookie = get_headerfield("Cookie:", session->headerfields);

    char *conn;
    if ((conn = get_headerfield("Connection:", session->headerfields)) != NULL) {
        conn = strlower(remove_spaces(conn));
    }
    session->keep_alive = false;

    switch (*str_end) {
    case '0':
        if ((conn != NULL) && (session->kept_alive < session->binding->max_keepalive)) {
            if (strcasecmp(conn, "keep-alive") == 0) {
                session->keep_alive = true;
            }
        }
        break;
    case '1':
        if (session->hostname == NULL) {
            retval = 400;
        } else if (session->kept_alive < session->binding->max_keepalive) {
            session->keep_alive = true;
            if (conn != NULL) {
                if (strcmp(conn, "close") == 0) {
                    session->keep_alive = false;
                }
            }
        }
        break;
    default:
        retval = 505;
        break;
    }
    if (session->keep_alive) {
        session->kept_alive++;
    }

    return retval;
}

/**
    Convert the request uri to a filename.
*/
int uri_to_path(t_session *session) {
    size_t length;
    char *strstart, *strend;
    int retval;

    /* Requested file in userdirectory? */
    if (session->host->user_websites && (session->uri_len >= 3)) {
        if (*(session->uri + 1) == '~') {
            strstart = session->uri + 1;
            if ((strend = strchr(strstart, '/')) == NULL) {
                return 301;
            } else if ((length = strend - strstart) > 1) {
                if ((session->local_user = (char*)malloc(length + 1)) == NULL) {
                    return 500;
                }

                memcpy(session->local_user, strstart, length);
                *(session->local_user + length) = '\0';

                if ((retval = get_homedir(session, session->local_user + 1)) != 200) {
                    return retval;
                }
                session->host->error_handlers = NULL;
            } else {
                /* uri is '/~/...' */
                return 404;
            }
        }
    }

    /* Search for an alias. */
    size_t alias_length = 0;
    t_keyvalue *alias = session->host->alias;
    /*alias = session->host->alias;*/
    while (alias != NULL) {
        alias_length = strlen(alias->key);
        if (strncmp(session->uri, alias->key, alias_length) == 0) {
            if ((*(session->uri + alias_length) == '/') || (*(session->uri + alias_length) == '\0')) {
                session->alias_used = true;
                break;
            }
        }
        alias = alias->next;
    }

    /* Allocate memory */
    if (alias == NULL) {
        length = session->host->website_root_len;
    } else {
        length = strlen(alias->value);
    }
    length += session->uri_len + MAX_START_FILE_LENGTH;
    if ((session->file_on_disk = (char*)malloc(length + 4)) == NULL) { /* + 3 for '.gz' (gzip encoding) */
        return 500;
    }

    /* Copy stuff */
    if (alias == NULL) {
        length = session->host->website_root_len;
        memcpy(session->file_on_disk, session->host->website_root, length);
        strstart = session->uri;
        if (session->local_user != NULL) {
            strstart += strlen(session->local_user) + 1;
        }
    } else {
        length = strlen(alias->value);
        memcpy(session->file_on_disk, alias->value, length);
        strstart = session->uri + alias_length;

    }
    strcpy(session->file_on_disk + length, strstart);

    return 200;
}

t_access allow_client(t_session *session) {
    char *x_forwarded_for;
    t_ip_addr forwarded_ip;
    t_access access;

    if ((access = ip_allowed(&(session->ip_address), session->host->access_list)) != allow) {
        return access;
    } else if ((x_forwarded_for = get_headerfield("X-Forwarded-For:", session->headerfields)) == NULL) {
        return allow;
    } else if (parse_ip(x_forwarded_for, &forwarded_ip) == -1) {
        return allow;
    } else if (ip_allowed(&forwarded_ip, session->host->access_list) == deny) {
        return deny;
    }

    return unspecified;
}

int get_path_info(t_session *session) {
    if (session->alias_used) {
        return 200;
    }

    if (session->host->website_root_len >= strlen(session->file_on_disk)) {
        return 500;
    }

    t_fsbool is_dir;
    char *slash = session->file_on_disk + session->host->website_root_len + 1;

    /*slash = session->file_on_disk + session->host->website_root_len + 1;*/
    while (*slash != '\0') {
        if (*slash == '/') {
            *slash = '\0';
            is_dir = is_directory(session->file_on_disk);
            *slash = '/';

            switch (is_dir) {
            case error:
                return 500;
            case not_found:
                return 404;
            case no_access:
                return 403;
            case no:
                if ((session->path_info = strdup(slash)) == NULL) {
                    return -1;
                }
                *slash = '\0';
                return 200;
            case yes:
                break;
            }
        }
        slash++;
    }

    return 200;
}

/**
    Serve the client that connected to the webserver
*/
int serve_client(t_session *session) {
    int result, length;

    if ((result = fetch_request(session)) != 200) {
        session->request_method = GET;
        return result;
    } else if ((result = parse_request(session, session->header_length + session->content_length)) != 200) {
        session->request_method = GET;
        return result;
    }

    char *search, *conffile, *qmark, chr, *client_ip;
    t_host *host_record;
    t_access access;
    t_deny_body *deny_body;
#ifdef HAVE_TOOLKIT
    t_toolkit_options options;
#endif
    t_ip_addr ip;

    session->time = time(NULL);

    /* Hide reverse proxies */
    if (in_iplist(session->config->hide_proxy, &(session->ip_address))) {
        if ((client_ip = get_headerfield("X-Forwarded-For:", session->headerfields)) != NULL) {
            if ((search = strrchr(client_ip, ',')) != NULL) {
                client_ip = search + 1;
            }

            while ((*client_ip == ' ') && (*client_ip != '\0')) {
                client_ip++;
            }

            if (*client_ip != '\0') {
                if (parse_ip(client_ip, &ip) != -1) {
                    if (reposition_client(session, &ip) != -1) {
                        copy_ip(&(session->ip_address), &ip);
                    }
                }
            }
        }
    }

    if (session->request_method == TRACE) {
        if (session->binding->enable_trace == false) {
            return 501;
        }
        return handle_trace_request(session);
    } else if ((session->request_method == PUT) || (session->request_method == DELETE)) {
        if (session->binding->enable_alter == false) {
            return 501;
        }
    } else if (session->request_method == unsupported) {
        return 501;
    } else if (session->request_method == unknown) {
        return 400;
    }

    if (session->hostname != NULL) {
        remove_port_from_hostname(session->hostname, session->binding);

        if ((host_record = get_hostrecord(session->config->first_host, session->hostname, session->binding)) != NULL) {
            session->host = host_record;
        }
    }
    session->host->access_time = session->time;

#ifdef HAVE_SSL
    if (session->host->require_ssl && (session->binding->use_ssl == false)) {
        if ((qmark = strchr(session->uri, '?')) != NULL) {
            *qmark = '\0';
            session->vars = qmark + 1;
            session->uri_len = strlen(session->uri);
        }
        session->cause_of_301 = require_ssl;
        return 301;
    }
#endif

    if (session->host->secure_url) {
        if (strstr(session->request_uri, "%00") != NULL) {
            return 403;
        }
    }

    /* Deny matching bodies */
    if (session->body != NULL) {
        chr = *(session->body + session->content_length);
        *(session->body + session->content_length) = '\0';

        deny_body = session->host->deny_body;
        while (deny_body != NULL) {
            if (strpcmp(session->body, &(deny_body->pattern)) == 0) {
                if ((session->config->ban_on_denied_body > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
                    ban_ip(&(session->ip_address), session->config->ban_on_denied_body, session->config->kick_on_ban);
                    log_system(session, "Client banned because of denied body");
                }

                log_string(session->host->error_logfile, "Request denied because of unallowed body content");
                log_exploit_attempt(session, "denied body", session->body);
                *(session->body + session->content_length) = chr;

                return 403;
            }
            deny_body = deny_body->next;
        }

        *(session->body + session->content_length) = chr;
    }

#ifdef HAVE_TOOLKIT
    /* URL toolkit */
#ifdef HAVE_SSL
    init_toolkit_options(&options, session->host->website_root, session->config->url_toolkit, session->binding->use_ssl);
#else
    init_toolkit_options(&options, session->host->website_root, session->config->url_toolkit, false);
#endif

    if ((session->request_method != PUT) && (session->request_method != DELETE)) {
        unsigned int i;
        for (i = 0; i < session->host->toolkit_rules.size; i++) {
            if ((result = use_toolkit(session->uri, session->host->toolkit_rules.item[i], &options)) == UT_ERROR) {
                return 500;
            }

            if ((options.ban > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
                ban_ip(&(session->ip_address), options.ban, session->config->kick_on_ban);
                log_system(session, "Client banned because of URL match in UrlToolkit rule");
                return 403;
            }

            session->toolkit_fastcgi = options.fastcgi_server;
            if (options.new_url != NULL) {
                if (register_tempdata(&(session->tempdata), options.new_url, tc_data) == -1) {
                    free(options.new_url);
                    return 500;
                }
                session->uri = options.new_url;
            }

            if (result == UT_REDIRECT) {
                session->location = strdup(options.new_url);
                session->cause_of_301 = location;
                return 301;
            }

            if (result == UT_DENY_ACCESS) {
                log_error(session, "access denied via URL toolkit rule");
                return 403;
            }

            if (options.expire > -1) {
                session->expires = options.expire;
            }
        }
    }
#endif

    /* Find GET data */
    if((qmark = strchr(session->uri, '?')) != NULL) {
        *qmark = '\0';
        session->vars = qmark + 1;
    }

    url_decode(session->uri);
    session->uri_len = strlen(session->uri);

    if ((session->vars != NULL) && (session->host->secure_url)) {
        if (forbidden_chars_present(session->vars)) {
            return 403;
        }
    }

    if (duplicate_host(session) == false) {
        return 500;
    }

    if (valid_uri(session->uri) == false) {
        if (session->request_method == PUT) {
            return 403;
        }
        return 404;
    } else if ((result = uri_to_path(session)) != 200) {
        return result;
    }

    /* Load configfile from directories */
    search = session->file_on_disk;
    while (*search != '\0') {
        if (*search == '/') {
            length = search - session->file_on_disk + 1;
            if ((conffile = (char*)malloc(length + 10)) == NULL) {
                result = 500;
            } else {
                memcpy(conffile, session->file_on_disk, length);
                memcpy(conffile + length, ".htaccess\0", 9);
                if (read_user_configfile(conffile, session->host, &(session->tempdata)) > 0) {
                    log_file_error(session, conffile, "error in configuration file");
                    result = 500;
                }
                free(conffile);
            }
        }
        if (result == 200) {
            search++;
        } else {
            return result;
        }
    }

    if (client_is_rejected_bot(session)) {
        log_error(session, "bot rejected");
        return 403;
    }

    if ((result = copy_directory_settings(session)) != 200) {
        return result;
    }

    switch (access = allow_client(session)) {
    case deny:
        log_error(session, fb_accesslist);
        return 403;
    case allow:
        break;
    case pwd:
    case unspecified:
        if (http_authentication_oke(session, access == unspecified) == false) {
            return 401;
        }
    }

    switch (is_directory(session->file_on_disk)) {
    case error:
        return 500;
    case yes:
        session->uri_is_dir = true;
        break;
    case no:
        if ((session->request_method != PUT) && (session->host->enable_path_info)) {
            if ((result = get_path_info(session)) != 200) {
                return result;
            }
        }
        break;
    case no_access:
        log_error(session, fb_filesystem);
        return 403;
    case not_found:
        if (session->request_method == DELETE) {
            return 404;
        }
    }

    length = strlen(session->file_on_disk);
    if (*(session->file_on_disk + length - 1) == '/') {
        if (session->uri_is_dir) {
            strcpy(session->file_on_disk + length, session->host->start_file);
        }
    } else if (session->uri_is_dir) {
        return 301;
    }

    if (get_target_extension(session) == -1) {
        return 500;
    }

    if ((session->request_method != PUT) && (session->request_method != DELETE)) {
        check_target_is_cgi(session);
    }

    switch (session->request_method) {
    case GET:
    case HEAD:
        if (session->cgi_type != no_cgi) {
            session->body = NULL;
            result = execute_cgi(session);
        } else {
            result = send_file(session);
        }
        if (result == 404) {

        }

        if ((session->request_method == GET) && (session->cgi_type == no_cgi) && (session->directory != NULL)) {
            if (session->directory->run_on_download != NULL) {
                run_program(session, session->directory->run_on_download, result);
            }
        }
        break;
    case POST:
        if (session->cgi_type != no_cgi) {
            result = execute_cgi(session);
        } else {
            result = 405;
        }
        break;
    case OPTIONS:
        result = handle_options_request(session);
        break;
    case PUT:
        result = handle_put_request(session);
        if (((result == 201) || (result == 204)) && (session->host->run_on_alter != NULL)) {
            run_program(session, session->host->run_on_alter, result);
        }
        break;
    case DELETE:
        result = handle_delete_request(session);
        if ((result == 204) && (session->host->run_on_alter != NULL)) {
            run_program(session, session->host->run_on_alter, result);
        }
        break;
    default:
        result = 400;
    }

    return result;
}

/**
    Handle timeout upon sending request
*/
void handle_timeout(t_session *session) {
    if ((session->config->ban_on_timeout > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
        ban_ip(&(session->ip_address), session->config->ban_on_timeout, session->config->kick_on_ban);
        log_system(session, "Client banned because of connection timeout");
    } else {
        log_system(session, "Timeout while waiting for request");
    }
}

/**
    Request has been handled, handle the return code.
*/
void handle_request_result(t_session *session, int result) {
    switch (result) {
    case fe_MAX_REQUESTSIZE:
        log_system(session, "Maximum request size reached");
        session->return_code = 413;
        send_code(session);
        if ((session->config->ban_on_max_request_size > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
            ban_ip(&(session->ip_address), session->config->ban_on_max_request_size, session->config->kick_on_ban);
            log_system(session, "Client banned because of sending a too large request");
        }
        break;
    case fe_TIMEOUT:
        if (session->kept_alive == 0) {
            session->return_code = 408;
            send_code(session);
            handle_timeout(session);
        }
        break;
    case fe_CLIENT_DISCONNECTED:
        if (session->kept_alive == 0) {
            log_system(session, "Client disconnected");
        }
        break;
    case fe_READ_ERROR:
        if (errno != ECONNRESET) {
            log_system(session, "Error while reading request");
        }
        break;
    case fe_FORCE_QUIT:
        log_system(session, "Client kicked");
        break;
    case rr_SQL_INJECTION:
        if ((session->config->ban_on_sqli > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
            ban_ip(&(session->ip_address), session->config->ban_on_sqli, session->config->kick_on_ban);
            log_system(session, "Client banned because of SQL injection");
        }
        session->return_code = 400;
        send_code(session);
        log_request(session, 400);
        break;
    case 200:
        break;
    case 201:
    case 204:
    case 304:
    case 412:
        if (session->data_sent == false) {
            session->return_code = result;
            send_header(session);
            send_buffer(session, "Content-Length: 0\r\n\r\n", 21);
        }
        break;
    case 411:
    case 413:
        session->keep_alive = false;
        if (session->data_sent == false) {
            session->return_code = result;
            send_header(session);
            send_buffer(session, "Content-Length: 0\r\n\r\n", 21);
        }
        break;
    case 400:
        log_garbage(session);
        if (session->data_sent == false) {
            session->return_code = 400;
            if (send_code(session) == -1) {
                session->keep_alive = false;
            }
        }
        if ((session->config->ban_on_garbage > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
            ban_ip(&(session->ip_address), session->config->ban_on_garbage, session->config->kick_on_ban);
            log_system(session, "Client banned because of sending garbage");
        }
        break;
    case 401:
    case 403:
    case 404:
    case 501:
    case 503:
        if (session->data_sent == false) {
            switch (handle_error(session, result)) {
            case -1:
                session->keep_alive = false;
                break;
            case 200:
                break;
            default:
                if (session->data_sent == false) {
                    session->return_code = result;
                    if (send_code(session) == -1) {
                        session->keep_alive = false;
                    }
                }
            }
        }
        break;
    case 500:
        session->keep_alive = false;
    default:
        if (session->data_sent == false) {
            session->return_code = result;
            send_code(session);
        }
    }

    if ((result > 0) && (result != 400)) {
        log_request(session, result);
    } else {
        session->keep_alive = false;
    }
}

/**
    Handle the connection of a client.
*/
void connection_handler(t_session *session) {
    int result;
#ifdef HAVE_SSL
    int timeout;
#endif

#ifdef HAVE_SSL
    if (session->binding->use_ssl) {
        timeout = session->kept_alive == 0 ? session->binding->time_for_1st_request : session->binding->time_for_request;
        switch (ssl_accept(session->client_socket, &(session->ssl_data), session->binding->ssl_context, timeout)) {
        case -2:
            handle_timeout(session);
            break;
        case 0:
            session->socket_open = true;
            break;
        }
    } else
#endif
        session->socket_open = true;

    if (session->socket_open) {
        do {
            result = serve_client(session);
            handle_request_result(session, result);

            if (session->socket_open) {
                send_buffer(session, NULL, 0); /* Flush the output-buffer */
            }

            reset_session(session);

            if (session->keep_alive && (session->config->ban_on_flooding > 0)) {
                if (client_is_flooding(session)) {
                    if (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny) {
                        ban_ip(&(session->ip_address), session->config->ban_on_flooding, session->config->kick_on_ban);
                        log_system(session, "Client banned because of flooding");
                        session->keep_alive = false;
                    }
                }
            }
        } while (session->keep_alive && session->socket_open);

        destroy_session(session);
        close_socket(session);
    } else {
        close(session->client_socket);
        session->socket_open = false;
    }

    if (session->config->reconnect_delay > 0) {
        mark_client_for_removal(session, session->config->reconnect_delay);
    } else {
        remove_client(session, true);
    }

    /* Client session ends here */
    pthread_exit(NULL);
}

/**
    Task-runner starts periodic tasks.
*/
void task_runner(t_config *config) {
    t_ip_addr ip_addr;
    int delay = 0;
    time_t now;

    do {
        sleep(1);

        if (delay == TASK_RUNNER_INTERVAL) {
            now = time(NULL);

            /* Client checks */
            check_ban_list(config, now);
            check_remove_deadlines(config, now);
            remove_wrong_password_list(config);

            /* FastCGI check */
            check_load_balancer(config, now);

            /* Close idle logfile handles */
            close_logfiles(config->first_host, now);

#ifdef HAVE_CACHE
            /* Cache check */
            check_cache(now);
#endif

            delay = 0;
        } else {
            delay++;
        }

        switch (received_signal) {
        case rs_NONE:
            break;
        case rs_QUIT_SERVER:
            must_quit = true;
            break;
        case rs_UNBAN_CLIENTS:
            default_ipv4(&ip_addr);
            unban_ip(&ip_addr);
#ifdef HAVE_IPV6
            default_ipv6(&ip_addr);
            unban_ip(&ip_addr);
#endif
            received_signal = rs_NONE;
            break;
        case rs_UNLOCK_LOGFILES:
            close_logfiles(config->first_host, 0);
            received_signal = rs_NONE;
            break;
#ifdef HAVE_CACHE
        case rs_CLEAR_CACHE:
            clear_cache();
            received_signal = rs_NONE;
            break;
#endif
        }
    } while (must_quit == false);

    pthread_exit(NULL);
}

/**
    Signal handlers
*/
void SEGV_handler(int sig) {
    syslog(LOG_DAEMON | LOG_ALERT, "segmentation fault!");
    exit(EXIT_FAILURE);
}

void TERM_handler(int sig) {
    received_signal = rs_QUIT_SERVER;
}

void HUP_handler(int sig) {
    received_signal = rs_UNLOCK_LOGFILES;
}

void USR1_handler(int sig) {
    received_signal = rs_UNBAN_CLIENTS;
}

#ifdef HAVE_CACHE
void USR2_handler(int sig) {
    received_signal = rs_CLEAR_CACHE;
}
#endif

/**
    Fill a filedescriptor set with sockets.
*/
int fill_read_fds(fd_set *read_fds, t_binding *binding) {
    /* Probably safe to make it "unsigned" */
    unsigned int highest_fd = 0;

    FD_ZERO(read_fds);
    while (binding != NULL) {
        FD_SET(binding->socket, read_fds);
        if (binding->socket > highest_fd) {
            highest_fd = binding->socket;
        }
        binding = binding->next;
    }

    return highest_fd;
}

/**
    Create a socketlist.
*/
int bind_sockets(t_binding *binding) {
    char ip_address[MAX_IP_STR_LEN], separator;
    struct sockaddr_in  saddr4;
#ifdef HAVE_IPV6
    struct sockaddr_in6 saddr6;
#endif
    int domain, one, result;

    while (binding != NULL) {
#ifdef HAVE_IPV6
        domain = (binding->interface.family == AF_INET ? PF_INET : PF_INET6);
#else
        domain = PF_INET;
#endif
        if ((binding->socket = socket(domain, SOCK_STREAM, 0)) == -1) {
            perror("socket()");
            return -1;
        }

        one = 1;
        if (setsockopt(binding->socket, SOL_SOCKET, SO_REUSEADDR, (void*)&one, sizeof(int)) == -1) {
            perror("setsockopt(SOL_SOCKET, SO_REUSEADDR)");
        }
        one = 1;
        if (setsockopt(binding->socket, IPPROTO_TCP, TCP_NODELAY, (void*)&one, sizeof(int)) == -1) {
            perror("setsockopt(IPPROTO_TCP, TCP_NODELAY)");
        }

        if (binding->interface.family == AF_INET) {
            /* IPv4 */
            memset(&saddr4, 0, sizeof(struct sockaddr_in));
            //saddr4.sin_len = sizeof(struct sockaddr_in);
            saddr4.sin_family = AF_INET;
            memcpy(&(saddr4.sin_addr.s_addr), &(binding->interface.value), IPv4_LEN);
            saddr4.sin_port = htons(binding->port);

            result = bind(binding->socket, (struct sockaddr*)&saddr4, sizeof(struct sockaddr_in));

            separator = ':';
#ifdef HAVE_IPV6
        } else if (binding->interface.family == AF_INET6) {
            /* IPv6 */
            memset(&saddr6, 0, sizeof(struct sockaddr_in6));
            //saddr6.sin6_len = sizeof(struct sockaddr_in6);
            saddr6.sin6_family = AF_INET6;
            memcpy(&(saddr6.sin6_addr.s6_addr), &(binding->interface.value), IPv6_LEN);
            saddr6.sin6_port = htons(binding->port);

            result = bind(binding->socket, (struct sockaddr*)&saddr6, sizeof(struct sockaddr_in6));

            separator = '.';
#endif
        } else {
            fprintf(stderr, "Unknown protocol (family %d).\n", binding->interface.family);
            return -1;
        }

        if (result == -1) {
            /* Handle error */
            if (inet_ntop(binding->interface.family, &(binding->interface.value), ip_address, MAX_IP_STR_LEN) == NULL) {
                strcpy(ip_address, "?.?.?.?");
            }
            fprintf(stderr, "Error binding %s%c%d\n", ip_address, separator, binding->port);
            return -1;
        }

        binding = binding->next;
    }

    return 0;
}

/**
    Accept or deny an incoming connection.
*/
int accept_connection(t_binding *binding, t_config *config) {
    socklen_t           size;
    bool                kick_client;
    t_session           *session;
    struct sockaddr_in  caddr4;
#ifdef HAVE_IPV6
    struct sockaddr_in6 caddr6;
#endif
    pthread_attr_t      child_attr;
    pthread_t           child_thread;
    int                 total_conns, one, conns_per_ip;
    struct timeval      timer;
#ifdef DEBUG
    static int          thread_id = 0;
#endif

    if ((session = (t_session*)malloc(sizeof(t_session))) == NULL) {
        return -1;
    }
#ifdef DEBUG
    session->thread_id = thread_id++;
#endif
    session->config = config;
    session->binding = binding;
    init_session(session);

    if (binding->interface.family == AF_INET) {
        /* IPv4 */
        size = sizeof(struct sockaddr_in);
        memset((void*)&caddr4, 0, (size_t)size);
        if ((session->client_socket = accept(binding->socket, (struct sockaddr*)&caddr4, &size)) == -1) {
            free(session);
            log_string(config->system_logfile, "Error accepting incoming IPv4 connection: %s", strerror(errno));
            if (errno == EINTR) {
                return 0;
            }
            return -1;
        }

        session->ip_address.family = AF_INET;
        session->ip_address.size   = IPv4_LEN;
        memcpy(&(session->ip_address.value), (char*)&caddr4.sin_addr.s_addr, session->ip_address.size);
#ifdef HAVE_IPV6
    } else if (binding->interface.family == AF_INET6) {
        /* IPv6 */
        size = sizeof(struct sockaddr_in6);
        memset((void*)&caddr6, 0, (size_t)size);
        if ((session->client_socket = accept(binding->socket, (struct sockaddr*)&caddr6, &size)) == -1) {
            free(session);
            log_string(config->system_logfile, "Error accepting incoming IPv6 connection: %s", strerror(errno));
            if (errno == EINTR) {
                return 0;
            }
            return -1;
        }

        session->ip_address.family = AF_INET6;
        session->ip_address.size   = IPv6_LEN;
        memcpy(&(session->ip_address.value), (char*)&caddr6.sin6_addr.s6_addr, session->ip_address.size);
#endif
    } else {
        log_system(session, "Incoming connection via unknown protocol");
        free(session);
        return -1;
    }

    kick_client = true;

    session->request_limit = (ip_allowed(&(session->ip_address), session->config->request_limit_mask) != deny);
    if (session->request_limit == false) {
        conns_per_ip = config->total_connections;
    } else {
        conns_per_ip = config->connections_per_ip;
    }

    if ((total_conns = connection_allowed(&(session->ip_address), conns_per_ip, config->total_connections)) >= 0) {
        if (total_conns < (config->total_connections >> 2)) {
            one = 1;
            if (setsockopt(session->client_socket, IPPROTO_TCP, TCP_NODELAY, (void*)&one, sizeof(int)) == -1) {
                close(session->client_socket);
                free(session);
                log_string(config->system_logfile, "error setsockopt(TCP_NODELAY)");
                return -1;
            }

            if (config->socket_send_timeout > 0) {
                timer.tv_sec  = config->socket_send_timeout;
                timer.tv_usec = 0;
                if (setsockopt(session->client_socket, SOL_SOCKET, SO_SNDTIMEO, &timer, sizeof(struct timeval)) == -1) {
                    close(session->client_socket);
                    free(session);
                    log_string(config->system_logfile, "error setsockopt(SO_SNDTIMEO)");
                    return -1;
                }
            }
        }

        /* Pthread initialization */
        if (pthread_attr_init(&child_attr) != 0) {
            log_system(session, "pthread init error");
        } else {
            if (pthread_attr_setdetachstate(&child_attr, PTHREAD_CREATE_DETACHED) != 0) {
                log_system(session, "pthread set detach state error");
            } else if (pthread_attr_setstacksize(&child_attr, PTHREAD_STACK_SIZE) != 0) {
                log_system(session, "pthread set stack size error");
            } else if (add_client(session) == 0) {
                if (pthread_create(&child_thread, &child_attr, (void*)connection_handler, (void*)session) == 0) {
                    /* Thread started */
                    kick_client = false;
                } else {
                    remove_client(session, false);
                    log_system(session, "pthread create error");
                }
            }
            pthread_attr_destroy(&child_attr);
        }
    } else switch (total_conns) {
        case ca_TOOMUCH_PERIP:
            log_system(session, "Maximum number of connections for IP address reached");
            if ((config->ban_on_max_per_ip > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
                log_system(session, "Client banned because of too many simultaneous connections");
                ban_ip(&(session->ip_address), config->ban_on_max_per_ip, config->kick_on_ban);
            }
            break;
        case ca_TOOMUCH_TOTAL:
            log_system(session, "Maximum number of total connections reached");
            break;
        case ca_BANNED:
            if (config->reban_during_ban && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
                reban_ip(&(session->ip_address));
            }
            break;
        }

    if (kick_client) {
        close(session->client_socket);
        free(session);
    }

    return 0;
}

/**
    Run the Araneum HTTP Server.
*/
int run_server(t_settings *settings) {
    int                highest_fd;
    struct timeval     select_timeout;
    pthread_attr_t     task_runner_attr;
    pthread_t          task_runner_thread;
#ifdef HAVE_SSL
    char               random_buffer[RANDOM_BUFFER_SIZE];
#endif
    pid_t              pid;
    t_binding          *binding;
    t_config           *config;
    fd_set             read_fds;
#ifndef CYGWIN
    struct stat        status;
    mode_t             access_rights;
#endif

    config = default_config();

    if(chdir(settings->config_dir) == -1) {
        perror(settings->config_dir);
        return -1;
    } else if(settings->config_check) {
        printf("Using %s\n", settings->config_dir);
    }

    if(read_main_configfile("httpd.conf", config, settings->config_check) == -1) {
        return -1;
    } else if(check_configuration(config) == -1) {
        return -1;
    }

    if (read_mimetypes(config->mimetype_config, &(config->mimetype)) == -1) {
        fputs("Error while reading mimetype configuration.",stderr);
        return -1;
    }

    if (settings->config_check) {
        puts("Configuration OK.");
        return 0;
    }

    /* Bind Serverports */
    if (bind_sockets(config->binding) == -1) {
        return -1;
    }

#ifdef HAVE_SSL
    fill_random_buffer(config, random_buffer, RANDOM_BUFFER_SIZE);
    if (ssl_init(random_buffer, RANDOM_BUFFER_SIZE) == -1) {
        perror("ssl initialize");
        return -1;
    }

    binding = config->binding;
    while (binding != NULL) {
        if (binding->use_ssl) {
            if ((binding->ssl_context = ssl_binding(binding->ssl_key_cert, binding->required_ca, binding->verify_depth, config->dh_file, config->allowed_ciphers)) == NULL) {
                perror("bind https");
                return -1;
            }
        }
        binding = binding->next;
    }
#endif

    /* Misc settings */
    tzset();
    clearenv();

    /* Become a daemon */
    if (settings->daemon) {
        switch (pid = fork()) {
        case -1:
            perror("fork()");
            return -1;
        case 0:
            if (setsid() == -1) {
                perror("setsid()");
                return -1;
            }
            break;
        default:
            log_pid(config, pid);
            return 0;
        }
    } else {
        log_pid(config, getpid());
    }

#ifdef HAVE_CHROOT
    /* Change server root */
    if (config->server_root != NULL) {
        do {
            if (chdir(config->server_root) != -1) {
                if (chroot(config->server_root) != -1) {
                    break;
                }
            }
            fprintf(stderr, "\nError while changing root to %s!\n", config->server_root);
            return -1;
        } while (false);

#ifdef CYGWIN
    } else if (chdir("/cygdrive/c") == -1) {
#else
    } else if (chdir("/") == -1) {
#endif
        fputs("\nError while changing to root directory!",stderr);
        return -1;
    }
#endif

    /* Create work directory */
    if (mkdir(config->work_directory, 0700) == -1) {
        if (errno != EEXIST) {
            fprintf(stderr, "Error creating work directory '%s'\n", config->work_directory);
            return -1;
#ifndef CYGWIN
        } else if (chmod(config->work_directory, 0700) == -1) {
            fprintf(stderr, "Can't change access permissions of work directory '%s'\n", config->work_directory);
            return -1;
#endif
        }
    }
#ifndef CYGWIN
    if ((getuid() == 0) || (geteuid() == 0)) {
        if (chown(config->work_directory, config->server_uid, config->server_gid) == -1) {
            perror("chown(WorkDirectory)");
            return -1;
        }
    }
#endif

    /* Create the upload directory for PUT requests */
    if (mkdir(config->upload_directory, 0733) == -1) {
        if (errno != EEXIST) {
            fprintf(stderr, "Error while creating UploadDirectory '%s'\n", config->upload_directory);
            return -1;
        }
    }

#ifndef CYGWIN
    if (stat(config->upload_directory, &status) == -1) {
        perror("stat(UploadDirectory)");
        return -1;
    }
    access_rights = 01733;
    if (status.st_uid != 0) {
        if ((getuid() == 0) || (geteuid() == 0)) {
            if (chown(config->upload_directory, 0, 0) == -1) {
                perror("chown(UploadDirectory, 0, 0)");
                return -1;
            }
        } else {
            access_rights = 01333;
        }
    }

    if ((status.st_mode & 07777) != access_rights) {
        if (chmod(config->upload_directory, access_rights) == -1) {
            fprintf(stderr, "Can't change access permissions of UploadDirectory '%s'.\n", config->upload_directory);
            return -1;
        }
    }
#endif

    /* Create logfiles */
#ifdef HAVE_CHROOT
    touch_logfiles(config, config->server_root);
#else
    touch_logfiles(config, "");
#endif

    /* Change userid */
#ifndef CYGWIN
    if ((getuid() == 0) || (geteuid() == 0)) do {
            if (setgroups(config->groups.number, config->groups.array) != -1) {
                if (setgid(config->server_gid) != -1) {
                    if (setuid(config->server_uid) != -1) {
                        break;
                    }
                }
            }
            fputs("\nError while changing uid/gid!",stderr);
            return -1;
        } while (false);
#endif

    if (settings->daemon == false) {
        puts("Press Ctrl-C to shutdown the Araneum HTTP Server.");
        signal(SIGINT, TERM_handler);
    } else {
        signal(SIGINT, SIG_IGN);
    }

    /* Set signal handlers */
    if (config->wait_for_cgi == false) {
        signal(SIGCHLD, SIG_IGN);
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGSEGV, SEGV_handler);
    signal(SIGTERM, TERM_handler);
    signal(SIGHUP,  HUP_handler);
    signal(SIGUSR1, USR1_handler);
#ifdef HAVE_CACHE
    signal(SIGUSR2, USR2_handler);
#endif

    /* Start listening for incoming connections */
    binding = config->binding;
    while (binding != NULL) {
        if (listen(binding->socket, 16) == -1) {
            perror("listen(http(s))");
            return -1;
        }
        binding = binding->next;
    }

    init_log_module();
    init_client_module();
    init_load_balancer(config->fcgi_server);
#ifdef HAVE_CACHE
    init_cache_module();
#endif

    /* Redirecting I/O to /dev/null */
    if (settings->daemon) {
        if (close(STDIN_FILENO) == -1) {
            fputs("Warning: error closing STDIN",stderr);
        } else if (open("/dev/null", O_RDONLY) == -1) {
            fputs("Warning: error redirecting stdin",stderr);
        }
        if (close(STDOUT_FILENO) == -1) {
            fputs("Warning: error closing STDOUT",stderr);
        } else if (open("/dev/null", O_WRONLY) == -1) {
            fputs("Warning: error redirecting stdout",stderr);
        }
        if (close(STDERR_FILENO) == -1) {
            fputs("Warning: error closing STDERR",stderr);
        } else if (open("/dev/null", O_WRONLY) == -1) {
            log_string(config->system_logfile, "Warning: error redirecting stderr\n");
        }
    }

    log_string(config->system_logfile, PACKAGE_STRING" started");

    /* Start task_runner */
    if (pthread_attr_init(&task_runner_attr) != 0) {
        fprintf(stderr, "Task-runner pthread init error");
        return -1;
    } else if (pthread_attr_setdetachstate(&task_runner_attr, PTHREAD_CREATE_DETACHED) != 0) {
        fprintf(stderr, "Task-runner pthread set detach state error");
        return -1;
    } else if (pthread_attr_setstacksize(&task_runner_attr, PTHREAD_STACK_SIZE) != 0) {
        fprintf(stderr, "Task-runner pthread set stack size error");
        return -1;
    } else if (pthread_create(&task_runner_thread, &task_runner_attr, (void*)task_runner, (void*)config) != 0) {
        fprintf(stderr, "Task-runner pthread create error");
        return -1;
    }
    pthread_attr_destroy(&task_runner_attr);

    /* Main loop */
    do {
        highest_fd = fill_read_fds(&read_fds, config->binding);

        select_timeout.tv_sec = 1;
        select_timeout.tv_usec = 0;
        switch (select(highest_fd + 1, &read_fds, NULL, NULL, &select_timeout)) {
        case -1:
            if (errno != EINTR) {
                log_string(config->system_logfile, "Fatal error selecting connection");
                usleep(1000);
            }
            break;
        case 0:
            break;
        default:

            /* HTTP(S) ports */
            binding = config->binding;
            while (binding != NULL) {
                if (FD_ISSET(binding->socket, &read_fds)) {
                    if (accept_connection(binding, config) != 0) {
                        usleep(1000);
                        break;

                    }
                }
                binding = binding->next;
            }

        }
    } while (must_quit == false);

    signal(SIGTERM, SIG_DFL);

    close_bindings(config->binding);

    disconnect_clients(config);

    log_string(config->system_logfile, PACKAGE_STRING" stopped");
    close_logfiles(config->first_host, 0);

    return 0;
}

/**
    This is where it all starts.
*/
int main(int argc, char *argv[]) {
    register int i = 0;
    t_settings settings;

    /* Default settings */
    settings.config_dir   = CONFIG_DIR;
    settings.daemon       = true;
    settings.config_check = false;

    /* Read commandline parameters */
    while(++i < argc) {
        if(strcmp(argv[i], "-c") == 0) {
            if (++i < argc) {
                settings.config_dir = argv[i];
            } else {
                fputs("Specify a directory.",stderr);
                return EXIT_FAILURE;
            }
        } else if(strcmp(argv[i], "-d") == 0) {
            settings.daemon = false;
        } else if(strcmp(argv[i], "-h") == 0) {
            puts("Usage: araneum [options]\nOptions: -c <path>: path to where the configfiles are located.\n         -d: don't fork to the background.\n         -h: you are looking at it!\n         -k: check config and exit.\n         -v: show version number.");
            return EXIT_SUCCESS;
        } else if(strcmp(argv[i], "-k") == 0) {
            settings.config_check = true;
        } else if(strcmp(argv[i], "-v") == 0) {
            puts(PACKAGE_STRING"\n - Copyright (C) 2010-2013 Koppin22 Media DA\n - Copyright (C) 2002-2010 Hugo Leisink");
            return EXIT_SUCCESS;
        } else {
            fputs("Unknown option. Use '-h' for help.",stderr);
            return EXIT_FAILURE;
        }

    }

    /* Run Araneum HTTP server. */
    if(run_server(&settings) == -1) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
