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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_SSL
#include "libssl.h"
#endif
#include "libstr.h"
#include "libmd5.h"
#include "log.h"
#include "send.h"

#define MAX_CHUNK_SIZE 2048
#define MAX_TO_BUFFER 400
#define NONCE_DIGITS 10
#define SEND_TIMEOUT 5
#define TIMESTR_SIZE 64

static char *hs_http10  = "HTTP/1.0 ";                  /*  9 */
static char *hs_http11  = "HTTP/1.1 ";                  /*  9 */
static char *hs_server  = "Server: ";                   /*  8 */
static char *hs_conn    = "Connection: ";               /* 12 */
static char *hs_concl   = "close\r\n";                  /*  7 */
static char *hs_conka   = "keep-alive\r\n";             /* 12 */
char *hs_contyp  = "Content-Type: ";                    /* 14 */                /* Used in target.c */
static char *hs_lctn    = "Location: ";                 /* 10 */
static char *hs_expires = "Expires: ";                  /*  9 */
static char *hs_http    = "http://";                    /*  7 */
static char *hs_https   = "https://";                   /*  8 */
static char *hs_range   = "Accept-Ranges: bytes\r\n";   /* 22 */
static char *hs_gzip    = "Content-Encoding: gzip\r\n"; /* 24 */
char *hs_eol     = "\r\n";                              /*  2 */                /* Used in target.c */

/**
    Send a char buffer to the client. Traffic throttling is handled here.
*/
static int send_to_client(t_session *session, const char *buffer, int size) {
    /* HELP!! No socket open. */
    if (session->socket_open == false) {
        return -1;
    } else if ((buffer == NULL) || (size <= 0)) {
        return 0;
    }

    int bytes_sent = 0, total_sent = 0, can_send, rest;
    time_t new_time;

    if (session->directory != NULL) {
        if (session->directory->session_speed > 0) {
            session->throttle = session->directory->session_speed;
        }
    }

    do {
        rest = size - total_sent;
        if (session->throttle > 0) {
            do {
                new_time = time(NULL);
                if (session->throttle_timer < new_time) {
                    session->bytecounter = 0;
                    session->throttle_timer = new_time;
                }
                can_send = session->throttle - session->bytecounter;
                if (can_send <= 0) {
                    usleep(10000);
                }
            } while (can_send <= 0);
            if (can_send > rest) {
                can_send = rest;
            }
        } else {
            can_send = rest;
        }

#ifdef HAVE_SSL
        if (session->binding->use_ssl) {
            if ((bytes_sent = ssl_send(session->ssl_data, (char*)(buffer + total_sent), can_send)) <= 0) {
                bytes_sent = -1;
            }
        } else
#endif
            if ((bytes_sent = send(session->client_socket, (char*)(buffer + total_sent), can_send, 0)) <= 0) {
                bytes_sent = -1;
            }

        /* Handle read result */
        if (bytes_sent == -1) {
            if (errno != EINTR) {
                if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                    log_error(session, "send timeout");
                } else if ((errno != EPIPE) && (errno != ECONNRESET)) {
                    log_error(session, "socket error");
                }
                close_socket(session);
                session->keep_alive = false;
                return -1;
            }
        } else {
            total_sent += bytes_sent;
            session->bytecounter += bytes_sent;
        }
    } while (total_sent < size);

    return 0;
}

/**
    This function has been added to improve speed by buffering small amounts of data to be sent.

    @param  t_session *session      Current Session.
    @param  const char *buffer      Buffer to send.
    @param  int size                Size of buffer.
    @return int                     -1 on failure, 0 on success.
*/
int send_buffer(t_session *session, const char *buffer, int size) {

    if (size > MAX_TO_BUFFER) {
        if (session->output_size > 0) {
            if (send_to_client(session, session->output_buffer, session->output_size) == -1) {
                return -1;
            }
            session->output_size = 0;
        }
        if (send_to_client(session, buffer, size) == -1) {
            return -1;
        }
    } else if (buffer == NULL) {
        if (session->output_size > 0) {
            if (send_to_client(session, session->output_buffer, session->output_size) == -1) {
                return -1;
            }
            session->output_size = 0;
        }
    } else {
        if ((session->output_size + size > OUTPUT_BUFFER_SIZE) && (session->output_size > 0)) {
            if (send_to_client(session, session->output_buffer, session->output_size) == -1) {
                return -1;
            }
            session->output_size = 0;
        }

        memcpy(session->output_buffer + session->output_size, buffer, size);
        session->output_size += size;
    }

    session->bytes_sent += size;

    return 0;
}

/**
    Send a HTTP header to the client. Header is not closed by this function.

    @param  t_session *session      Current Session.
    @return int                     -1 on failure, 0 on success.
*/
int send_header(t_session *session) {
    char timestr[TIMESTR_SIZE], buf[100];
    time_t t;
    struct tm *s;

    /* Send HTTP header. */
    session->data_sent = true;

    /* HTTP version */
    if (((session->http_version != NULL)) && (*(session->http_version + 7) == '0')) {
        if (send_buffer(session, hs_http10, 9) == -1) {
            return -1;
        }
    } else {
        if (send_buffer(session, hs_http11, 9) == -1) {
            return -1;
        }
    }

    /* HTTP code */
    snprintf(buf,sizeof(buf)-1,"%d %s\r\n",session->return_code,http_error(session->return_code));
    if (send_buffer(session, buf, strlen(buf)) == -1) {
        return -1;
    }

    /* Date */
    if (time(&t) == -1) {
        return -1;
    } else if ((s = gmtime(&t)) == NULL) {
        return -1;
    } else if (strftime(timestr, TIMESTR_SIZE, "%a, %d %b %Y %X GMT\r\n", s) == 0) {
        return -1;
    } else if (send_buffer(session, "Date: ", 6) == -1) {
        return -1;
    } else if (send_buffer(session, timestr, strlen(timestr)) == -1) {
        return -1;
    }

    /* Server */
    if (session->config->server_string != NULL) {
        snprintf(buf,sizeof(buf)-1,"%s%s\r\n",hs_server,session->config->server_string); /* Let's reuse our char buffer. */
        if (send_buffer(session, buf, strlen(buf)) == -1) {
            return -1;
        }
    }

    /* Range */
    if ((session->cgi_type == no_cgi) && (session->uri_is_dir == false)) {
        if (send_buffer(session, hs_range, 22) == -1) {
            return -1;
        }
    }

    /* Connection */
    if (send_buffer(session, hs_conn, 12) == -1) {
        return -1;
    } else if (session->keep_alive) {
        if (send_buffer(session, hs_conka, 12) == -1) {
            return -1;
        }
    } else if (send_buffer(session, hs_concl, 7) == -1) {
        return -1;
    }

    /* Content-Encoding */
    if (session->encode_gzip) {
        if (send_buffer(session, hs_gzip, 24) == -1) {
            return -1;
        }
    }

    /* Content-Type */
    if (session->mimetype != NULL) {
        snprintf(buf,sizeof(buf)-1,"%s%s\r\n",hs_contyp,session->mimetype); /* Let's reuse our char buffer. */
        if (send_buffer(session, buf, strlen(buf)) == -1) {
            return -1;
        }
    }

    /* Expires */
    if ((session->expires > -1) && (session->return_code == 200)) {
        if (time(&t) == -1) {
            return -1;
        }
        t += (time_t)session->expires;

        if ((s = gmtime(&t)) == NULL) {
            return -1;
        } else if (send_buffer(session, hs_expires, 9) == -1) {
            return -1;
        } else if (strftime(timestr, TIMESTR_SIZE, "%a, %d %b %Y %X GMT\r\n", s) == 0) {
            return -1;
        } else if (send_buffer(session, timestr, strlen(timestr)) == -1) {
            return -1;
        }
    }

    return 0;
}

/**
    Send a datachunk to the client, used by run_script() in target.c
*/
static int send_chunk_to_client(t_session *session, const char *chunk, int size) {
    char hex[10];

    if (session->keep_alive) {
        hex[9] = '\0';
        if (snprintf(hex, 9, "%x\r\n", size) < 0) {
            return -1;
        } else if (send_to_client(session, hex, strlen(hex)) == -1) {
            return -1;
        }
    }

    if (send_to_client(session, chunk, size) == -1) {
        return -1;
    }

    if (session->keep_alive) {
        if (send_to_client(session, "\r\n", 2) == -1) {
            return -1;
        }
    }

    return 0;
}

int send_chunk(t_session *session, const char *chunk, int size) {
    if (size > MAX_TO_BUFFER) {
        if (session->output_size > 0) {
            if (send_chunk_to_client(session, session->output_buffer, session->output_size) == -1) {
                return -1;
            }
            session->output_size = 0;
        }
        if (send_chunk_to_client(session, chunk, size) == -1) {
            return -1;
        }
    } else if (chunk == NULL) {
        if (session->output_size > 0) {
            if (send_chunk_to_client(session, session->output_buffer, session->output_size) == -1) {
                return -1;
            }
            session->output_size = 0;
        }
        if (send_to_client(session, "0\r\n\r\n", 5) == -1) {
            return -1;
        }
    } else {
        if ((session->output_size + size > OUTPUT_BUFFER_SIZE) && (session->output_size > 0)) {
            if (send_chunk_to_client(session, session->output_buffer, session->output_size) == -1) {
                return -1;
            }
            session->output_size = 0;
        }

        memcpy(session->output_buffer + session->output_size, chunk, size);
        session->output_size += size;
    }

    session->bytes_sent += size;

    return 0;
}

/**
    Send a HTTP code to the client. Used in case of an error.

    @param  t_session *session      Current Session.
    @return int                     -1 on failure, 0 on success.
*/
int send_code(t_session *session) {
    int default_port;
    char port[10];

    if (session->return_code == -1) {
        session->return_code = 500;
    }

    /* Send simple HTTP error message. */
    session->mimetype = NULL;
    if (send_header(session) == -1) {
        return -1;
    }

    switch (session->return_code) {
    case 301:
        if (send_buffer(session, hs_lctn, 10) == -1) {
            return -1;
        }

        if (session->cause_of_301 == location) {
            if (session->location != NULL) {
                if (send_buffer(session, session->location, strlen(session->location)) == -1) {
                    return -1;
                }
            }
            if (send_buffer(session, "\r\n", 2) == -1) {
                return -1;
            }
            break;
        }

#ifdef HAVE_SSL
        if (session->binding->use_ssl || (session->cause_of_301 == require_ssl)) {
            if (send_buffer(session, hs_https, 8) == -1) {
                return -1;
            }
        } else
#endif
            if (send_buffer(session, hs_http, 7) == -1) {
                return -1;
            }

        if (session->hostname != NULL) {
            if (send_buffer(session, session->hostname, strlen(session->hostname)) == -1) {
                return -1;
            }
        } else if (send_buffer(session, *(session->host->hostname.item), strlen(*(session->host->hostname.item))) == -1) {
            return -1;
        }

        if (session->cause_of_301 != require_ssl) {
#ifdef HAVE_SSL
            if (session->binding->use_ssl) {
                default_port = 443;
            } else
#endif
                default_port = 80;

            if (session->binding->port != default_port) {
                /*port[9] = '\0';*/
                snprintf(port, 9, ":%d", session->binding->port);
                if (send_buffer(session, port, strlen(port)) == -1) {
                    return -1;
                }
            }
        }

        if (send_buffer(session, session->uri, session->uri_len) == -1) {
            return -1;
        }

        if (session->cause_of_301 == missing_slash) {
            if (send_buffer(session, "/", 1) == -1) {
                return -1;
            }
        }
        if (session->vars != NULL) {
            if (send_buffer(session, "?", 1) == -1) {
                return -1;
            } else if (send_buffer(session, session->vars, strlen(session->vars)) == -1) {
                return -1;
            }
        }
        if (send_buffer(session, "\r\n", 2) == -1) {
            return -1;
        }
        break;
    case 401:
        if (session->host->auth_method == basic) {
            send_basic_auth(session);
        } else {
            send_digest_auth(session);
        }
        break;
    }

    const char *emesg = http_error(session->return_code);

    char cbuf[1024], hbuf[256];    /* Content and Header Buffer */
    snprintf(cbuf, 1024,"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\"><html><head><title>%d - %s</title><style type=\"text/css\">body{font-family:Arial,Helvetica,sans-serif;background-color:#441;font-size:12px;line-height:2em;color:#000;}h1{font-size:2em;margin-bottom:.4em;font-weight:normal;}a{color:#0088b5;text-decoration:underline;}a:hover{color:#8ab54a;text-decoration:none;}.bc{padding:30px 45px 45px 30px;margin:100px auto 0 auto;border:6px solid #000;background-color:#fff;width:450px}.tc{padding:20px 50px 0 65px;text-align:center;}.f{margin-top:50px;font-size:8pt;text-align:right;}</style></head><body><div class=bc><div class=tc><h1>%d - %s</h1></div><div class=f> &copy; 2010-2011 <a href=\"http://koppin22.com\">Koppin22 Media DA.</a> All rights reserved.</div></div></body></html>",session->return_code,emesg,session->return_code,emesg);
    snprintf(hbuf, 256, "Content-Length: %d\r\n%stext/html\r\n\r\n",(int)strlen(cbuf),hs_contyp);

    /* Send Header */
    if (send_buffer(session, hbuf, (int)strlen(hbuf)) == -1) {
        return -1;
    }

    session->header_sent = true;

    if (session->request_method == HEAD) {
        return 0;
    }

    /* Send Error page Content */
    if (send_buffer(session, cbuf, (int)strlen(cbuf)) == -1) {
        return -1;
    }

    return 0;
}

/**
    Send directly to socket, unbuffered
*/
int send_directly(int sock, const char *buffer, int size) {
    int total_sent = 0, bytes_sent;

    if (size <= 0) {
        return 0;
    } else while (total_sent < size) {
            if ((bytes_sent = send(sock, buffer + total_sent, size - total_sent, 0)) == -1) {
                if (errno != EINTR) {
                    return -1;
                }
            } else {
                total_sent += bytes_sent;
            }
        }

    return 0;
}

static int set_padding(t_fcgi_buffer *fcgi_buffer, bool adjust_buffer) {
    unsigned char padding;

    if ((padding = (fcgi_buffer->data[5] & 7)) > 0) {
        padding = 8 - padding;
        if (adjust_buffer) {
            memset(fcgi_buffer->data + fcgi_buffer->size, 0, (size_t)padding);
            fcgi_buffer->size += (int)padding;
        }
    }
    fcgi_buffer->data[6] = padding;

    return (int)padding;
}

int send_fcgi_buffer(t_fcgi_buffer *fcgi_buffer, const char *buffer, int size) {
/*    int padding;*/

    if (size > FCGI_BUFFER_SIZE) {
        if (fcgi_buffer->size > 0) {
            set_padding(fcgi_buffer, true);
            if (send_directly(fcgi_buffer->sock, (char*)fcgi_buffer->data, fcgi_buffer->size) == -1) {
                return -1;
            }
        }

        memcpy(fcgi_buffer->data, "\x01\x00\x00\x01" "\xff\xff\x00\x00", 8);
        fcgi_buffer->data[1] = fcgi_buffer->mode;
        fcgi_buffer->data[4] = (FCGI_BUFFER_SIZE >> 8 ) & 255;
        fcgi_buffer->data[5] = FCGI_BUFFER_SIZE & 255;

        int padding = set_padding(fcgi_buffer, false);
        if (send_directly(fcgi_buffer->sock, (char*)fcgi_buffer->data, 8) == -1) {
            return -1;
        } else if (send_directly(fcgi_buffer->sock, buffer, FCGI_BUFFER_SIZE) == -1) {
            return -1;
        }

        fcgi_buffer->size = 0;
        memset(fcgi_buffer->data, 0, (size_t)padding);

        if (send_directly(fcgi_buffer->sock, (char*)fcgi_buffer->data, padding) == -1) {
            return -1;
        } else if (send_fcgi_buffer(fcgi_buffer, buffer + FCGI_BUFFER_SIZE, size - FCGI_BUFFER_SIZE) == -1) {
            return -1;
        }
    } else if (buffer == NULL) {
        if (fcgi_buffer->size > 0) {
            set_padding(fcgi_buffer, true);
            if (send_directly(fcgi_buffer->sock, (char*)fcgi_buffer->data, fcgi_buffer->size) == -1) {
                return -1;
            }
        }

        memcpy(fcgi_buffer->data, "\x01\x00\x00\x01" "\x00\x00\x00\x00", 8);
        fcgi_buffer->data[1] = fcgi_buffer->mode;
        set_padding(fcgi_buffer, true);
        if (send_directly(fcgi_buffer->sock, (char*)fcgi_buffer->data, 8) == -1) {
            return -1;
        }

        fcgi_buffer->size = 0;
    } else {
        if ((fcgi_buffer->size + size > FCGI_BUFFER_SIZE) && (fcgi_buffer->size > 0)) {
            set_padding(fcgi_buffer, true);
            if (send_directly(fcgi_buffer->sock, (char*)fcgi_buffer->data, fcgi_buffer->size) == -1) {
                return -1;
            }
            fcgi_buffer->size = 0;
        }

        if (fcgi_buffer->size == 0) {
            memcpy(fcgi_buffer->data, "\x01\x00\x00\x01" "\x00\x00\x00\x00", 8);
            fcgi_buffer->data[1] = fcgi_buffer->mode;
            fcgi_buffer->size = 8;
        }
        memcpy(fcgi_buffer->data + fcgi_buffer->size, buffer, size);
        fcgi_buffer->size += size;
        fcgi_buffer->data[4] = ((fcgi_buffer->size - 8) >> 8) & 255;
        fcgi_buffer->data[5] = (fcgi_buffer->size - 8) & 255;
    }

    return 0;
}

/**
    Send a Basic Authentication message to the client.

    @param  t_session *session      Current Session.
*/
void send_basic_auth(t_session *session) {
    if (send_buffer(session, "WWW-Authenticate: Basic", 23) == -1) {
        return;
    } else if (session->host->login_message != NULL) {
        if (send_buffer(session, " realm=\"", 8) == -1) {
            return;
        } else if (send_buffer(session, session->host->login_message, strlen(session->host->login_message)) == -1) {
            return;
        } else if (send_buffer(session, "\"", 1) == -1) {
            return;
        }
    }
    send_buffer(session, "\r\n", 2);
}

/**
    Send a Digest Authentication message to the client.

    @param  t_session *session      Current Session.
*/
void send_digest_auth(t_session *session) {
    char nonce[2 * NONCE_DIGITS + 1];
    int i;

    for (i = 0; i < NONCE_DIGITS; i++) {
        snprintf(nonce + (2 * i), 3, "%02hhX", (char)random());
    }

    if (send_buffer(session, "WWW-Authenticate: Digest", 24) == -1) {
        return;
    } else if (session->host->login_message != NULL) {
        if (send_buffer(session, " realm=\"", 8) == -1) {
            return;
        } else if (send_buffer(session, session->host->login_message, strlen(session->host->login_message)) == -1) {
            return;
        } else if (send_buffer(session, "\"", 1) == -1) {
            return;
        }
    }
    if (send_buffer(session, ", nonce=\"", 9) == -1) {
        return;
    } else if (send_buffer(session, nonce, 2 * NONCE_DIGITS) == -1) {
        return;
    }
    send_buffer(session, "\", algorithm=MD5, stale=false\r\n", 31);
}

int write_buffer(int handle, const char *buffer, int size) {
    long total_written = 0;
    ssize_t bytes_written;

    if (size <= 0) {
        return 0;
    } else while (total_written < size) {
            if ((bytes_written = write(handle, buffer + total_written, size - total_written)) == -1) {
                if (errno != EINTR) {
                    return -1;
                }
            } else {
                total_written += bytes_written;
            }
        }

    return 0;
}
