/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License. For a copy,
 * see http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * The copyright holder gives permission to link this code with the OpenSSL
 * library and distribute linked combinations including the two. You must obey
 * the GNU General Public License in all respects for all of the code used other
 * than OpenSSL. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * do so, delete this exception statement from your version.
 */

#include "config.h"

#ifdef HAVE_SSL

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "alternative.h"
#include "libssl.h"

static pthread_mutex_t *locks;
static int lockcount;

#ifdef DEBUG
int print_ssl_error(SSL *ssl, int code) {
    int result;

    switch (result = SSL_get_error(ssl, code)) {
    case SSL_ERROR_ZERO_RETURN:
        fprintf(stderr, "connection closed\n");
        break;
    case SSL_ERROR_WANT_READ:
        fprintf(stderr, "read incomplete\n");
        break;
    case SSL_ERROR_WANT_WRITE:
        fprintf(stderr, "write incomplete\n");
        break;
    case SSL_ERROR_WANT_CONNECT:
        fprintf(stderr, "connect incomplete\n");
        break;
    case SSL_ERROR_WANT_ACCEPT:
        fprintf(stderr, "accept incomplete\n");
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        fprintf(stderr, "X509 lookup incomplete\n");
        break;
    case SSL_ERROR_SYSCALL:
        fprintf(stderr, "I/O error\n");
        break;
    case SSL_ERROR_SSL:
        fprintf(stderr, "protocol error\n");
        break;
    default:
        fprintf(stderr, "unknown error\n");
        break;
    }

    return result;
}
#endif

/* SSL multithread locking callback
 */
static void locking_callback(int mode, int n, const char *file, int line) {
    if ((n >= 0) && (n < lockcount)) {
        if (mode & CRYPTO_LOCK) {
            pthread_mutex_lock(&locks[n]);
        } else {
            pthread_mutex_unlock(&locks[n]);
        }
    } else {
        syslog(LOG_DAEMON | LOG_ALERT, "libssl::locking_callback() error!");
        exit(EXIT_FAILURE);
    }
}

/* SSL thread ID callback
 */
static unsigned long id_callback() {
    return (unsigned long)pthread_self();
}

/* Password callback
 */
static int password_callback(char *buffer, int size, int rwflag, void *data) {
    int len;

    if ((len = (int)strlen((char*)data) + 1) > size) {
        return 0;
    }
    memcpy(buffer, (char*)data, len);

    return len;
}

int ssl_init(char *buffer, int size) {
    int i;

    SSL_library_init();
    SSL_load_error_strings();

    if (buffer != NULL) {
        RAND_add(buffer, size, (double)size);
    }

    lockcount = CRYPTO_num_locks();
    if (lockcount > 0) {
        if ((locks = malloc(lockcount * sizeof(pthread_mutex_t))) != NULL) {
            for (i = 0; i < lockcount; i++) {
                if (pthread_mutex_init(&locks[i], NULL) != 0) {
                    return -1;
                }
            }
        }
    }

    CRYPTO_set_locking_callback(locking_callback);
    CRYPTO_set_id_callback(id_callback);

    return 0;
}

static int load_dh_params(SSL_CTX *context, char *file) {
    DH *dh = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(file,"r")) == NULL) {
        fprintf(stderr, "Couldn't open DH file");
        return -1;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (SSL_CTX_set_tmp_dh(context, dh) != 1) {
        fprintf(stderr, "Couldn't set DH parameters");
        return -1;
    }

    return 0;
}

SSL_CTX *ssl_binding(char *keyfile, char *ca_cert, int verify_depth, char *dh_file, char *ciphers) {
    SSL_METHOD *meth;
    SSL_CTX    *context;
    STACK_OF(X509_NAME) *ca_list;

    if ((meth = SSLv23_method()) == NULL) {
        fprintf(stderr, "SSLv23_method() error\n");
        return NULL;
    }
    if ((context = SSL_CTX_new(meth)) == NULL) {
        fprintf(stderr, "SSL_CTX_new() error\n");
        return NULL;
    }

    SSL_CTX_set_options(context, SSL_OP_NO_SSLv2);

    if (SSL_CTX_use_certificate_chain_file(context, keyfile) != 1) {
        fprintf(stderr, "Error while reading certificate (chain) from %s\n", keyfile);
        return NULL;
    }

    SSL_CTX_set_default_passwd_cb(context, password_callback);
    /* SSL_CTX_set_default_passwd_cb_userdata(context, (void*)password); */
    if (SSL_CTX_use_PrivateKey_file(context, keyfile, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Error while reading private key from %s\n", keyfile);
        return NULL;
    }

    if (SSL_CTX_check_private_key(context) != 1) {
        fprintf(stderr, "Private key does not match the certificate\n");
        return NULL;
    }

    if (ca_cert != NULL) {
        SSL_CTX_set_verify_depth(context, verify_depth);
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
        if (SSL_CTX_load_verify_locations(context, ca_cert, NULL) != 1) {
            fprintf(stderr, "Error while setting CA verify locations\n");
            return NULL;
        }

        if ((ca_list = SSL_load_client_CA_file(ca_cert)) == NULL) {
            fprintf(stderr, "Error while loading CA certificate file\n");
            return NULL;
        }
        SSL_CTX_set_client_CA_list(context, ca_list);
    }

    if (dh_file != NULL) {
        if (load_dh_params(context, dh_file) == -1) {
            fprintf(stderr, "Error while loading DH file\n");
            return NULL;
        }
    }
    if (ciphers != NULL) {
        if (SSL_CTX_set_cipher_list(context, ciphers) == 0) {
            fprintf(stderr, "Error while setting cipher list\n");
            return NULL;
        }
    }

    return context;
}

int ssl_accept(int sock, SSL **ssl, SSL_CTX *context, int timeout) {
    BIO *bio;
    int result;
    struct timeval select_timeout;
    fd_set read_fds;

    if ((bio = BIO_new_socket(sock, 0)) == NULL) {
        return -1;
    } else if ((*ssl = SSL_new(context)) == NULL) {
        return -1;
    }

    SSL_set_bio(*ssl, bio, bio);

    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    select_timeout.tv_sec = timeout;
    select_timeout.tv_usec = 0;

    result = select(sock + 1, &read_fds, NULL, NULL, &select_timeout);
    if (result == -1) {
        return -1;
    } else if (result == 0) {
        return -2;
    }

    if ((result = SSL_accept(*ssl)) != 1) {
#ifdef DEBUG
        fprintf(stderr, "SSL_accept(): ");
        print_ssl_error(*ssl, result);
#endif
        SSL_free(*ssl);
        return -1;
    }

    return 0;
}

int ssl_receive(SSL *ssl, char *buffer, unsigned int maxlength) {
    int result;

    result = SSL_read(ssl, buffer, maxlength);
    if (result > 0) {
        return result;
    } else if (result == 0) {
        if (SSL_get_error(ssl, result) == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
    }

#ifdef DEBUG
    fprintf(stderr, "SSL_read(): ");
    print_ssl_error(ssl, result);
#endif

    return -1;
}

int ssl_send(SSL *ssl, char *buffer, unsigned int length) {
    int result;

    result = SSL_write(ssl, buffer, length);
    if (result > 0) {
        return result;
    } else if (result == 0) {
        if (SSL_get_error(ssl, result) == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
    }

#ifdef DEBUG
    fprintf(stderr, "SSL_write(): ");
    print_ssl_error(ssl, result);
#endif

    return -1;
}

int ssl_close(SSL **ssl) {
    int result;

    result = SSL_shutdown(*ssl);
    SSL_free(*ssl);
    *ssl = NULL;

    ERR_remove_state(0);

    return result;
}

void ssl_free(SSL_CTX *context) {
    SSL_CTX_free(context);
}

int get_client_certificate(SSL *ssl_data, char *subject, char *issuer, int size) {
    X509 *cert;

    subject[size - 1] = '\0';
    issuer[size - 1] = '\0';

    if ((cert = SSL_get_peer_certificate(ssl_data)) == NULL) {
        return -1;
    }

    X509_NAME_oneline(X509_get_subject_name(cert), subject, size - 1);
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, size - 1);

    return 0;
}

#endif
