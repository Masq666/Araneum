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

#ifndef _LIBSSL_H
#define _LIBSSL_H

#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

int  ssl_init(char *buffer, int size);
SSL_CTX *ssl_binding(char *keyfile, char *ca_cert, int verify_depth, char *dh_file, char *ciphers);
int  ssl_accept(int sock, SSL **ssl, SSL_CTX *context, int timeout);
int  ssl_receive(SSL *ssl, char *buffer, unsigned int maxlength);
int  ssl_send(SSL *ssl, char *buffer, unsigned int length);
int  ssl_close(SSL **ssl);
void ssl_free(SSL_CTX *context);
int  get_client_certificate(SSL *ssl_data, char *subject, char *issuer, int size);

#endif
