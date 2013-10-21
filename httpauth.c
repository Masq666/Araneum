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
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_RPCSVC_CRYPT_H
#include <rpcsvc/crypt.h>
#endif
#include <errno.h>
#include "libstr.h"
#include "liblist.h"
#include "libmd5.h"
#include "client.h"
#include "httpauth.h"
#include "log.h"

/**
    If a required_group_file exist, is a user in the right group?
*/
bool group_oke(t_session *session, char *user, t_charlist *group) {
    if ((user == NULL) || (group->size == 0)) {
        return true;
    }
    if (session->host->groupfile == NULL) {
        return false;
    }

    /*bool retval;*/
    FILE *gfp;
    char line[257], *item, *rest, *result;

    if ((gfp = fopen_neighbour(session->host->groupfile, "r", session->file_on_disk)) == NULL) {
        switch (errno) {
        case EACCES:
            result = "no access to group file";
            break;
        case ENOENT:
            result = "group file not found";
            break;
        default:
            result = "error while reading group file";
        }
        log_file_error(session, session->host->groupfile, result);
        return false;
    }

    bool retval = false;
    int len;
    line[256] = '\0';
    while (fgets(line, 256, gfp) != NULL) {
        if (split_string(line, &item, &rest, ':') == 0) {
            if (in_charlist(item, group)) {
                if ((len = strlen(rest)) == 0) {
                    continue;
                }
                if ((rest[len] == '\n') || (rest[len] == '\r')) {
                    rest[len] = '\0';
                }
                do {
                    split_string(rest, &item, &rest, ' ');
                    if (strcmp(user, item) == 0) {
                        retval = true;
                        break;
                    }
                } while (rest != NULL);
            }
        }
        if (retval == true) {
            break;
        }
    }
    fclose(gfp);

    return retval;
}

static FILE *open_password_file(t_session *session) {
    char *result;
    FILE *fp;

    if ((fp = fopen_neighbour(session->host->passwordfile, "r", session->file_on_disk)) == NULL) {
        switch (errno) {
        case EACCES:
            result = "no access to password file";
            break;
        case ENOENT:
            result = "password file not found";
            break;
        default:
            result = "error while reading password file";
        }
        log_file_error(session, session->host->passwordfile, result);
        return NULL;
    }

    return fp;
}

/**
    Get password from password file
*/
static char *get_password(t_session *session, char *username) {
    FILE *fp;

    if ((fp = open_password_file(session)) == NULL) {
        return NULL;
    }

    char line[257], *result = NULL, *sep;
    line[256] = '\0';
    while ((sep = fgets(line, 256, fp)) != NULL) {
        if ((sep = strchr(sep, ':')) == NULL) {
            continue;
        }

        *(sep++) = '\0';
        if (strcmp(line, username) != 0) {
            continue;
        }

        result = sep;
        while ((*sep != '\n') && (*sep != '\r') && (*sep != ':') && (*sep != '\0')) {
            sep++;
        }
        if (*sep != '\0') {
            *sep = '\0';
            result = strdup(result);
        } else {
            result = NULL;
        }
        break;
    }
    fclose(fp);

    return result;
}

/**
    Get password (A1) from password file
*/
static char *get_A1(t_session *session, char *username, char *realm) {
    FILE *fp;

    if ((fp = open_password_file(session)) == NULL) {
        return NULL;
    }

    char line[257], *result = NULL, *sep1, *sep2;
    line[256] = '\0';
    while ((sep1 = fgets(line, 256, fp)) != NULL) {
        if ((sep1 = strchr(sep1, ':')) == NULL) {
            continue;
        }

        *(sep1++) = '\0';
        if (strcmp(line, username) != 0) {
            continue;
        }

        if ((sep2 = strchr(sep1, ':')) == NULL) {
            continue;
        }

        *(sep2++) = '\0';
        if (strcmp(sep1, realm) != 0) {
            continue;
        }

        result = sep2;
        while ((*sep2 != '\n') && (*sep2 != '\r') && (*sep2 != ':') && (*sep2 != '\0')) {
            sep2++;
        }
        if (*sep2 != '\0') {
            *sep2 = '\0';
            result = strdup(result);
        } else {
            result = NULL;
        }
        break;
    }
    fclose(fp);

    return result;
}

/**
    Basic HTTP authentication.
*/
static bool basic_http_authentication(t_session *session, char *auth_str) {
    bool retval = false;
    char *auth_user, *auth_passwd, *passwd, *encrypted, salt[3];

    if ((auth_user = strdup(auth_str)) == NULL) {
        return false;
    }

    if (decode_base64(auth_user)) {
        auth_passwd = auth_user;
        while ((*auth_passwd != ':') && (*auth_passwd != '\0')) {
            auth_passwd++;
        }
        if (*auth_passwd == ':') {
            *(auth_passwd++) = '\0';

            if ((passwd = get_password(session, auth_user)) != NULL) {
                if (group_oke(session, auth_user, &(session->host->required_group))) {
                    salt[0] = *passwd;
                    salt[1] = *(passwd + 1);
                    salt[2] = '\0';
                    encrypted = crypt(auth_passwd, salt);

                    /* Password match? */
                    if (strcmp(encrypted, passwd) == 0) {
                        retval = ((session->remote_user = strdup(auth_user)) != NULL);
                    } else {
                        register_wrong_password(session);
                    }
                }
                free(passwd);
            }
        }
    }
    free(auth_user);

    return retval;
}

static char *unquoted(char *str) {
    /*int len;*/

    if (str != NULL) {
        int len = strlen(str);
        if (len > 0) {
            if (*str == '\"') {
                str++;
                len--;
            }
            if (str[len - 1] == '\"') {
                str[len - 1] = '\0';
            }
        }
    }

    return str;
}

/**
    Digest HTTP authentication.
*/
static bool digest_http_authentication(t_session *session, char *auth_str) {
    bool quote_found;
    char *key, *value, *rest, *empty = "", *passwd, A1[33], A2[33], result[33];
    char *username = empty, *realm = empty, *nonce = empty, *uri = empty, *qop = empty,
                                     *nc = empty, *cnonce = empty, *algoritm = empty, *response = empty, *opaque = empty;

    key = rest = auth_str;
    while (*key != '\0') {
        quote_found = false;
        while (*rest != '\0') {
            if (*rest == '"') {
                if (quote_found) {
                    if (*(rest + 1) == ',') {
                        rest++;
                        *(rest++) = '\0';
                        break;
                    } else if (*(rest + 1) == '\0') {
                        rest++;
                        break;
                    } else {
                        return false;
                    }
                }
                quote_found = true;
            } else if ((*rest == ',') && (quote_found == false)) {
                *(rest++) = '\0';
                break;
            }
            rest++;
        }

        if (split_string(key, &key, &value, '=') != -1) {
            if (strcmp(key, "username") == 0) {
                username = unquoted(value);
            } else if (strcmp(key, "realm") == 0) {
                realm = unquoted(value);
            } else if (strcmp(key, "nonce") == 0) {
                nonce = unquoted(value);
            } else if (strcmp(key, "uri") == 0) {
                uri = unquoted(value);
            } else if (strcmp(key, "qop") == 0) {
                qop = unquoted(value);
            } else if (strcmp(key, "nc") == 0) {
                nc = unquoted(value);
            } else if (strcmp(key, "cnonce") == 0) {
                cnonce = unquoted(value);
            } else if (strcmp(key, "algoritm") == 0) {
                algoritm = unquoted(value);
            } else if (strcmp(key, "response") == 0) {
                response = unquoted(value);
            } else if (strcmp(key, "opaque") == 0) {
                opaque = unquoted(value);
            }
        }
        key = rest;
    }

    if (strcmp(session->request_uri, uri) != 0) {
        return false;
    }

    /* Retrieve A1 from passwordfile */
    if ((passwd = get_A1(session, username, realm)) == NULL) {
        return false;
    } else if (strlen(passwd) != 32) {
        free(passwd);
        return false;
    }
    memcpy(A1, passwd, 33);
    free(passwd);

    /* Group OK? */
    if (group_oke(session, username, &(session->host->required_group)) == false) {
        return false;
    }

    /* Calculate A2 */
    if ((value = (char*)malloc(strlen(session->method) + strlen(uri) + 2)) == NULL) {
        return false;
    }
    sprintf(value, "%s:%s", session->method, uri);
    md5_hash(value, strlen(value), A2);
    free(value);

    /* Calculate response */
    if ((value = (char*)malloc(strlen(A1) + strlen(nonce) + strlen(A2) + 6)) == NULL) {
        return false;
    }
    sprintf(value, "%s:%s:%s", A1, nonce, A2);
    md5_hash(value, strlen(value), result);
    free(value);

    /* Password match? */
    if (strcmp(result, response) != 0) {
        register_wrong_password(session);
        return false;
    }

    return (session->remote_user = strdup(username)) != NULL;
}

/**
    Check if the file is protected by an .htaccess file with passwordfile setting.
*/
bool http_authentication_oke(t_session *session, bool on_pwdfile_missing) {
    char *auth_str;
    bool result = false;

    if (session->host->passwordfile == NULL) {
        return on_pwdfile_missing;
    } else if ((auth_str = get_headerfield("Authorization:", session->headerfields)) != NULL) {
        auth_str = strdup(auth_str);
        if ((strncmp(auth_str, "Basic ", 6) == 0) && (session->host->auth_method == basic)) {
            session->http_auth = basic;
            result = basic_http_authentication(session, auth_str + 6);
        } else if ((strncmp(auth_str, "Digest ", 7) == 0) && (session->host->auth_method == digest)) {
            session->http_auth = digest;
            result = digest_http_authentication(session, auth_str + 7);
        }
        free(auth_str);
    }

    return result;
}
