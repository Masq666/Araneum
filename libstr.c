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
#include <string.h>
#include <limits.h>
#include <regex.h>
#include "global.h"

#define MAX_VALUE (INT_MAX - 10) / 10

/**
    Convert a string to an integer.
*/
int str2int(const char *str) {
    int i = 0, value = 0;

    if (str == NULL) {
        return -1;
    } else if (*str == '\0') {
        return -1;
    } else while (*(str + i) != '\0') {
            if ((*(str + i) >= '0') && (*(str + i) <= '9')) {
                if (value >= MAX_VALUE) {
                    return -1;
                }
                value *= 10;
                value += (*(str + i) - '0');
                i++;
            } else {
                return -1;
            }
        }

    return value;
}

/**
    Remove the leading and trailing spaces in a string.
*/
char *remove_spaces(char *str) {
/*    int pos;*/

    if (str != NULL) {
        while ((*str == ' ') || (*str == '\t')) {
            str++;
        }
        int pos = strlen(str) - 1;
        while (pos >= 0) {
            switch (*(str + pos)) {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
                *(str + pos) = '\0';
                pos--;
                break;
            default:
                pos = -1;
            }
        }
    }

    return str;
}

/**
    Remove comment from a string.
*/
char *uncomment(char *str) {
    if (str == NULL) {
        return NULL;
    }

    if (*str == '#') {
        *str = '\0';
        return str;
    }

    char *hash;
    if ((hash = strstr(str, " #")) != NULL) {
        *hash = '\0';
    } else if ((hash = strstr(str, "\t#")) != NULL) {
        *hash = '\0';
    }

    return remove_spaces(str);
}

/**
    Covert a string to lowercase.
    Hmm, why not use the ANSI C tolower(int c) function?
    -philipe
*/
char *strlower(char *str) {
    if (str != NULL) {
        char *c = str;
        while (*c != '\0') {
            if ((*c >= 'A') && (*c <= 'Z')) {
                *c += 32;
            }
            c++;
        }
    }

    return str;
}

/**
    Convert a hexadecimal char to an integer.
*/
short hex_to_int(char c) {
    if ((c >= '0') && (c <= '9')) {
        return c - '0';
    } else if ((c >= 'A') && (c <= 'F')) {
        return c - 'A' + 10;
    } else if ((c >= 'a') && (c <= 'f')) {
        return c - 'a' + 10;
    }

    return -1;
}

/**
    Split a string in 2 strings.
*/
int split_string(const char *str, char **key, char **value, char c) {
    if ((str == NULL) || (key == NULL) || (value == NULL)) {
        return -1;
    }

    *key = (char*)str;
    if ((*value = strchr(*key, c)) != NULL) {
        *(*value)++ = '\0';
        *key = remove_spaces(*key);
        *value = remove_spaces(*value);

        return 0;
    }

    return -1;
}

int split_configline(const char *str, char **key, char **value) {
    if ((str == NULL) || (key == NULL) || (value == NULL)) {
        return -1;
    }

    *key = remove_spaces((char*)str);
    *value = *key;
    int eq = 0;

    while (**value != '\0') {
        if ((**value == ' ') || (**value == '=')) {
            if (**value == '=') eq++;
            **value = '\0';
            do {
                (*value)++;
                if (**value == '=') eq++;
            } while ((**value == ' ') || (**value == '='));

            if (eq > 1) return -1;
            return 0;
        }
        (*value)++;
    }

    value = NULL;

    return -1;
}

/**
    Check the validity of an URL.
*/
bool valid_uri(char *uri) {
    if (uri == NULL) {
        return false;
    } else if (*uri != '/') {
        return false;
    }

#ifdef CYGWIN
    // Deny trailing dots and spaces
    size_t last_pos = strlen(uri) - 1;
    if (*(uri + last_pos) == '.') {
        return false;
    } else if (*(uri + last_pos) == ' ') {
        return false;
    }

    // Deny 8.3 file format
    if (last_pos >= 6) {
        if ((*(uri + last_pos - 5) == '~') && (*(uri + last_pos - 4) >= '0') &&
                (*(uri + last_pos - 4) <= '9') && (*(uri + last_pos - 3) == '.')) {
            return false;
        }
    }

    if (strstr(uri, "\\.") != NULL) {
        return false;
    }
#endif

    if (strstr(uri, "/.") != NULL) {
        return false;
    }

    while (*(++uri) != '\0') {
        if ((unsigned char)*uri < 32) {
            return false;
        }
    }

    return true;
}

/**
    Encode a string to an URL encoded one
*/
static bool char_needs_encoding(char c) {
    return (c <= 32) || (strchr("\"#\%&'+:<>", c) != NULL) || (c >= 126);
}

int url_encode(char *str, char **encoded) {
    char *c, *e;
    int replace = 0;

    c = str;
    while (*c != '\0') {
        if (char_needs_encoding(*c)) {
            replace++;
        }
        c++;
    }

    if (replace == 0) {
        *encoded = NULL;
        return 0;
    } else if ((*encoded = (char*)malloc(strlen(str) + (2 * replace) + 1)) == NULL) {
        return -1;
    }

    c = str;
    e = *encoded;
    while (*c != '\0') {
//		if (*c == ' ') {
//			*e = '+';
//		} else
        if (char_needs_encoding(*c)) {
            sprintf(e, "%%%02hhx", *c);
            e += 2;
        } else {
            *e = *c;
        }
        c++;
        e++;
    }
    *e = '\0';

    return replace;
}

/**
    Decode the URL encoded characters (%XX).
*/
void url_decode(char *str) {
    if (str == NULL) {
        return;
    }

    short low, high;
    char *dest = str;

    while (*str != '\0') {
        if (*str == '+') {
            *str = ' ';
        } else if (*str == '%') {
            if ((high = hex_to_int(*(str + 1))) != -1) {
                if ((low = hex_to_int(*(str + 2))) != -1) {
                    str += 2;
                    *str = (char)(high<<4) + low;
                }
            }
        }
        *(dest++) = *(str++);
    }

    *dest = '\0';
}

/**
    Scan for characters with ASCII value < 32.
*/
bool forbidden_chars_present(char *str) {
    if (str == NULL) {
        return false;
    }

    short low, high;

    while (*str != '\0') {
        if ((*str > 0) && (*str < 32)) {
            return true;
        } else if (*str == '%') {
            if ((high = hex_to_int(*(str + 1))) != -1) {
                if ((low = hex_to_int(*(str + 2))) != -1) {
                    if (((high << 4) + low) < 32) {
                        return true;
                    }
                }
            }
        }
        str++;
    }

    return false;
}

/**
    Return an errormessage.

    @param unsigned int HTTP error code.
    @return const char Returns the textual equivalent of the error code.
*/
const char *http_error(unsigned int code) {
    switch(code){
        /* Success 2xx */
        case 200: return "OK"; break;
        case 201: return "Created"; break;
        case 204: return "No Content"; break;
        case 206: return "Partial Content"; break;
        /* Redirection 3xx */
        case 301: return "Moved Permanently"; break;
        case 302: return "Found"; break;
        case 304: return "Not Modified"; break;
        /* Client Error 4xx */
        case 400: return "Bad Request"; break;
        case 401: return "Unauthorized"; break;
        case 403: return "Forbidden"; break;
        case 404: return "Not Found"; break;
        case 405: return "Method Not Allowed"; break;
        case 408: return "Request Timeout"; break;
        case 411: return "Length Required"; break;
        case 412: return "Precondition Failed"; break;
        case 413: return "Request Entity Too Large"; break;
        case 416: return "Requested Range Not Satisfiable"; break;
        /* Server Error 5xx */
        case 500: return "Internal Server Error"; break;
        case 501: return "Not Implemented"; break;
        case 503: return "Service Unavailable"; break;
        case 505: return "HTTP Version Not Supported"; break;

        default:
            return "Unknown Error";
    }
}

/**
    Decode an base64 encoded string.
*/
bool decode_base64(char *base64) {
    if (base64 == NULL) {
        return false;
    }

    bool retval = true, found;
    const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int l, i, t, byte = 0, bit = 0;

    l = strlen(base64);
    for (i = 0; i < l; i++) {
        if (*(base64 + i) != '=') {
            found = false;
            for (t = 0; t < 64; t++) {
                if (*(base64 + i) == *(table + t)) {
                    switch (bit) {
                    case 0:
                        *(base64 + byte) = (t << 2);
                        break;
                    case 2:
                        *(base64 + byte) = (*(base64 + byte) & 192) | t;
                        break;
                    case 4:
                        *(base64 + byte) = (*(base64 + byte) & 240) | (t >> 2);
                        *(base64 + byte + 1) = (t << 6);
                        break;
                    case 6:
                        *(base64 + byte) = (*(base64 + byte) & 252) | (t >> 4);
                        *(base64 + byte + 1) = (t << 4);
                        break;
                    }
                    bit += 6;
                    if (bit >= 8) {
                        bit -= 8;
                        byte++;
                    }
                    found = true;
                    break;
                }
            }
            if (found == false) {
                retval = false;
                break;
            }
        } else {
            break;
        }
    }

    if (bit <= 2) {
        *(base64 + byte) = '\0';
    } else {
        *(base64 + byte + 1) = '\0';
    }

    return retval;
}

int str_replace(char *src, char *from, char *to, char **dst) {
    if ((src == NULL) || (from == NULL) || (to == NULL) || (dst == NULL)) {
        return 0;
    }

    char *pos, *start;
    int replaced = 0, len_from, len_to, len_start;

    if ((len_from = strlen(from)) == 0) {
        return -1;
    }
    len_to = strlen(to);

    start = src;
    while ((pos = strstr(start, from)) != NULL) {
        if ((*dst = (char*)malloc(strlen(src) - len_from + len_to + 1)) == NULL) {
            if (replaced > 0) {
                free(src);
            }
            return -1;
        }
        len_start = pos - src;
        memcpy(*dst, src, len_start);
        if (len_to > 0) {
            memcpy(*dst + len_start, to, len_to);
        }
        strcpy(*dst + len_start + len_to, pos + len_from);

        if (replaced > 0) {
            free(src);
        }
        if (replaced++ == 100) {
            if (*dst != NULL) {
                free(*dst);
            }
            return -1;
        }
        src = *dst;
        start = src + len_start + len_to;
    }

    return replaced;
}

bool min_strlen(char *str, int n) {
    if (str != NULL) {
        int i = 0;
        while (i < n) {
            if (*(str + i) == '\0') {
                return false;
            }
            i++;
        }
    }

    return true;
}

int header_to_variable(char *header, char *variable, int size) {
    char *column;
    int len, i;

    if ((column = strchr(header, ':')) == NULL) {
        return -1;
    }
    len = column - header;
    if (len + 6 > size) {
        return -1;
    }

    strcpy(variable, "HTTP_");

    for (i = 0; i < len; i++) {
        if (((header[i] >= 'A') && (header[i] <= 'Z')) || ((header[i] >= '0') && (header[i] <= '9'))) {
            variable[i + 5] = header[i];
        } else if ((header[i] >= 'a') && (header[i] <= 'z')) {
            variable[i + 5] = header[i] - 32;
        } else if (header[i] == '-') {
            variable[i + 5] = '_';
        } else {
            return -1;
        }
    }
    variable[len + 5] = '\0';

    return 0;
}

/**
    Converts a filesize to a string.
*/
int filesize2str(char *buffer, int len, off_t fsize) {
    int result = 0;

    buffer[len - 1] = '\0';
    if (fsize < KILOBYTE) {
        result = snprintf(buffer, len - 1, "%llu byte", (long long)fsize);
    } else if (fsize < MEGABYTE) {
        result = snprintf(buffer, len - 1, "%0.1f kB", ((double)(fsize >> 6)) / 16);
    } else if (fsize < GIGABYTE) {
        result = snprintf(buffer, len - 1, "%0.1f MB", ((double)(fsize >> 16)) / 16);
    } else {
        result = snprintf(buffer, len - 1, "%0.1f GB", ((double)(fsize >> 26)) / 16);
    }

    return (result < 0) ? 0 : result;
}


int add_str(char **buffer, int *size, int extra_size, int *len, char *str) {
    char *new;
    size_t str_len = strlen(str);

    while (*len + str_len >= *size) {
        *size += extra_size;
        if ((new = (char*)realloc(*buffer, *size)) == NULL) {
            *size -= extra_size;
            return -1;
        }
        *buffer = new;
    }

    memcpy(*buffer + *len, str, str_len);
    *len += str_len;
    *(*buffer + *len) = '\0';

    return 0;
}

int strpcmp(char *str, regex_t *regexp) {
    return (regexec(regexp, str, 0, NULL, 0) == 0) ? 0 : -1;
}
