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
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_SETENV
int setenv(const char *key, const char *value, int overwrite) {
    if((key != NULL) && (value != NULL)) {
        if((getenv(key) == NULL) || (overwrite != 0)) {
            char *line;
            if((line = (char*)malloc(strlen(key) + strlen(value) + 2)) != NULL) {
                sprintf(line, "%s=%s", key, value);
                return putenv(line);
            } else {
                return -1;
            }
        }

        return 0;
    }

    return -1;
}
#endif

#ifndef HAVE_UNSETENV
int unsetenv(char *key) {
    if(key != NULL) {
        return putenv(key);
    }

    return -1;
}
#endif

#ifndef HAVE_CLEARENV
void clearenv(void) {
    extern char **environ;
    char *eq, key[256];
    int len;

    while(*environ != NULL) {
        if((eq = strchr(*environ, '=')) != NULL) {
            if((len = eq - *environ) < 256) {
                memcpy(key, *environ, (size_t)len);
                key[len] = '\0';
                unsetenv(key);
            }
        }
        environ++;
    }
}
#endif

#ifndef HAVE_STRCASECMP
int strcasecmp(char *str1, char *str2) {
    if((str1 != NULL) && (str2 != NULL)) {
        char c1, c2;
        while(*str1 != '\0') {
            if(*str1 != *str2) {
                c1 = *str1;
                if((c1 >= 'A') && (c1 <= 'Z')) {
                    c1 += 32;
                }
                c2 = *str2;
                if((c2 >= 'A') && (c2 <= 'Z')) {
                    c2 += 32;
                }
                if(c1 != c2) {
                    return -1;
                }
            }
            str1++;
            str2++;
        }

        if(*str2 == '\0') {
            return 0;
        }
    }

    return -1;
}
#endif

#ifndef HAVE_STRNCASECMP
int strncasecmp(char *str1, char *str2, int len) {
    if((str1 == NULL) || (str2 == NULL)) {
        return -1;
    }

    char c1, c2;

    while(len-- > 0) {
        if(*str1 != *str2) {
            c1 = *str1;
            if((c1 >= 'A') && (c1 <= 'Z')) {
                c1 += 32;
            }
            c2 = *str2;
            if((c2 >= 'A') && (c2 <= 'Z')) {
                c2 += 32;
            }
            if(c1 != c2) {
                return -1;
            }
        }
        if(*str1 == '\0') {
            break;
        }
        str1++;
        str2++;
    }

    return 0;
}
#endif

#ifndef HAVE_STRCASESTR
char *strcasestr(char *haystack, char *needle) {
    int i, len, steps;

    if((haystack != NULL) && (needle != NULL)) {
        len = strlen(needle);
        steps = strlen(haystack) - len + 1;
        for(i = 0; i < steps; i++) {
            if(strncasecmp(haystack + i, needle, len) == 0) {
                return haystack + i;
            }
        }
    }

    return NULL;
}
#endif
