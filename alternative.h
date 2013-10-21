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

#ifndef _ALTERNATIVE_H
#define _ALTERNATIVE_H
#ifndef HAVE_SETENV
int setenv(const char *key, const char *value, int overwrite);
#endif
#ifndef HAVE_UNSETENV
int unsetenv(char *key);
#endif
#ifndef HAVE_CLEARENV
void clearenv(void);
#endif
#ifndef HAVE_STRCASECMP
int strcasecmp(char *str1, char *str2);
#endif
#ifndef HAVE_STRNCASECMP
int strncasecmp(char *str1, char *str2, int len);
#endif
#ifndef HAVE_STRCASESTR
char *strcasestr(char *haystack, char *needle);
#endif

#endif
