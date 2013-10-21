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

#ifndef _CACHE_H
#define _CACHE_H

#include <stdbool.h>
#include "global.h"
#include "libip.h"

#define TIME_IN_CACHE     MINUTE
#define MAX_CACHE_TIMER     HOUR

typedef struct type_cached_object {
	char          *file;
	char          *data;
	off_t         size;
	time_t        deadline;
	time_t        last_changed;
	volatile int  in_use;
	t_ip_addr     last_ip;

	struct type_cached_object *prev;
	struct type_cached_object *next;
} t_cached_object;

void init_cache_module(void);
t_cached_object *add_to_cache(t_session *session, char *file);
t_cached_object *search_cache(t_session *session, char *file);
void done_with_cached_object(t_cached_object *object, bool remove_object);
void check_cache(time_t time);
int clear_cache(void);

#endif
