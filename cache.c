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

#ifdef HAVE_CACHE

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include "libfs.h"
#include "libip.h"
#include "session.h"
#include "cache.h"

#define MAX_CACHE_INDEX 27 * 27

static t_cached_object *cache[MAX_CACHE_INDEX];
static pthread_mutex_t cache_mutex[MAX_CACHE_INDEX];
static pthread_mutex_t cachesize_mutex;
static volatile off_t cachesize;

void init_cache_module(void) {
    int i;

    for(i = 0; i < MAX_CACHE_INDEX; i++) {
        cache[i] = NULL;
        pthread_mutex_init(&cache_mutex[i], NULL);
    }

    pthread_mutex_init(&cachesize_mutex, NULL);
    cachesize = 0;
}

static int cache_index(char *filename) {
    if(filename == NULL) {
        return -1;
    }

    char *c, c1, c2;

    c = filename + strlen(filename);

    while((*c != '/') && (c > filename)) {
        c--;
    }

    if(*c == '/') {
        c++;
    }

    if(*c == '\0') {
        return -1;
    } else {
        c1 = *c;

        if((c1 >= 'A') && (c1 <= 'Z')) {
            c1 -= ('A' - 1);
        } else if((c1 >= 'a') && (c1 <= 'z')) {
            c1 -= ('a' - 1);
        } else {
            c1 = 0;
        }
    }

    if(*(c + 1) == '\0') {
        c2 = 0;
    } else {
        c2 = *(c + 1);

        if((c2 >= 'A') && (c2 <= 'Z')) {
            c2 -= ('A' - 1);
        } else if((c2 >= 'a') && (c2 <= 'z')) {
            c2 -= ('a' - 1);
        } else {
            c2 = 0;
        }
    }

    return (c1 * 27) + c2;
}

static t_cached_object *remove_from_cache(t_cached_object *object, int index) {
    t_cached_object *next;

    if(object->prev != NULL) {
        object->prev->next = object->next;
    }

    if((next = object->next) != NULL) {
        object->next->prev = object->prev;
    }

    pthread_mutex_lock(&cachesize_mutex);
    cachesize -= object->size;
    pthread_mutex_unlock(&cachesize_mutex);

    if(object == cache[index]) {
        cache[index] = object->next;
    }

    free(object->data);
    free(object->file);
    free(object);

    return next;
}

t_cached_object *add_to_cache(t_session *session, char *file) {
    t_cached_object *object;
    struct stat status;
    off_t size;
    int fd, i;
    size_t bytes_read, bytes_total = 0;

    if(file == NULL) {
        return NULL;
    } else if (stat(file, &status) == -1) {
        return NULL;
    } else if((size = status.st_size) == -1) {
        return NULL;
    } else if((size < session->config->cache_min_filesize) || (size > session->config->cache_max_filesize)) {
        return NULL;
    } else if(cachesize + size > session->config->cache_size) {
        return NULL;
    } else if((object = (t_cached_object*)malloc(sizeof(t_cached_object))) == NULL) {
        return NULL;
    } else if((object->file = strdup(file)) == NULL) {
        free(object);
        return NULL;
    } else if((object->data = (char*)malloc(size)) == NULL) {
        free(object->file);
        free(object);
        return NULL;
    }

    if((fd = open(file, O_RDONLY)) != -1) {
        while(bytes_total < size) {
            if((bytes_read = read(fd, object->data + bytes_total, size - bytes_total)) == -1) {
                if(errno != EINTR) {
                    free(object->data);
                    free(object->file);
                    free(object);
                    close(fd);
                    return NULL;
                }
            } else {
                bytes_total += bytes_read;
            }
        }
        close(fd);
    } else {
        free(object->data);
        free(object->file);
        free(object);
        return NULL;
    }

    object->last_changed = status.st_mtime;
    object->deadline = session->time + TIME_IN_CACHE;
    object->size = size;
    object->in_use = 1;
    copy_ip(&(object->last_ip), &(session->ip_address));

    if((i = cache_index(file)) == -1) {
        free(object->data);
        free(object->file);
        free(object);
        return NULL;
    }

    pthread_mutex_lock(&cache_mutex[i]);

    object->prev = NULL;
    object->next = cache[i];

    if(cache[i] != NULL) {
        cache[i]->prev = object;
    }

    cache[i] = object;
    pthread_mutex_lock(&cachesize_mutex);
    cachesize += object->size;
    pthread_mutex_unlock(&cachesize_mutex);
    pthread_mutex_unlock(&cache_mutex[i]);

    return object;
}

t_cached_object *search_cache(t_session *session, char *file) {
    off_t size;

    if(file == NULL) {
        return NULL;
    } else if((size = filesize(file)) == -1) {
        return NULL;
    }

    int i;

    if((i = cache_index(file)) == -1) {
        return NULL;
    }

    pthread_mutex_lock(&cache_mutex[i]);

    t_cached_object *object = cache[i], *result = NULL;
    struct stat status;
    /*object = cache[i];*/

    while(object != NULL) {
        if(object->size == size) {
            if (strcmp(object->file, file) == 0) {
                if(stat(file, &status) == 0) {
                    if((object->deadline > session->time) && (status.st_mtime == object->last_changed)) {
                        if(same_ip(&(object->last_ip), &(session->ip_address)) == false) {
                            if((object->deadline += TIME_IN_CACHE) > (session->time + MAX_CACHE_TIMER)) {
                                object->deadline = session->time + MAX_CACHE_TIMER;
                            }
                            copy_ip(&(object->last_ip), &(session->ip_address));
                        }
                        object->in_use++;
                        result = object;
                    } else if(object->in_use <= 0) {
                        remove_from_cache(object, i);
                    }
                } else if(object->in_use <= 0) {
                    remove_from_cache(object, i);
                }
                break;
            }
        }
        object = object->next;
    }

    pthread_mutex_unlock(&cache_mutex[i]);

    return result;
}

void done_with_cached_object(t_cached_object *object, bool remove_object) {
    if(remove_object) {
        object->deadline = 0;
    }
    object->in_use--;
}

void check_cache(time_t now) {
    t_cached_object *object;
    int i;

    for(i = 0; i < MAX_CACHE_INDEX; i++) {
        pthread_mutex_lock(&cache_mutex[i]);
        object = cache[i];

        while(object != NULL) {
            if(now > object->deadline) {
                if(object->in_use <= 0) {
                    object = remove_from_cache(object, i);
                    continue;
                } else {
                    object->deadline = 0;
                }
            }
            object = object->next;
        }

        pthread_mutex_unlock(&cache_mutex[i]);
    }
}

int clear_cache(void) {
    t_cached_object *object, *list;
    unsigned int i, removed = 0;

    for(i = 0; i < MAX_CACHE_INDEX; i++) {
        pthread_mutex_lock(&cache_mutex[i]);
        list = cache[i];
        cache[i] = NULL;

        while (list != NULL) {
            object = list;
            list = list->next;

            if(object->in_use == 0) {
                /* Object unused, so remove */
                pthread_mutex_lock(&cachesize_mutex);
                cachesize -= object->size;
                pthread_mutex_unlock(&cachesize_mutex);

                free(object->data);
                free(object->file);
                free(object);
                removed++;
            } else {
                /* Object in use, put back in list */
                object->next = cache[i];
                cache[i] = object;
            }
        }

        pthread_mutex_unlock(&cache_mutex[i]);
    }

    return removed;
}

#endif
