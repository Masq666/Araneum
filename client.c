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
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/wait.h>
#include "global.h"
#include "client.h"
#include "log.h"

#define MAX_PASSWORD_DELAY_TIMER (int)(MINUTE / TASK_RUNNER_INTERVAL)

typedef struct type_client {
    t_session *session;
    time_t remove_deadline;

    struct type_client *next;
} t_client;

typedef struct type_banned {
    t_ip_addr ip;
    time_t    deadline;
    int       bantime;
    unsigned long connect_attempts;

    struct type_banned *next;
} t_banned;

static t_client *client_list[256];
static pthread_mutex_t client_mutex[256];
static t_banned *banlist;
static pthread_mutex_t ban_mutex;
static t_ipcounterlist *wrong_password_list;
static pthread_mutex_t pwd_mutex;
static int password_delay_timer = 0;

/**
    Initialize this module.
*/
void init_client_module(void) {
    unsigned int i;

    for (i = 0; i < 256; i++) {
        client_list[i] = NULL;
        pthread_mutex_init(&client_mutex[i], NULL);
    }
    banlist = NULL;
    pthread_mutex_init(&ban_mutex, NULL);
    wrong_password_list = NULL;
    pthread_mutex_init(&pwd_mutex, NULL);
}

/**
    Add the session record of a client to the client_list.
*/
int add_client(t_session *session) {
    t_client *new;
    unsigned char i;

    if ((new = (t_client*)malloc(sizeof(t_client))) != NULL) {
        new->session = session;
        new->remove_deadline = TIMER_OFF;

        i = index_by_ip(&(session->ip_address));
        pthread_mutex_lock(&client_mutex[i]);

        new->next = client_list[i];
        client_list[i] = new;

        pthread_mutex_unlock(&client_mutex[i]);

        return 0;
    } else {
        return -1;
    }
}

/**
    Change position in client list
*/
int reposition_client(t_session *session, t_ip_addr *ip_address) {
    t_client *to_be_repositioned = NULL, *list;
    unsigned char old_i, new_i;

    new_i = index_by_ip(ip_address);
    old_i = index_by_ip(&(session->ip_address));

    if (old_i == new_i) {
        return 0;
    }

    pthread_mutex_lock(&client_mutex[old_i]);

    if (client_list[old_i] != NULL) {
        if (client_list[old_i]->session == session) {
            to_be_repositioned = client_list[old_i];
            client_list[old_i] = client_list[old_i]->next;
        } else {
            list = client_list[old_i];
            while (list->next != NULL) {
                if (list->next->session == session) {
                    to_be_repositioned = list->next;
                    list->next = to_be_repositioned->next;
                    break;
                }
                list = list->next;
            }
        }
    } else {
        log_error(session, "Client record not found.");
    }

    pthread_mutex_unlock(&client_mutex[old_i]);

    if (to_be_repositioned == NULL) {
        return -1;
    }

    pthread_mutex_lock(&client_mutex[new_i]);

    to_be_repositioned->next = client_list[new_i];
    client_list[new_i] = to_be_repositioned;

    pthread_mutex_unlock(&client_mutex[new_i]);

    return 1;
}

/**
    Remember the client record for flooding prevention
*/
int mark_client_for_removal(t_session *session, int delay) {
    t_client *list;
    unsigned char i;
    int result = 0;

    i = index_by_ip(&(session->ip_address));
    pthread_mutex_lock(&client_mutex[i]);

    list = client_list[i];
    while (list != NULL) {
        if (list->session == session) {
            list->remove_deadline = time(NULL) + delay;
            result = 1;
            break;
        }
        list = list->next;
    }

    pthread_mutex_unlock(&client_mutex[i]);

    return result;
}

/**
    Check the remove_deadline timers and remove client when timer has reached 0
*/
void check_remove_deadlines(t_config *config, time_t now) {
    if (config->reconnect_delay <= 0) {
        return;
    }

    t_client *client, *prev, *next;
    unsigned int i;

    for (i = 0; i < 256; i++) {
        pthread_mutex_lock(&client_mutex[i]);

        prev = NULL;
        client = client_list[i];
        while (client != NULL) {
            next = client->next;
            if (client->remove_deadline == TIMER_OFF) {
                prev = client;
            } else if (now > client->remove_deadline) {
                free(client->session);
                free(client);
                if (prev == NULL) {
                    client_list[i] = next;
                } else {
                    prev->next = next;
                }
            } else {
                prev = client;
            }
            client = next;
        }

        pthread_mutex_unlock(&client_mutex[i]);
    }
}

/**
    Remove a client from the client_list.
*/
int remove_client(t_session *session, bool free_session) {
    t_client *to_be_removed = NULL, *list;

    unsigned char i = index_by_ip(&(session->ip_address));
    pthread_mutex_lock(&client_mutex[i]);

    if (client_list[i] != NULL) {
        if (client_list[i]->session == session) {
            to_be_removed = client_list[i];
            client_list[i] = client_list[i]->next;
        } else {
            list = client_list[i];
            while (list->next != NULL) {
                if (list->next->session == session) {
                    to_be_removed = list->next;
                    list->next = to_be_removed->next;
                    break;
                }
                list = list->next;
            }
        }
    } else {
        log_error(session, "Client record not found.");
    }

    pthread_mutex_unlock(&client_mutex[i]);

    if (to_be_removed == NULL) {
        return -1;
    }

    if (free_session) {
        close_socket(to_be_removed->session);
        free(to_be_removed->session);
    }
    free(to_be_removed);

    return 0;
}

/**
    Check whether to allow or deny a new connection.
*/
int connection_allowed(t_ip_addr *ip, int maxperip, int maxtotal) {
    time_t now = time(NULL);

    /* Check bans */
    pthread_mutex_lock(&ban_mutex);

    t_banned *ban = banlist;
    while (ban != NULL) {
        if (same_ip(&(ban->ip), ip)) {
            /* Ban expired? */
            if (now >= ban->deadline) {
                break;
            }

            ban->connect_attempts++;
            pthread_mutex_unlock(&ban_mutex);
            return ca_BANNED;
        }
        ban = ban->next;
    }

    pthread_mutex_unlock(&ban_mutex);

    /* Check max connections */
    int perip = 1, total = 1, i;
    t_client *client;
    for (i = 0; i < 256; i++) {
        pthread_mutex_lock(&client_mutex[i]);

        client = client_list[i];
        while (client != NULL) {
            if (same_ip(&(client->session->ip_address), ip)) {
                if ((client->remove_deadline == TIMER_OFF) || (now < client->remove_deadline)) {
                    perip++;
                }
            }
            if (client->remove_deadline == TIMER_OFF) {
                total++;
            }
            client = client->next;
        }

        pthread_mutex_unlock(&client_mutex[i]);
    }

    if (perip > maxperip) {
        return ca_TOOMUCH_PERIP;
    } else if (total > maxtotal) {
        return ca_TOOMUCH_TOTAL;
    } else {
        return total;
    }
}

/**
    Disconnect all connected clients.
*/
int disconnect_clients(t_config *config) {
    t_client *client;
    int max_wait = 10, i, kicked = 0;

    for (i = 0; i < 256; i++) {
        pthread_mutex_lock(&client_mutex[i]);

        client = client_list[i];
        while (client != NULL) {
            client->session->force_quit = true;
            client = client->next;
            kicked++;
        }

        pthread_mutex_unlock(&client_mutex[i]);
    }

    for (i = 0; i < 256; i++) {
        while ((client_list[i] != NULL) && (max_wait-- > 0)) {
            usleep(100000);
        }
    }

    t_directory *dir = config->directory;
    while (dir != NULL) {
        dir->nr_of_clients = 0;
        dir = dir->next;
    }

    return kicked;
}

/**
    Kick an IP address.
*/
int kick_ip(t_ip_addr *ip) {
    int result = 0;

    unsigned char i = index_by_ip(ip);
    pthread_mutex_lock(&client_mutex[i]);

    t_client *client = client_list[i];
    while (client != NULL) {
        if (same_ip(&(client->session->ip_address), ip)) {
            client->session->force_quit = true;
            result++;
        }
        client = client->next;
    }

    pthread_mutex_unlock(&client_mutex[i]);

    return result;
}

/**
    Check if the client is flooding the server with requests
*/
bool client_is_flooding(t_session *session) {
    time_t time_passed = session->time - session->flooding_timer + 1;
    return ((session->kept_alive * session->config->flooding_time) > (session->config->flooding_count * time_passed));
}

/**
    Disconnect a client.
*/
int kick_client(int id) {
    t_client *client;
    unsigned int i, result = 0;

    for (i = 0; i < 256; i++) {
        pthread_mutex_lock(&client_mutex[i]);

        client = client_list[i];
        while (client != NULL) {
            if (client->session->client_id == id) {
                client->session->force_quit = true;
                result = 1;
                break;
            }
            client = client->next;
        }

        pthread_mutex_unlock(&client_mutex[i]);
    }

    return result;
}

/**
    IP ban functions
*/
int ban_ip(t_ip_addr *ip, int timer, bool kick_on_ban) {
    bool new_ip = true;

    pthread_mutex_lock(&ban_mutex);

    t_banned *ban = banlist;
    while (ban != NULL) {
        if (same_ip(&(ban->ip), ip)) {
            ban->bantime = timer;
            if (timer == TIMER_OFF) {
                ban->deadline = TIMER_OFF;
            } else {
                ban->deadline = time(NULL) + ban->bantime;
            }
            new_ip = false;
            break;
        }
        ban = ban->next;
    }

    int retval = 0;
    if (new_ip) {
        if ((ban = (t_banned*)malloc(sizeof(t_banned))) != NULL) {
            copy_ip(&(ban->ip), ip);
            ban->bantime = timer;
            if (timer == TIMER_OFF) {
                ban->deadline = TIMER_OFF;
            } else {
                ban->deadline = time(NULL) + ban->bantime;
            }
            ban->connect_attempts = 0;
            ban->next = banlist;
            banlist = ban;
            retval = 1;
        } else {
            retval = -1;
        }
    }

    pthread_mutex_unlock(&ban_mutex);

    if (kick_on_ban && new_ip) {
        retval = kick_ip(ip);
    }

    return retval;
}

/**
    Reset the timer of a banned IP address.
*/
void reban_ip(t_ip_addr *ip) {
    pthread_mutex_lock(&ban_mutex);

    t_banned *ban = banlist;
    while (ban != NULL) {
        if (same_ip(&(ban->ip), ip)) {
            if (ban->bantime != TIMER_OFF) {
                ban->deadline = time(NULL) + ban->bantime;
            }
            break;
        }
        ban = ban->next;
    }

    pthread_mutex_unlock(&ban_mutex);
}

/**
    Check the timers of the banlist.
*/
void check_ban_list(t_config *config, time_t now) {
    t_banned *ban, *prev = NULL, *next;

    pthread_mutex_lock(&ban_mutex);

    ban = banlist;
    while (ban != NULL) {
        next = ban->next;
        if (ban->deadline == TIMER_OFF) {
            /* Timer off */
            prev = ban;
        } else if (ban->deadline <= now) {
            /* Deadline reached */
            if (prev == NULL) {
                banlist = next;
            } else {
                prev->next = next;
            }
            log_unban(config->system_logfile, &(ban->ip), ban->connect_attempts);
            free(ban);
        } else {
            /* other */
            prev = ban;
        }
        ban = next;
    }

    pthread_mutex_unlock(&ban_mutex);
}

/**
    Unban an IP address.
*/
int unban_ip(t_ip_addr *ip) {
    t_ip_addr any;
    bool any_ip;
    t_banned *ban, *prev = NULL, *next;
    unsigned int result = 0;

    /* Unban all? */
    default_ipv4(&any);
    any_ip = same_ip(ip, &any);
#ifdef HAVE_IPV6
    if (any_ip == false) {
        default_ipv6(&any);
        any_ip = same_ip(ip, &any);
    }
#endif

    pthread_mutex_lock(&ban_mutex);

    ban = banlist;
    while (ban != NULL) {
        next = ban->next;
        if (same_ip(&(ban->ip), ip) || any_ip) {
            if (prev == NULL) {
                banlist = ban->next;
            } else {
                prev->next = ban->next;
            }
            free(ban);
            result++;

            if (any_ip == false) {
                break;
            }
        } else {
            prev = ban;
        }
        ban = next;
    }

    pthread_mutex_unlock(&ban_mutex);

    return result;
}

/**
    Remember a client that sent a wrong password for HTTP authentication
*/
int register_wrong_password(t_session *session) {
    if (session->config->ban_on_wrong_password == 0) {
        return 0;
    }

    pthread_mutex_lock(&pwd_mutex);

    t_ipcounterlist *item = wrong_password_list;
    while (item != NULL) {
        if (same_ip(&(item->ip), &(session->ip_address))) {
            if (++(item->count) >= session->config->max_wrong_passwords) {
                if (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny) {
                    ban_ip(&(session->ip_address), session->config->ban_on_wrong_password, session->config->kick_on_ban);
                    session->keep_alive = false;
                    log_system(session, "Client banned because of too many wrong passwords");
                }
            }

            pthread_mutex_unlock(&pwd_mutex);
            return 0;
        }
        item = item->next;
    }

    if ((item = (t_ipcounterlist*)malloc(sizeof(t_ipcounterlist))) == NULL) {
        pthread_mutex_unlock(&pwd_mutex);
        return -1;
    }

    copy_ip(&(item->ip), &(session->ip_address));
    item->count = 1;
    item->next = wrong_password_list;
    wrong_password_list = item;

    pthread_mutex_unlock(&pwd_mutex);

    return 0;
}

/**
    Remove all clients from the wrong-password list
*/
void remove_wrong_password_list(t_config *config) {
    if ((config->ban_on_wrong_password == 0) || (wrong_password_list == NULL)) {
        return;
    } else if (++password_delay_timer < MAX_PASSWORD_DELAY_TIMER) {
        return;
    }

    t_ipcounterlist *item, *remove;

    pthread_mutex_lock(&pwd_mutex);

    item = wrong_password_list;
    wrong_password_list = NULL;

    pthread_mutex_unlock(&pwd_mutex);

    while (item != NULL) {
        remove = item;
        item = item->next;
        free(remove);
    }

    password_delay_timer = 0;
}

/**
    Close all client sockets to run a CGI program
*/
void close_client_sockets_for_cgi_run(void) {
    t_client *client;
    unsigned int i;

    for (i = 0; i < 256; i++) {
        client = client_list[i];
        while (client != NULL) {
            close(client->session->client_socket);
            client = client->next;
        }
    }
}
