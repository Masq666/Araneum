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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <grp.h>
#include <time.h>
#include <sys/wait.h>
#include "alternative.h"
#include "libstr.h"
#include "liblist.h"
#include "userconfig.h"

#define MAX_CONFIG_LINE KILOBYTE
#define DELIMITER ';'
#define TIMESTAMP_SIZE 40

typedef struct type_php_cgi {
	char     *executable;
	char     *chroot;
	char     *binding;
	uid_t    uid;
	gid_t    gid;
	char     *config_file;
	t_groups groups;
	pid_t    pid;

	struct type_php_cgi *next;
} t_php_cgi;

typedef struct {
	char       *pidfile;
	char       *children;
	char       *max_requests;
	t_php_cgi  *php_cgi;
	t_keyvalue *envir;
} t_config;

bool quiet = false;

/**
    Log a message
*/
void log_string(char *mesg, ...) {
	va_list args;
	FILE *fp;
	time_t t;
	struct tm *s;

	va_start(args, mesg);

	if (quiet == false) {
		vfprintf(stderr, mesg, args);
		fprintf(stderr, "\n");
	}

	char timestamp[TIMESTAMP_SIZE];
	if ((fp = fopen(LOG_DIR"/php-fcgi.log", "a")) != NULL) {
		time(&t);
		s = localtime(&t);
		timestamp[TIMESTAMP_SIZE - 1] = '\0';
		strftime(timestamp, TIMESTAMP_SIZE - 1, "%a %d %b %Y %T %z", s);

		fprintf(fp, "%s|", timestamp);
		vfprintf(fp, mesg, args);
		fprintf(fp, "\n");

		fclose(fp);
	}

	va_end(args);
}

/**
    Start php-cgi as a FastCGI daemon
*/
int run_php_cgi(t_php_cgi *php_cgi) {
	FILE *fp;

	if ((fp = fopen(php_cgi->executable, "r")) == NULL) {
		log_string("PHP binary %s not found", php_cgi->executable);
		return -1;
	}
	fclose(fp);

	pid_t pid;
	switch (pid = fork()) {
		case -1:
			log_string("fork error");
			return -1;
		case 0:
			if (setsid() == -1) {
				exit(EXIT_FAILURE);
			}
			break;
		default:
			return pid;
	}

	if (php_cgi->chroot != NULL) {
		if (chdir(php_cgi->chroot) == -1) {
			exit(EXIT_FAILURE);
		} else if (chroot(php_cgi->chroot) == -1) {
			exit(EXIT_FAILURE);
		}
	}

	do {
		if (setgroups(php_cgi->groups.number, php_cgi->groups.array) != -1) {
			if (setgid(php_cgi->gid) != -1) {
				if (setuid(php_cgi->uid) != -1) {
					break;
				}
			}
		}
		log_string("error while changing uid/gid");
		exit(EXIT_FAILURE);
	} while (false);

	if (close(STDIN_FILENO) == -1) {
		log_string("error closing stdin");
	} else if (open("/dev/null", O_RDONLY) == -1) {
		log_string("error redirecting stdin");
		exit(EXIT_FAILURE);
	}
	if (close(STDOUT_FILENO) == -1) {
		log_string("error closing stdout");
	} else if (open("/dev/null", O_WRONLY) == -1) {
		log_string("error redirecting stdout");
		exit(EXIT_FAILURE);
	}
	if (close(STDERR_FILENO) == -1) {
		log_string("error closing stderr");
	} else if (open("/dev/null", O_WRONLY) == -1) {
		quiet = true;
		log_string("error redirecting stderr");
		exit(EXIT_FAILURE);
	}

	if (php_cgi->config_file == NULL) {
		execlp(php_cgi->executable, php_cgi->executable, "-b", php_cgi->binding, (char*)NULL);
	} else {
		execlp(php_cgi->executable, php_cgi->executable, "-b", php_cgi->binding, "-c", php_cgi->config_file, (char*)NULL);
	}

	quiet = true;
	log_string("error while executing %s", php_cgi->executable);

	exit(EXIT_FAILURE);
}

/**
    Parse a configuration line
*/
int parse_line(t_config *config, char *line) {
	char *key, *value, *item, *group, *pipe;
	t_php_cgi *new;

	if (split_configline(line, &key, &value) != -1) {
		strlower(key);
		if (strcmp(key, "pidfile") == 0) {
			free(config->pidfile);
			if ((config->pidfile = strdup(value)) == NULL) {
				return -1;
			}
		} else if (strcmp(key, "forks") == 0) {
			free(config->children);
			if (str2int(value) < 1) {
				return -1;
			}
			if ((config->children = strdup(value)) == NULL) {
				return -1;
			}
		} else if (strcmp(key, "maxrequests") == 0) {
			free(config->max_requests);
			if (str2int(value) < 1) {
				return -1;
			}
			if ((config->max_requests = strdup(value)) == NULL) {
				return -1;
			}
		} else if (strcmp(key, "setenv") == 0) {
			if (parse_keyvaluelist(value, &(config->envir), "=") == -1) {
				return -1;
			}
		} else if (strcmp(key, "server") == 0) {
			if ((new = (t_php_cgi*)malloc(sizeof(t_php_cgi))) == NULL) {
				return -1;
			}

			/* PHP executable */
			if (split_string(value, &item, &value, DELIMITER) == -1) {
				return -1;
			}
			if ((pipe = strchr(item, '|')) != NULL) {
				*pipe = '\0';
				if ((new->chroot = strdup(item)) == NULL) {
					return -1;
				}
				*pipe = '/';
				item = pipe;
			} else {
				new->chroot = NULL;
			}
			if ((new->executable = strdup(item)) == NULL) {
				return -1;
			}

			/* Binding */
			if (split_string(value, &item, &value, DELIMITER) == -1) {
				return -1;
			}
			if ((new->binding = strdup(item)) == NULL) {
				return -1;
			}

			/* UID, GID's */
			split_string(value, &item, &value, DELIMITER);
			split_string(item, &item, &group, ':');
			if (parse_userid(item, &(new->uid)) != 1) {
				log_string("invalid user %s", item);
				return -1;
			}
			if (group != NULL) {
				if (parse_groups(group, &(new->gid), &(new->groups)) != 1) {
					log_string("invalid group %s", group);
					return -1;
				}
			} else {
				if (lookup_group_ids(new->uid, &(new->gid), &(new->groups)) != 1) {
					return -1;
				}
			}

			/* Configuration file */
			if (value != NULL) {
				if ((new->config_file = strdup(value)) == NULL) {
					return -1;
				}
			} else {
				new->config_file = NULL;
			}

			new->next = config->php_cgi;
			config->php_cgi = new;
		} else {
			return -1;
		}
	}

	return 0;
}

/**
    Read the configuration file
*/
t_config *read_config(char *config_file) {
	t_config *config;

	if ((config = (t_config*)malloc(sizeof(t_config))) == NULL) {
		return NULL;
	}

	FILE *fp;
	char line[MAX_CONFIG_LINE + 1], *data;
	int linenr = 0;

	/* Default settings */
	config->pidfile = strdup(PIDFILE_DIR"/php-fcgi.pid");
	config->children = strdup("3");
	config->max_requests = strdup("100");
	config->php_cgi = NULL;
	config->envir = NULL;

	if ((fp = fopen(config_file, "r")) == NULL) {
		perror(config_file);
		return NULL;
	}

	line[MAX_CONFIG_LINE] = '\0';
	while (fgets(line, MAX_CONFIG_LINE, fp) != NULL) {
		linenr++;
		data = uncomment(line);
		if (*data != '\0') {
			if (parse_line(config, data) == -1) {
				log_string("syntax error in %s on line %d", config_file, linenr);
				return NULL;
			}
		}
	}
	fclose(fp);

	return config;
}

/**
    Verify the configuration
*/
bool valid_config(t_config *config) {
	t_php_cgi *php_cgi;
	size_t len;

	php_cgi = config->php_cgi;
	while (php_cgi != NULL) {
		if ((len = strlen(php_cgi->executable)) >= 8) {
			if (strcmp(php_cgi->executable + len - 8, "php-fcgi") == 0) {
				log_string("%s is not a PHP binary", php_cgi->executable);
				return false;
			}
		}
		php_cgi = php_cgi->next;
	}

	return true;
}

/**
    Show help information
*/
void show_help(char *php_cgi) {
	printf("Usage: %s [options]\n", php_cgi);
	printf("Options: -c <configfile>: the configuration file to be used.\n");
	printf("         -h: show this information and exit.\n");
	printf("         -k: kill running FastCGI servers.\n");
	printf("         -q: don't print the results.\n");
	printf("         -v: show version and exit.\n");
}

/**
    Start FastCGI servers
*/
int start_fastcgi_servers(t_config *config) {
	FILE *fp;
	/*t_keyvalue *env;*/
	/*t_php_cgi *php_cgi;*/
	int started = 0, status;

	/* Start PHP FastCGI servers */
	if (config->php_cgi == NULL) {
		fputs("No servers have been defined.",stderr);
		return -1;
	}

	clearenv();
	setenv("PHP_FCGI_CHILDREN", config->children, 1);
	setenv("PHP_FCGI_MAX_REQUESTS", config->max_requests, 1);
	t_keyvalue *env = config->envir;

	while (env != NULL) {
		setenv(env->key, env->value, 1);
		env = env->next;
	}

	if ((fp = fopen(config->pidfile, "r")) != NULL) {
		fclose(fp);
		fputs("A PID file exists. Are FastCGI daemons already running?",stderr);
		return -1;
	}

	log_string("starting PHP FastCGI daemons");

	/* Start daemons */
	t_php_cgi *php_cgi = config->php_cgi;
	while (php_cgi != NULL) {
		if ((php_cgi->pid = run_php_cgi(php_cgi)) != -1) {
			started++;
		}
		php_cgi = php_cgi->next;
	}

	if (started == 0) {
		return -1;
	}

	/* Check return codes */
	sleep(1);
	php_cgi = config->php_cgi;
	while (php_cgi != NULL) {
		if (php_cgi->pid != -1) {
			if (waitpid(php_cgi->pid, &status, WNOHANG) > 0) {
				log_string("PHP FastCGI daemon exited with code %d", status);
				php_cgi->pid = -1;
			}
		}
		php_cgi = php_cgi->next;
	}

	/* Log PIDs */
	if ((fp = fopen(config->pidfile, "w")) != NULL) {
		php_cgi = config->php_cgi;
		while (php_cgi != NULL) {
			if (php_cgi->pid != -1) {
				fprintf(fp, "%d\n", php_cgi->pid);
			}
			php_cgi = php_cgi->next;
		}
		fclose(fp);
	} else {
		fprintf(stderr, "write ");
		perror(config->pidfile);

		return -1;
	}

	return 0;
}

/**
    Stop running FastCGI servers
*/
int stop_fastcgi_servers(t_config *config) {
	FILE *fp;

	if ((fp = fopen(config->pidfile, "r")) != NULL) {
		log_string("stopping PHP FastCGI daemons");

        char line[11];
        size_t len;
        pid_t pid;

		line[10] = '\0';
		while (fgets(line, 10, fp) != NULL) {
			if ((len = strlen(line)) > 0) {
				if (line[len - 1] == '\n') {
					line[len - 1] = '\0';
				}
				if ((pid = (pid_t)str2int(line)) > 1) {
					if (kill(pid, SIGTERM) == -1) {
						fprintf(stderr, "kill -15 ");
						perror(line);
					}
				}
			}
		}

		fclose(fp);
		if (unlink(config->pidfile) == -1) {
			fprintf(stderr, "unlink ");
			perror(config->pidfile);

			return -1;
		}
	} else {
		fprintf(stderr, "read ");
		perror(config->pidfile);

		return -1;
	}

	return 0;
}

/**
    Main routine
*/
int main(int argc, char *argv[]) {
	char *config_file = CONFIG_DIR"/php-fcgi.conf";
	bool kill_servers = false;
	int i = 0;

	while (++i < argc) {
		if (strcmp(argv[i], "-c") == 0) {
			if (++i < argc) {
				config_file = argv[i];
			} else {
				fputs("Specify a configuration file.",stderr);
				return EXIT_FAILURE;
			}
		} else if (strcmp(argv[i], "-h") == 0) {
			show_help(argv[0]);
			return EXIT_SUCCESS;
		} else if (strcmp(argv[i], "-k") == 0) {
			kill_servers = true;
		} else if (strcmp(argv[i], "-q") == 0) {
			quiet = true;
		} else if (strcmp(argv[i], "-v") == 0) {
			puts("PHP-FastCGI v"VERSION);
			return EXIT_SUCCESS;
		} else {
			fputs("Unknown option. Use '-h' for help.",stderr);
			return EXIT_FAILURE;
		}
	}

    t_config *config;
	if ((config = read_config(config_file)) == NULL) {
		return EXIT_FAILURE;
	}
	if (valid_config(config) == false) {
		return EXIT_FAILURE;
	}

	if (kill_servers == false) {
		if (start_fastcgi_servers(config) == -1) {
			return EXIT_FAILURE;
		}
	} else {
		if (stop_fastcgi_servers(config) == -1) {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
