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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include "alternative.h"
#include "libstr.h"
#include "liblist.h"

#define CGI_BUFFER_SIZE    4096
#define MAX_LINE_SIZE      1024
#define MAX_CWD             256
#define MAX_INCLUDE_DEPTH    16
#define SSI_EXTENSIONS     "shtml, stm, shtm"

typedef struct type_parameter {
	char *key, *value;
	struct type_parameter *next;
} t_parameter;

typedef struct {
	t_charlist extension;
	int  include_depth;
	char *document_root;
	char *working_dir;
	char *errmsg;
} t_config;

typedef enum { cgi, cmd } t_exec_type;

char *CURRENT_DIRECTORY = ".";

int process_ssi_file(t_config *config, char *file);

/**
    Get configuration
*/
t_config *get_configuration(void) {
	t_config *config;
	char *extensions;

	if ((config = (t_config*)malloc(sizeof(t_config))) == NULL) {
		return NULL;
	}

	if ((extensions = strdup(SSI_EXTENSIONS)) == NULL) {
		return NULL;
	} else if (parse_charlist(extensions, &(config->extension)) == -1) {
		return NULL;
	}

	config->include_depth = 0;

	if ((config->document_root = getenv("DOCUMENT_ROOT")) == NULL) {
		config->document_root = CURRENT_DIRECTORY;
	}

	if ((config->working_dir = (char*)malloc(MAX_CWD)) == NULL) {
		return NULL;
	} else if (getcwd(config->working_dir, MAX_CWD) == NULL) {
		config->working_dir = CURRENT_DIRECTORY;
	}

	config->errmsg = NULL;

	return config;
}

/**
    Write buffer
*/
int write_buffer(int sock, char *buffer, int len) {
	int bytes_written, total_written = 0;

	while (total_written < len) {
		if ((bytes_written = write(sock, buffer + total_written, len - total_written)) == -1) {
			if (errno != EINTR) {
				return -1;
			}
		} else {
			total_written += bytes_written;
		}
	}

	return 0;
}

/**
    Close pipe
*/
void close_pipe_end(int *pipe_end, int *count) {
	if (*pipe_end != -1) {
		close(*pipe_end);
		(*pipe_end) = -1;
		(*count)--;
	}
}

/**
    Get parameter value based in key
*/
char *get_parameter(t_parameter *param, char *key) {
	while (param != NULL) {
		if (strcmp(param->key, key) == 0) {
			return param->value;
		}
		param = param->next;
	}

	return NULL;
}

/**
    Remove parameters
*/
void *remove_parameters(t_parameter *param) {
	t_parameter *delete;

	while (param != NULL) {
		delete = param;
		param = param->next;
		free(delete);
	}

	return NULL;
}

/**
    Print error message
*/
void error(t_config *config, char *message) {
	if (config != NULL) {
		if (config->errmsg != NULL) {
			printf("%s\n", config->errmsg);
		}
	}

	fprintf(stderr, "%s\n", message);
}

/**
    Execute file
*/
int execute_command(char *command, t_exec_type type) {
	int output_pipe[2], error_pipe[2], result, skip;
	int bytes_read, bytes_in_buffer = 0, highest_fd, open_pipes = 2;
	char buffer[CGI_BUFFER_SIZE], *pos;
	bool header_read;
	struct timeval select_timeout;
	fd_set read_fds;
	pid_t cgi_pid;

	fflush(stdout);
	fflush(stderr);

	header_read = (type == cmd);

	if (pipe(output_pipe) == -1) {
		return -1;
	} else if (pipe(error_pipe) == -1) {
		close(output_pipe[0]);
		close(output_pipe[1]);
		return -1;
	}

	switch (cgi_pid = fork()) {
		case -1:
			break;
		case 0:
			/* Child. Executes command. */
			dup2(output_pipe[1], STDOUT_FILENO);
			dup2(error_pipe[1], STDERR_FILENO);

			close(output_pipe[0]);
			close(output_pipe[1]);
			close(error_pipe[0]);
			close(error_pipe[1]);

			fcntl(STDOUT_FILENO, F_SETFD, 0);
			fcntl(STDERR_FILENO, F_SETFD, 0);

			if (type == cgi) {
				if ((pos = strchr(command, '?')) != NULL) {
					*(pos++) = '\0';
					setenv("QUERY_STRING", pos, 1);
				}
				url_decode(command);

				execlp(command, command, (char*)NULL);
			} else {
				if ((result = system(command)) != -1) {
					exit(result);
				}
			}

			exit(EXIT_FAILURE);
		default:
			/* Parent. Reads command output. */
			close(output_pipe[1]);
			close(error_pipe[1]);

			do {
				highest_fd = -1;

				FD_ZERO(&read_fds);
				if (output_pipe[0] != -1) {
					FD_SET(output_pipe[0], &read_fds);
					if (output_pipe[0] > highest_fd) {
						highest_fd = output_pipe[0];
					}
				}
				if (error_pipe[0] != -1) {
					FD_SET(error_pipe[0], &read_fds);
					if (error_pipe[0] > highest_fd) {
						highest_fd = error_pipe[0];
					}
				}

				if (highest_fd == -1) {
					break;
				}

				select_timeout.tv_sec = 1;
				select_timeout.tv_usec = 0;

				switch (select(highest_fd + 1, &read_fds, NULL, NULL, &select_timeout)) {
					case -1:
						return -1;
					case 0:
						break;
					default:
						/* Output */
						if (output_pipe[0] != -1) {
							if (FD_ISSET(output_pipe[0], &read_fds)) {
								bytes_read = read(output_pipe[0], buffer + bytes_in_buffer, CGI_BUFFER_SIZE - bytes_in_buffer);
								switch (bytes_read) {
									case -1:
										return -1;
									case 0:
										close_pipe_end(&output_pipe[0], &open_pipes);
										header_read = true;
										break;
									default:
										if (header_read == false) {
											bytes_in_buffer += bytes_read;

											if ((pos = strstr(buffer, "\r\n\r\n")) == NULL) {
												pos = strstr(buffer, "\n\n");
												skip = 2;
											} else {
												skip = 4;
											}

											if (pos != NULL) {
												/* Skip CGI header */
												pos += skip;
												if (write_buffer(STDOUT_FILENO, pos, bytes_in_buffer - (pos - buffer)) == -1) {
													return -1;
												}
												header_read = true;
												bytes_in_buffer = 0;
											}
										} else if (write_buffer(STDOUT_FILENO, buffer, bytes_read) == -1) {
											return -1;
										}
								}
							}
						}

						/* Error */
						if ((error_pipe[0] != -1) && header_read) {
							if (FD_ISSET(error_pipe[0], &read_fds)) {
								bytes_read = read(error_pipe[0], buffer, CGI_BUFFER_SIZE);
								switch (bytes_read) {
									case -1:
										return -1;
									case 0:
										close_pipe_end(&error_pipe[0], &open_pipes);
										break;
									default:
										if (write_buffer(STDERR_FILENO, buffer, bytes_read) == -1) {
											return -1;
										}
								}
							}
						}
				}
			} while (open_pipes > 0);

			waitpid(cgi_pid, NULL, 0);
	}

	return 0;
}

/**
    Include file
*/
int include_file(t_config *config, char *directory, char *file) {
	if (chdir(directory) == -1) {
		return -1;
	}

	FILE *fp;
	char line[MAX_LINE_SIZE + 1], *extension;

	if ((extension = strrchr(file, '.')) != NULL) {
		extension++;
		if (in_charlist(extension, &(config->extension))) {
			if (config->include_depth >= MAX_INCLUDE_DEPTH) {
				error(config, "maximum include depth reached");
			} else {
				config->include_depth++;
				if (process_ssi_file(config, file) == -1) {
					error(config, "|");
					return -1;
				}
				config->include_depth--;
			}

			return 0;
		}
	}

	if ((fp = fopen(file, "r")) == NULL) {
		return -1;
	}

	line[MAX_LINE_SIZE] = '\0';
	while (fgets(line, MAX_LINE_SIZE, fp) != NULL) {
		printf("%s", line);
	}

	fclose(fp);

	return 0;
}

/**
    Execute SSI command
*/
int execute_ssi_command(t_config *config, char *command, t_parameter *param) {
	extern char **environ;
	char *str, **env;
	struct stat status;

	if (strcmp(command, "config") == 0) {
		/* CONFIG */
		while (param != NULL) {
			/* errmsg */
			if (strcmp(param->key, "errmsg") == 0) {
				if (config->errmsg != NULL) {
					free(config->errmsg);
				}
				if ((config->errmsg = strdup(param->value)) == NULL) {
					error(config, "strdup error");
				}
			}

			param = param ->next;
		}
	} else if (strcmp(command, "echo") == 0) {
		/* ECHO */
		while (param != NULL) {
			/* var */
			if (strcmp(param->key, "var") == 0) {
				if ((str = getenv(param->value)) != NULL) {
					printf("%s", str);
				}
			}

			param = param->next;
		}
	} else if (strcmp(command, "exec") == 0) {
		/* EXEC */
		while (param != NULL) {
			if (strcmp(param->key, "cgi") == 0) {
				execute_command(param->value, cgi);
			} else if (strcmp(param->key, "cmd") == 0) {
				execute_command(param->value, cmd);
			}

			param = param->next;
		}
	} else if (strcmp(command, "fsize") == 0) {
		/* FSIZE */
		while (param != NULL) {
			if (strcmp(param->key, "file") == 0) {
				if (stat(param->value, &status) == 0) {
					printf("%ld", (long)status.st_size);
				} else {
					error(config, "stat error");
				}
			}

			param = param->next;
		}
	} else if (strcmp(command, "include") == 0) {
		/* INCLUDE */
		while (param != NULL) {
			if (strcmp(param->key, "file") == 0) {
				/* file */
				if (chdir(config->working_dir) == -1) {
					error(config, "chdir error");
				} else if (include_file(config, CURRENT_DIRECTORY, param->value) == -1) {
					error(config, "include error");
				}
			} else if (strcmp(param->key, "virtual") == 0) {
				/* virtual */
				while (*param->value == '/') {
					param->value++;
				}

				if (chdir(config->document_root) == -1) {
					error(config, "chdir error");
				} else if (include_file(config, CURRENT_DIRECTORY, param->value) == -1) {
					error(config, "include error");
				}
			}

			param = param->next;
		}
	} else if (strcmp(command, "printenv") == 0) {
		/* PRINTENV */
		env = environ;
		while (*env != NULL) {
			printf("%s\n", *env);
			env++;
		}
	}

	return 0;
}

/**
    Process SSI file
*/
int process_ssi_file(t_config *config, char *file) {
	FILE *fp;

	if ((fp = fopen(file, "r")) == NULL) {
		fprintf(stderr, "file '%s' not found", file);
		return -1;
	}

	char line[MAX_LINE_SIZE + 1], *scan, *tag_begin, *tag_end;
	char *command, *param_key, *param_value, *param_end;
	t_parameter *param = NULL, *last = NULL, *new;
	bool error_found;

	line[MAX_LINE_SIZE] = '\0';
	while (fgets(line, MAX_LINE_SIZE, fp) != NULL) {
		scan = line;

		/* Scan for SSI tags */
		while ((tag_begin = strstr(scan, "<!--#")) != NULL) {
			if ((tag_end = strstr(tag_begin, "-->")) != NULL) {

				*tag_begin = *tag_end = '\0';
				printf("%s", scan);
				scan = tag_end + 3;

				command = remove_spaces(tag_begin + 5);

				/* Scan for parameters */
				if ((param_key = strchr(command, ' ')) != NULL) {
					*(param_key++) = '\0';

					while (*param_key == ' ') {
						param_key++;
					}

					error_found = false;
					while (*param_key != '\0') {
						if ((param_value = strstr(param_key, "=\"")) == NULL) {
							param = remove_parameters(param);
							error_found = true;
							break;
						}

						*param_value = '\0';
						param_value += 2;

						if ((param_end = strchr(param_value, '"')) == NULL) {
							param = remove_parameters(param);
							error_found = true;
							break;
						}

						*param_end = '\0';

						/* Add parameter to list */
						if ((new = (t_parameter*)malloc(sizeof(t_parameter))) == NULL) {
							error(config, "error allocating memory for parameter");
							return -1;
						}
						if (param == NULL) {
							param = new;
						} else {
							last->next = new;
						}
						last = new;

						new->key = param_key;
						new->value = param_value;
						new->next = NULL;

						param_key = param_end + 1;
						while (*param_key == ' ') {
							param_key++;
						}
					}

					if (error_found) {
						continue;
					}
				}

				/* Execute SSI command */
				execute_ssi_command(config, command, param);
				param = remove_parameters(param);
			} else {
				break;
			}
		}

		printf("%s", scan);
	}

	fclose(fp);

	return 0;
}

/**
    Main
*/
int main(int argc, char *argv[]) {
	t_config *config;

	if (argc <= 1) {
		puts("Missing parameter.");
		return EXIT_FAILURE;
	} else if (strcmp(argv[1], "-h") == 0) {
		/* Help */
		printf("Usage: %s <SSI file>\n", argv[0]);
		return EXIT_SUCCESS;
	} else if (strcmp(argv[1], "-v") == 0) {
		/* Version */
		puts("SSI-CGI v"VERSION);
		return EXIT_SUCCESS;
	}

	if ((config = get_configuration()) == NULL) {
		error(NULL, "error getting configuration");
		return EXIT_FAILURE;
	}

	printf("Content-Type: text/html\r\n\r\n");

	if (process_ssi_file(config, argv[1]) == -1) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
