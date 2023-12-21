// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1
#define ERROR 		2

/**
 * Internal change-directory command.
 */


static void manage_redirections(simple_command_t *s, char *stdin, char* stdout, char* stderr, 
int *fd_in, int *fd_out, int *fd_err, int *fd_common_out) {

	// printf("THE COMMAND FLAG < > >> is : %d@\n", s->io_flags);

	if (stdin != NULL) {
		*fd_in = open(stdin, O_RDONLY, 0777);
		int dup_result = dup2((*fd_in), READ);


		if ((*fd_in) < 0 || dup_result < 0) {
			close(*fd_in);

			free(stdin);
			free(stdout);
			free(stderr);
			exit(-1); 
		}

		close((*fd_in));
	}

	if (stdout != NULL && stderr != NULL && strcmp(stdout, stderr) == 0) {
		if (s->io_flags == IO_REGULAR) {
			*fd_common_out = open(stdout, O_WRONLY | O_CREAT | O_TRUNC, 0777);

			int dup2_first_result = dup2((*fd_common_out), WRITE);
			int dup2_second_result = dup2((*fd_common_out), ERROR);

			if ((*fd_common_out) < 0 || dup2_first_result < 0 || dup2_second_result < 0) {
				close((*fd_common_out));

				free(stdin);
				free(stdout);
				free(stderr);
				exit(-1);
			}
			
			close((*fd_common_out));
			
		}
	} else {
		if (stdout != NULL) {
			if (s->io_flags == IO_REGULAR) {
				*fd_out = open(stdout, O_WRONLY | O_CREAT | O_TRUNC, 0777);
				// printf("ENTERED REDIRECT_OUT > WITH FD: %d@\n", *fd_out);
				// printf("The file to write in is named: @%s@\n", stdout);
				int dup_out_regular_result = dup2((*fd_out), WRITE);
				if ((*fd_out) < 0 || dup_out_regular_result < 0) {
					close((*fd_out));

					free(stdin);
					free(stdout);
					free(stderr);
					exit(-1);
				}

				write(*fd_out, "", 0);

				close((*fd_out));

			} else if (s->io_flags == IO_OUT_APPEND) {
				*fd_out = open(stdout, O_WRONLY | O_CREAT | O_APPEND, 0777);

				int dup_out_append_result = dup2((*fd_out), WRITE);

				// printf ("DEBUG IN OUT APPEND: fd = %d, dup2res = %d@\n", *fd_out, dup_out_append_result);

				if ((*fd_out) < 0 || dup_out_append_result < 0) {
					close((*fd_out));

					free(stdin);
					free(stdout);
					free(stderr);
					exit(-1);
				}

				close((*fd_out));

			}
		}

		if (stderr != NULL) {
			if (s->io_flags == IO_REGULAR) {
				*fd_err = open(stderr, O_WRONLY | O_CREAT | O_TRUNC, 0777);

				int dup2_err_regular_result = dup2((*fd_err), ERROR);
				if ((*fd_err) < 0 || dup2_err_regular_result < 0) {
					close((*fd_err));
					
					free(stdin);
					free(stdout);
					free(stderr);
					exit(-1);
				}

				close((*fd_err));

			} else if (s->io_flags == IO_ERR_APPEND) {
				*fd_err = open(stderr, O_WRONLY | O_CREAT | O_APPEND, 0777);

				int dup2_err_append_result = dup2((*fd_err), ERROR);
				if ((*fd_err) < 0 || dup2_err_append_result < 0) {
					close((*fd_err));
					
					free(stdin);
					free(stdout);
					free(stderr);
					exit(-1);
				}

				close((*fd_err));

			}
		}
	}	

}

static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */

	char *arg_path = get_word(dir);
	int return_value;


	if (arg_path == NULL || strlen(arg_path) == 0) {
		
		// daca dam comanda cd fara niciun argument vrem sa mergem in HOME ~
		char *home_dest = getenv("HOME");

		if (home_dest != NULL && strlen(home_dest) > 0) {
			return_value = chdir(home_dest);
		} else {
			//daca vrem sa mergem la HOME iar aceasta variabila de mediu nu este setata
			//atunci nu vom face nimic
		}
	} else {
		//daca avem un argument valid diferit de null
		return_value = chdir(arg_path);
	}

	free(arg_path);
	return return_value;

}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */

	close(READ);
	close(WRITE);
	close(ERROR);

	return SHELL_EXIT;

	// return 0; /* TODO: Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (s == NULL || level < 0) {
		return SHELL_EXIT;
	}

	/* TODO: If builtin command, execute the command. */

	char *command = get_word(s->verb); //inainte era doar s.verb
	char *input = get_word(s->in);
	char *output = get_word(s->out);
	char *err = get_word(s->err);
	int fd_input = -1, fd_output = -1, fd_error = -1, fd_common_out_error = -1;

	// printf("The given command is : @%s@\n", command);
	// printf("The IO Flag is set to : @%d@\n", s->io_flags);
	// printf("The input for this command is : @%s@\n", input);
	// printf("The output for this command is : @%s@\n", output);
	// printf("The err for this command is : @%s@\n", err);

	if (strcmp(command, "cd") == 0) {
		manage_redirections(s, input, output, err, &fd_input, &fd_output, &fd_error, &fd_common_out_error);
		return shell_cd(s->params);
	} else if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0) {
		// printf("@@@@@Entered exit/quit@@@@@\n");
		// return shell_exit(); decomment after debug done
		int debug_value2 = shell_exit();
		// printf("IN PARSE SIMPLE SHELL_EXIT RETURNS: %d@@@@!#!@#\n", debug_value2);
		return debug_value2;
	}
	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	if (strchr(command, '=') != 0 ) {

		char *var_name = s->verb->string;
		char *value = get_word(s->verb->next_part->next_part);

		int return_value = setenv(var_name, value, 1);
		
		free(value);
		return return_value;
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	int number_of_args = 0;

	char **argv = get_argv(s, &number_of_args);

	int pid = fork();
	if (pid == 0) {
		//inside child process
		// sleep(120);

		int exec_result;
		
		// int original_stdin = dup(0);
		// int origianl_stdout = dup(1);
		// int original_stderr = dup(2);

		manage_redirections(s, input, output, err, &fd_input, &fd_output, &fd_error, &fd_common_out_error);
		
		// dup2(cine (incocuieste), pe cine);
		// dup2(original_stdin, 0);
		// dup2(origianl_stdout, 1);
		// dup2(original_stderr, 2);


		free(input);
		free(output);
		free(err);

		exec_result = execvpe(command, argv, __environ);

		exit(-1); //TODO SET CORRECT EXIT FLAG

	} else if (pid > 0){
		//inside parent process
		waitpid(pid, NULL, 0);
	}


	return 0; /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */

	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */

	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */

	if(c == NULL || level < 0 ) {
		return SHELL_EXIT;
	}

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		// return parse_simple(c->scmd, level + 1, c); to decomment

		//debug start
		int debug_value = parse_simple(c->scmd, level + 1, c);
		// printf ("in parse command switch simple ret value is : %d###\n", debug_value);
		return debug_value;

		// return 0; /* TODO: Replace with actual exit code of command. */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		break;

	default:
		return SHELL_EXIT;
	}

	return 0; /* TODO: Replace with actual exit code of command. */
}
