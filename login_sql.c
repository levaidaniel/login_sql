/*
 * Copyright (c) 2010, LEVAI Daniel
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	* Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 *	* Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL LEVAI Daniel BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syslimits.h>
#include <sys/types.h>

#include <login_cap.h>
#include <unistd.h>

#include "common.h"
#include "sql_check.h"
#include "login_sql.h"


char	*config_file = NULL;


int
main(int argc, char *argv[])
{
struct		rlimit rl;
login_cap_t	*lc = NULL;

FILE		*back = NULL;
int		mode = 0, c, count = 0;
char		response[MAX_PASSWORD];
int		sql_check_ret = EXIT_FAILURE;
char		*class = NULL, *username = NULL, *password = NULL;


	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	(void)setrlimit(RLIMIT_CORE, &rl);

	(void)setpriority(PRIO_PROCESS, 0, 0);

	openlog("login_sql", LOG_ODELAY, LOG_AUTH);

	while ((c = getopt(argc, argv, "v:s:d")) != -1) {
		switch (c) {
		case 'v':
			break;
		case 's':	/* service */
			if (strncmp(optarg, "login", 5) == 0) {
				mode = MODE_LOGIN;
			} else if (strncmp(optarg, "challenge", 9) == 0) {
				mode = MODE_CHALLENGE;
			} else if (strncmp(optarg, "response", 8) == 0) {
				mode = MODE_RESPONSE;
			} else {
				syslog(LOG_ERR, "%s: invalid service", optarg);
				exit(AUTH_FAILED);
			}
			break;
		case 'd':
			back = stdout;
			break;
		default:
			syslog(LOG_ERR, "usage error1");
			exit(AUTH_FAILED);
		}
	}

	switch (argc - optind) {
		case 2:
			class = argv[optind + 1];
			/*FALLTHROUGH*/
		case 1:
			username = argv[optind];
			break;
		default:
			syslog(LOG_ERR, "usage error2");
			exit(AUTH_FAILED);
	}

	if (back == NULL && (back = fdopen(3, "r+")) == NULL) {
		syslog(LOG_ERR, "reopening back channel: %m");
		exit(AUTH_FAILED);
	}

	switch (mode) {
		case MODE_LOGIN:
			password = getpass("Password:");
			break;
		case MODE_CHALLENGE:
			fprintf(back, BI_CHALLENGE "\n");
			exit(AUTH_OK);
			break;
		case MODE_RESPONSE:
			/* read the first string, which is the challenge (we do not use that) */
			while ( (read(3, &response[count], (size_t)1) == 1)  &&  count < MAX_PASSWORD ) {
				if (response[count] == '\0') {	/* read terminating null char in challenge */
					break;
				}
				count++;
			}

			/* read the second string, which is the response and the password */
			count = 0;
			while ( (read(3, &response[count], (size_t)1) == 1)  &&  count < MAX_PASSWORD ) {
				if (response[count] == '\0') {	/* read terminating null char in response */
					password = response;
					break;
				}
				count++;
			}
			break;
		default:
			syslog(LOG_ERR, "%d: unknown mode", mode);
			exit(AUTH_FAILED);
			break;
	}

	/* if defined in login.conf(5), get the config file's path */
	lc = login_getclass(class);
	if (!lc) {
		syslog(LOG_ERR, "unknown class: %s\n", class);
		return(AUTH_FAILED);
	}
	config_file = login_getcapstr(lc, CAP_CONFIG_FILE, NULL, NULL);
	login_close(lc);

	/* check against postgresql */
	sql_check_ret = sql_check(username, password);
	if (sql_check_ret == EXIT_SUCCESS) {
		fprintf(back, BI_AUTH "\n");
		syslog(LOG_NOTICE, "authorize ok for %s\n", username);
		closelog();

		exit(AUTH_OK);
	} else if (sql_check_ret == EXIT_FAILURE) {
		fprintf(back, BI_REJECT "\n");
		syslog(LOG_NOTICE, "authorize fail for %s\n", username);
		closelog();
	} else {
		fprintf(back, BI_REJECT "\n");
		syslog(LOG_ERR, "unkown error in authorization\n");
		closelog();
	}

	closelog();
	return(AUTH_FAILED);
} /* main */
