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

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>


int
main(int argc, char *argv[]) {
char		*password = NULL, *blowfish = NULL, *salt = NULL;
int		opt = 0;
unsigned char	log_rounds = 6;
int		fd = -1, i = 0, read_bytes = 0;
size_t		readbuf_size = 8, password_size = 8;
char		*tmp = NULL;
char		echo_password = 0;


	while ((opt = getopt(argc, argv, "p:l:eh")) != -1)
		switch (opt) {
			case 'p':
				password = optarg;
				break;
			case 'l':
				log_rounds = (unsigned char)atoi(optarg);
				break;
			case 'e':
				echo_password = 1;
				break;
			case 'h':
				printf("%s [-p password] [-l logrounds] [-eh]\n", argv[0]);
				return(EXIT_SUCCESS);
				break;
			default:
				break;
		}

	/* if previously we didn't get the password thru an option,
	 * then read it from stdin */
	if (password == NULL) {
		fd = fcntl(STDIN_FILENO, F_DUPFD, 0);
		if (fd == -1) {
			printf("error opening standard in: %s\n", strerror(errno));
			return(EXIT_FAILURE);
		}

		password = malloc(password_size);
		tmp = malloc(readbuf_size);
		while((i = read(fd, tmp, readbuf_size))) {
			read_bytes += i;

			if (read_bytes >= (int)password_size) {
				password = realloc(password, password_size + (size_t)i);
				password_size += (size_t)i;
			}

			strlcat(password, tmp, password_size);
		}
		password[read_bytes] = '\0';
	}


	if (log_rounds > 31)
		log_rounds = 31;
	if (log_rounds < 4)
		log_rounds = 4;


	/* Create */
	salt = bcrypt_gensalt(log_rounds);
	if (echo_password) {
		printf("%s\n", password);
	}
	blowfish = crypt(password, salt);
	if (!blowfish) {
		printf("error encrypting password: %s\n", strerror(errno));
		return(EXIT_FAILURE);
	}


	/* Display */
	printf("%s\n", blowfish);


	return(EXIT_SUCCESS);
} /* main */
