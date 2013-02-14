/*
 * Copyright (c) 2010, 2011, 2012, 2013 LEVAI Daniel
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

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <readpassphrase.h>

#include <openssl/bio.h>
#include <openssl/evp.h>


#define	SSHA_SALT_LEN	4
#define	RANDOM_DEVICE	"/dev/random"
#define	PASSWORD_MAXLEN	1024


char	*usage(void);
void	quit(int);


char	*salt = NULL;
char	*password = NULL;
BIO	*bio_chain = NULL;


int
main(int argc, char *argv[])
{
	char	*digest = NULL;

	int	random_fd = -1;

	char	*password_salted = NULL;
	char	*buf = NULL;
	int	pos = 0, ret = 0, c = 0;

	BIO	*bio_mem = NULL;
	BIO	*bio_b64 = NULL;

	EVP_MD_CTX	mdctx;
	const EVP_MD	*md = NULL;
	unsigned char	password_digest[EVP_MAX_MD_SIZE] = "";
	unsigned char	*password_digest_salted = NULL;
	unsigned int	md_len = 0;


	while ((c = getopt(argc, argv, "a:p:")) != -1)
		switch (c) {
			case 'a':
				digest = optarg;
			break;
			case 'p':
				password = strdup(optarg);
			break;
			default:
				printf("%s %s\n", argv[0], usage());
				quit(0);
			break;
		}


	/* Message digest setup */
	if (!digest) {
		puts("You must specify a message digest algorithm!\n");
		printf("%s %s\n", argv[0], usage());

		quit(1);
	}

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(digest);
	if (!md) {
		printf("Message digest algorithm '%s' is not supported by your OpenSSL.\nRun `openssl dgst -h' to see which digests you can use.\n", digest);
		quit(1);
	}


	/* Salt setup */
	random_fd = open(RANDOM_DEVICE, O_RDONLY);
	if (random_fd < 0) {
		perror("open: " RANDOM_DEVICE);
		quit(1);
	}

	salt = malloc(SSHA_SALT_LEN);
	if (!salt) {
		puts("Could not allocate memory for salt generation!");
		quit(1);
	}

	if (read(random_fd, salt, SSHA_SALT_LEN) < SSHA_SALT_LEN) {
		printf("Less than %d bytes read from %s!\n", SSHA_SALT_LEN, RANDOM_DEVICE);
		quit(1);
	}


	/* BIO chain setup */
	bio_mem = BIO_new(BIO_s_mem());
	if (!bio_mem) {
		perror("BIO_new(s_mem)");
		quit(1);
	}
	bio_chain = BIO_push(bio_mem, bio_chain);

	bio_b64 = BIO_new(BIO_f_base64());
	if (!bio_b64) {
		perror("BIO_new(f_base64)");
		quit(1);
	}
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	bio_chain = BIO_push(bio_b64, bio_chain);


	/* Password setup */
	if (!password) {
		password = malloc(PASSWORD_MAXLEN);
		if (!password) {
			puts("Could not allocate memory for password reading!");
			quit(1);
		}
		readpassphrase("Password:", password, PASSWORD_MAXLEN + 1, RPP_REQUIRE_TTY);
	}
	if (!strlen(password)) {
		puts("The specified password is empty!");
		quit(1);
	}


	/* Salt the user's password */
	password_salted = malloc(SSHA_SALT_LEN + strlen(password) + 1);
	if (!password_salted) {
		puts("Could not allocate memory for password salting!");
		quit(1);
	}
	memcpy(password_salted, salt, SSHA_SALT_LEN);
	memcpy(password_salted + SSHA_SALT_LEN, password, strlen(password));
	password_salted[SSHA_SALT_LEN + strlen(password)] = '\0';

	free(password); password = NULL;


	/* Create the message digest from the salted password */
	EVP_DigestInit(&mdctx, md);
	EVP_DigestUpdate(&mdctx, password_salted, strlen(password_salted));
	EVP_DigestFinal(&mdctx, password_digest, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);

	free(password_salted); password_salted = NULL;


	/* base64 encode the salt + message digest */
	password_digest_salted = malloc(SSHA_SALT_LEN + md_len);
	if (!password_digest_salted ) {
		puts("Could not allocate memory for digest generation!");
		quit(1);
	}
	memcpy(password_digest_salted, salt, SSHA_SALT_LEN);
	memcpy(password_digest_salted + SSHA_SALT_LEN, password_digest, md_len);

	BIO_write(bio_chain, password_digest_salted, SSHA_SALT_LEN + md_len);
	BIO_flush(bio_chain);

	free(salt); salt = NULL;
	free(password_digest_salted); password_digest_salted = NULL;

	pos = 0;
	do {
		buf = realloc(buf, pos + 1);
		ret = BIO_read(bio_mem, buf + pos, 1);
		pos += ret;
	} while(ret > 0);
	buf[pos + 1] = '\0';

	printf("%s\n", buf);


	quit(0);

	return(0);
} /* main() */

char *
usage(void)
{
	return(	"<-a algorithm> [-p <password>]\n\n"
		"-a <algorithm>: Specify the message digest algorithm to use.\n"
		"-p <password>: Specify password.");
} /* usage() */

void
quit(int retval)
{
	free(password); password = NULL;
	free(salt); salt = NULL;
	BIO_free_all(bio_chain);

	exit(retval);
} /* quit() */
