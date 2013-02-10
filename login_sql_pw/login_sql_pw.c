#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <readpassphrase.h>

#include <openssl/bio.h>
#include <openssl/evp.h>


#define	SSHA_SALT_LEN	4
#define	RANDOM_DEVICE	"/dev/random"
#define	PASSWORD_MAXLEN	1024


char *usage(void);


int
main(int argc, char *argv[])
{
	char	*digest_algo = NULL;
	char	*supported_digests[] = {
					"ssha1",
					"ssha256",
					"ssha512",
					NULL
					};
	char	found = 0;

	char	*salt = NULL;
	int	random_fd = -1;

	char	*password = NULL;
	char	*password_salted = NULL;
	char	*buf = NULL;
	int	pos = 0, ret = 0, c = 0;

	BIO	*bio_mem = NULL;
	BIO	*bio_b64 = NULL;
	BIO	*bio_chain = NULL;

	EVP_MD_CTX	mdctx;
	const EVP_MD	*md = NULL;
	unsigned char	password_digest[EVP_MAX_MD_SIZE] = "";
	unsigned char	*password_digest_salted = NULL;
	unsigned int	md_len = 0;


	while ((c = getopt(argc, argv, "a:lp:h")) != -1)
		switch (c) {
			case 'a':
				digest_algo = optarg;
			break;
			case 'l':
				digest_algo = supported_digests[pos++];
				while (digest_algo) {
					printf("%s ", digest_algo);
					digest_algo = supported_digests[pos++];
				}
				puts("");
				return(0);
			break;
			case 'p':
				password = optarg;
			break;
			case 'h':
				/* FALLTHROUGH */
			default:
				printf("%s %s\n", argv[0], usage());
				return(0);
			break;
		}


	/* Message digest setup */
	if (!digest_algo) {
		puts("You must specify a message digest algorithm!\n");
		printf("%s %s\n", argv[0], usage());

		return(1);
	}

	pos = 0;
	while (supported_digests[pos]) {
		if (strcmp(digest_algo, supported_digests[pos++]) == 0)
			found = 1;
	}
	if (!found) {
		printf("Invalid message digest algorithm: %s\n", digest_algo);
		return(1);
	}

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(++digest_algo);
	if (!md) {
		printf("Invalid message digest algorithm: %s\n", digest_algo);
		return(1);
	}


	/* Salt setup */
	random_fd = open(RANDOM_DEVICE, O_RDONLY);
	if (random_fd < 0) {
		perror("open: " RANDOM_DEVICE);
		return(1);
	}

	salt = malloc(SSHA_SALT_LEN);
	if (!salt) {
		puts("Could not allocate memory for salt generation!");
		return(1);
	}

	if (read(random_fd, salt, SSHA_SALT_LEN) < SSHA_SALT_LEN) {
		printf("Less than %d bytes read from %s!\n", SSHA_SALT_LEN, RANDOM_DEVICE);

		free(salt); salt = NULL;
		return(1);
	}


	/* BIO chain setup */
	bio_mem = BIO_new(BIO_s_mem());
	if (!bio_mem) {
		perror("BIO_new(s_mem)");

		free(salt); salt = NULL;
		return(1);
	}
	bio_chain = BIO_push(bio_mem, bio_chain);

	bio_b64 = BIO_new(BIO_f_base64());
	if (!bio_b64) {
		perror("BIO_new(f_base64)");

		free(salt); salt = NULL;
		return(1);
	}
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	bio_chain = BIO_push(bio_b64, bio_chain);


	/* Password setup */
	if (!password) {
		password = malloc(PASSWORD_MAXLEN);
		if (!password) {
			puts("Could not allocate memory for password reading!");

			free(salt); salt = NULL;
			return(1);
		}
		readpassphrase("Password: ", password, PASSWORD_MAXLEN + 1, RPP_REQUIRE_TTY);
	}
	if (!strlen(password)) {
		puts("The specified password is empty!");

		free(salt); salt = NULL;
		return(1);
	}


	/* Salt the user's password */
	password_salted = malloc(SSHA_SALT_LEN + strlen(password) + 1);
	if (!password_salted) {
		puts("Could not allocate memory for password salting!");

		free(salt); salt = NULL;
		return(1);
	}
	memcpy(password_salted, salt, SSHA_SALT_LEN);
	memcpy(password_salted + SSHA_SALT_LEN, password, strlen(password));
	password_salted[SSHA_SALT_LEN + strlen(password)] = '\0';


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

		free(salt); salt = NULL;
		return(1);
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


	BIO_free_all(bio_chain);

	return(0);
} /* main() */

char *
usage(void)
{
	return(	"<-a algorithm> [-l] [-p <password>] [-h]\n\n"
		"-a <algorithm>: Specify the message digest algorithm to use.\n"
		"-l: List supported message digest algorithms.\n"
		"-p <password>: Specify password.\n"
		"-h: This help.");
} /* usage() */
