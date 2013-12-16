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

#include "common.h"
#include "sql_check.h"

#ifdef _PGSQL_BACKEND
#include "pgsql_check.h"
#endif

#ifdef _MYSQL_BACKEND
#include <sys/param.h>
#include "mysql_check.h"
#endif

#ifdef _SQLITE_BACKEND
#include "sqlite_check.h"
#endif


#include <unistd.h>

/* OpenSSL stuff for the message digest algorithms */
#include <openssl/evp.h>


config_global	cfg = {
	"",	/* sql_backend */

	"",	/* db_host */
	0,	/* db_port */
	"",	/* db_name */
	"",	/* db_username */
	"",	/* db_password */
	"",	/* db_table */

	"",	/* column_username */
	"",	/* column_password */
	"",	/* column_scheme */
	"",	/* column_enabled */

	"",	/* pw_scheme */

	"no"	/* empty_password */
};
#ifdef _PGSQL_BACKEND
config_pgsql	cfg_pgsql = {
	""	/* dbconnection */
};
#endif
#ifdef _MYSQL_BACKEND
config_mysql	cfg_mysql = {
	"",	/* key */
	"",	/* cert */
	"",	/* ca */
	"",	/* capath */
	""	/* cipher */
};
#endif


void parse_config(const char *config_line);
char check_config(void);


char
sql_check(const char *got_username, const char *got_password,
		const char *config_file)
{
	FILE		*s_config_file = NULL;
	char		config_line[MAX_CONFIG_LINE + 1];

	/* the db specific functions will (over)write the password to this variable */
	char		password[MAX_PASSWORD + 1] = "";

	char		*salt = NULL;

	/* OpenSSL stuff for the message digest algorithms */
	EVP_MD_CTX	mdctx;
	const EVP_MD	*md = NULL;
	unsigned char	got_password_digest[EVP_MAX_MD_SIZE] = "";
	char		*got_password_digest_string = NULL;
	int		got_password_digest_string_size = 0;
	char		*digest_tmp = NULL;
	unsigned int	md_len = 0, i = 0, di = 0;

	BIO		*bio_mem = NULL;
	BIO		*bio_b64 = NULL;
	BIO		*bio_chain = NULL;
	unsigned int	bio_delay_check = 0;
	unsigned int	bio_delay_max = 1000;
	unsigned int	bio_read_chunk = 128;

	char		*password_digest = NULL, *got_password_salted = NULL, *got_password_digest_salted = NULL;
	int		ret = 0;


	/* if there was no config file defined in login.conf(5), use the default filename */
	if (!config_file)
		config_file = CONFIG_FILE_DEFAULT;

	s_config_file = fopen(config_file, "r");
	if (s_config_file == NULL) {
		syslog(LOG_ERR, "error opening %s: %s", config_file, strerror(errno));
		return(0);
	}

	/* parse the config file */
	while (fgets(config_line, sizeof(config_line), s_config_file)) {
		/* strip the newline */
		if (config_line[(int)strlen(config_line) - 1] == '\n')
			config_line[(int)strlen(config_line) - 1] = '\0';

		parse_config(config_line);
	}
	/* error checkings of the file descriptor */
	if (ferror(s_config_file) != 0) {
		syslog(LOG_ERR, "error while reading config file: %s", strerror(errno));
		return(0);
	}
	if(fclose(s_config_file) != 0)
		syslog(LOG_ERR, "error closing config file: %s", strerror(errno));


	/* validate the configuration */
	if (!check_config()) {
		syslog(LOG_ERR, "error parsing configuration!");
		return(0);
	}


	/* we write the queried password to the 'password' variable
	 * in one of the following database specific functions */
#ifdef _PGSQL_BACKEND
	if (strcmp(cfg.sql_backend, "pgsql") == 0) {
		if(!pgsql_check(got_username, password, &cfg, &cfg_pgsql)) {
			return(0);
		}
	} else
#endif
#ifdef _MYSQL_BACKEND
	if (strcmp(cfg.sql_backend, "mysql") == 0) {
		if(!mysql_check(got_username, password, &cfg, &cfg_mysql)) {
			return(0);
		}
	} else
#endif
#ifdef _SQLITE_BACKEND
	if (strcmp(cfg.sql_backend, "sqlite") == 0) {
		if(!sqlite_check(got_username, password, &cfg)) {
			return(0);
		}
	} else
#endif
	{
		syslog(LOG_ERR, "invalid sql backend: %s", cfg.sql_backend);
		return(0);
	}


	/*
	 * Basically we think that empty strings as passwords and digested
	 * empty strings are not equal and not the same.
	 *
	 * We want to avoid the case when empty password is not allowed by the
	 * configuration parameter, and the user supplies us an empty password,
	 * then we apply some message digest algorithm on it, but the queried
	 * password is also a digested empty string. So then in fact we would
	 * compare two digested empty strings, which would match because the
	 * two strings would be equal.
	 *
	 * This is why we check for allowed empty passwords, and if they are
	 * invalid, we fail to authorize if either of the supplied or queried
	 * passwords are empty.
	 */


	/* If we don't allow an empty password, but either the user supplied or
	 * the queried password is empty, then we fail to authenticate the user.
	 */
	if (	strcmp(cfg.empty_password, "yes") != 0  &&
		(!strlen(got_password)  ||
		!strlen(password)))

		return(0);


	/* Empty password is allowed, and the user supplied an empty password.
	 * This will only match with an empty queried password (not a digested empty
	 * string!).
	 */
	if (	strcmp(cfg.empty_password, "yes") == 0  &&
		!strlen(got_password))

		got_password_digest_string = "";

	/* apply the appropriate crypt/hash method */
	else if (strcmp(cfg.pw_scheme, "cleartext") == 0) {
		/* if the digest algorithm is cleartext, use the password as is ... */

		got_password_digest_string_size = strlen(got_password) + 1;
		got_password_digest_string = (char *)malloc(got_password_digest_string_size); malloc_check(got_password_digest_string);
		strlcpy(got_password_digest_string, got_password, got_password_digest_string_size);
	} else if (strcmp(cfg.pw_scheme, "blowfish") == 0) {
		/* ... if it is blowfish, use the crypt() function in blowfish
		 * mode ...
		 */

		salt = malloc(CRYPT_SALT_LEN + 1); malloc_check(salt);

		/* extract the salt from the queried password */
		strlcpy(salt, password, CRYPT_SALT_LEN + 1);
		got_password_digest_string = crypt(got_password, salt);
	} else if (strcmp(cfg.pw_scheme, "md5crypt") == 0) {
		/* ... if it is md5crypt, use the crypt() function in md5 mode
		 * ...
		 */

		salt = malloc(CRYPT_SALT_LEN + 1); malloc_check(salt);

		/* extract the salt from the queried password
		 * It spans from the first character until the third '$' sign.
		 */
		i = 0; di = 0;
		while (di != 3  &&  i <= strlen(password)  &&  i < CRYPT_SALT_LEN + 1) {
			salt[i] = password[i];
			if (password[i] == '$')
				di++;

			i++;
		}
		salt[i] = '\0';

		got_password_digest_string = crypt(got_password, salt);
	} else if (	strcmp(cfg.pw_scheme, "smd4") == 0  ||
			strcmp(cfg.pw_scheme, "smd5") == 0  ||
			strcmp(cfg.pw_scheme, "smdc2") == 0  ||
			strcmp(cfg.pw_scheme, "sripemd160") == 0  ||
			strcmp(cfg.pw_scheme, "ssha1") == 0  ||
			strcmp(cfg.pw_scheme, "ssha224") == 0  ||
			strcmp(cfg.pw_scheme, "ssha256") == 0  ||
			strcmp(cfg.pw_scheme, "ssha384") == 0  ||
			strcmp(cfg.pw_scheme, "ssha512") == 0  ||
			strcmp(cfg.pw_scheme, "swhirlpool") == 0) {

		/*
		 * ... Various digests using OpenSSL, but salting manually.
		 * ...
		 */

		OpenSSL_add_all_digests();
		md = EVP_get_digestbyname(cfg.pw_scheme + 1);
		if (!md) {
			syslog(LOG_ERR, "message digest algorithm '%s' is not supported by OpenSSL", cfg.pw_scheme + 1);
			return(0);
		}


		bio_mem = BIO_new(BIO_s_mem());
		if (!bio_mem) {
			syslog(LOG_ERR, "could not setup base64 decoding (bio_mem)");
			return(0);
		}
		bio_chain = BIO_push(bio_mem, bio_chain);

		bio_b64 = BIO_new(BIO_f_base64());
		if (!bio_b64) {
			syslog(LOG_ERR, "could not setup base64 decoding (bio_b64)");

			BIO_free_all(bio_chain);
			return(0);
		}
		BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
		bio_chain = BIO_push(bio_b64, bio_chain);


		/* base64 DEcode the queried password digest */
		BIO_reset(bio_chain);
		BIO_write(bio_mem, password, strlen(password));
		BIO_flush(bio_chain);
		do {
			/* Safeguard against BIO_read() delay inflicted infinite loops */
			if (bio_delay_check >= bio_delay_max) {
				syslog(LOG_ERR, "too much delay during base64 decoding (#1)");

				free(password_digest); password_digest = NULL;
				BIO_free_all(bio_chain);
				return(0);
			}

			password_digest = realloc(password_digest, i + bio_read_chunk);
			ret = BIO_read(bio_chain, password_digest + i, bio_read_chunk);
			switch (ret) {
				case 0:
					if (BIO_should_retry(bio_chain)) {
						bio_delay_check++;
						continue;
					}
				break;
				case -1:
					if (BIO_should_retry(bio_chain)) {
						bio_delay_check++;
						continue;
					} else {
						syslog(LOG_ERR, "error during base64 decoding of the queried password (-1)");

						free(password_digest); password_digest = NULL;
						BIO_free_all(bio_chain);
						return(0);
					}
				break;
				case -2:
					syslog(LOG_ERR, "error during base64 decoding of the queried password (-2)");

					free(password_digest); password_digest = NULL;
					BIO_free_all(bio_chain);
					return(0);
				break;
				default:
					i += ret;
				break;
			}
		} while (ret > 0);


		/* Extract the salt from the queried password digest */
		salt = malloc(SSHA_SALT_LEN); malloc_check(salt);
		memcpy(salt, password_digest, SSHA_SALT_LEN);

		free(password_digest); password_digest = NULL;


		/* Construct a salted version of the gotten password from salt + got_password */
		got_password_salted = malloc(SSHA_SALT_LEN + strlen(got_password) + 1); malloc_check(got_password_salted);
		memcpy(got_password_salted, salt, SSHA_SALT_LEN);
		memcpy(got_password_salted + SSHA_SALT_LEN, got_password, strlen(got_password));
		got_password_salted[SSHA_SALT_LEN + strlen(got_password)] = '\0';


		/* Process the salted gotten password with the digest algorithm */
		EVP_DigestInit(&mdctx, md);
		EVP_DigestUpdate(&mdctx, got_password_salted, strlen(got_password_salted));
		EVP_DigestFinal(&mdctx, got_password_digest, &md_len);
		EVP_MD_CTX_cleanup(&mdctx);

		got_password_digest_salted = malloc(SSHA_SALT_LEN + md_len); malloc_check(got_password_digest_salted);
		memcpy(got_password_digest_salted, salt, SSHA_SALT_LEN);
		memcpy(got_password_digest_salted + SSHA_SALT_LEN, got_password_digest, md_len);

		free(salt); salt = NULL;
		free(got_password_salted); got_password_salted = NULL;


		/* base64 ENcode the generated digest */
		BIO_reset(bio_chain);
		BIO_write(bio_chain, got_password_digest_salted, SSHA_SALT_LEN + md_len);
		BIO_flush(bio_chain);

		free(got_password_digest_salted); got_password_digest_salted = NULL;

		/* Read back the base64 encoded string */
		i = 0; bio_delay_check = 0;
		do {
			/* Safeguard against BIO_read() delay inflicted infinite loops */
			if (bio_delay_check >= bio_delay_max) {
				syslog(LOG_ERR, "too much delay during base64 encoding (#2)");

				free(got_password_digest_string); got_password_digest_string = NULL;
				BIO_free_all(bio_chain);
				return(0);
			}

			got_password_digest_string = realloc(got_password_digest_string, i + bio_read_chunk);
			ret = BIO_read(bio_mem, got_password_digest_string + i, bio_read_chunk);
			switch (ret) {
				case 0:
					if (BIO_should_retry(bio_mem)) {
						bio_delay_check++;
						continue;
					}
				break;
				case -1:
					if (BIO_should_retry(bio_mem)) {
						bio_delay_check++;
						continue;
					} else {
						syslog(LOG_ERR, "error during base64 encoding of the redigested password (-1)");

						free(got_password_digest_string); got_password_digest_string = NULL;
						BIO_free_all(bio_chain);
						return(0);
					}
				break;
				case -2:
					syslog(LOG_ERR, "error during base64 encoding of the redigested password (-2)");

					free(got_password_digest_string); got_password_digest_string = NULL;
					BIO_free_all(bio_chain);
					return(0);
				break;
				default:
					i += ret;
				break;
			}
		} while (ret > 0);
		got_password_digest_string[i] = '\0';

		BIO_free_all(bio_chain);
	} else {
		/* ... if something else, then pass it to openssl, and see if it
		 * can make something out of it :)
		 */

		OpenSSL_add_all_digests();
		md = EVP_get_digestbyname(cfg.pw_scheme);
		if (!md) {
			syslog(LOG_ERR, "message digest algorithm '%s' is not supported by OpenSSL", cfg.pw_scheme);
			return(0);
		}

		EVP_DigestInit(&mdctx, md);
		EVP_DigestUpdate(&mdctx, got_password, strlen(got_password));
		EVP_DigestFinal(&mdctx, got_password_digest, &md_len);
		EVP_MD_CTX_cleanup(&mdctx);

		/* create a string which contains the message digest as a string from the above generated message digest */
		got_password_digest_string = (char *)calloc(1, EVP_MAX_MD_SIZE * 2 + 1); malloc_check(got_password_digest_string);
		digest_tmp = (char *)malloc(sizeof(got_password_digest) * 2 + 1); malloc_check(digest_tmp);
		for(i = 0; i < md_len; i++) {
			/* copy out each hex char to a temp var */
			snprintf(digest_tmp, sizeof(got_password_digest[i]) * 2 + 1, "%02x", got_password_digest[i]);
			/* append the temp var to the final digest string */
			strlcat(got_password_digest_string, digest_tmp, md_len * 2 + 1);
		}
		free(digest_tmp); digest_tmp = NULL;
	}
	if (!got_password_digest_string) {
		syslog(LOG_ERR, "unknown error when encrypting password!");
		return(0);
	}
	if (	strcmp(cfg.empty_password, "yes") != 0  &&
		!strlen(got_password_digest_string)) {

		syslog(LOG_ERR, "unknown error when encrypting password!");
		return(0);
	}


	/* compare the compiled message digest and the queried one */
	if (strcmp(password, got_password_digest_string) == 0)
		return(1);

	return(0);
} /* sql_check() */

void
parse_config(const char *config_line)
{

	/* Global configuration options */
	if (strncmp(config_line, CONFIG_GLOBAL_SQL_BACKEND, strlen(CONFIG_GLOBAL_SQL_BACKEND)) == 0)
		strlcpy(cfg.sql_backend, config_line + (int)strlen(CONFIG_GLOBAL_SQL_BACKEND), sizeof(cfg.sql_backend));

	if (strncmp(config_line, CONFIG_GLOBAL_DB_HOST, strlen(CONFIG_GLOBAL_DB_HOST)) == 0)
		strlcpy(cfg.db_host, config_line + (int)strlen(CONFIG_GLOBAL_DB_HOST), sizeof(cfg.db_host));

	if (strncmp(config_line, CONFIG_GLOBAL_DB_PORT, strlen(CONFIG_GLOBAL_DB_PORT)) == 0)
		sscanf(config_line + (int)strlen(CONFIG_GLOBAL_DB_PORT), "%d", &cfg.db_port);

	if (strncmp(config_line, CONFIG_GLOBAL_DB_NAME, strlen(CONFIG_GLOBAL_DB_NAME)) == 0)
		strlcpy(cfg.db_name, config_line + (int)strlen(CONFIG_GLOBAL_DB_NAME), sizeof(cfg.db_name));

	if (strncmp(config_line, CONFIG_GLOBAL_DB_USERNAME, strlen(CONFIG_GLOBAL_DB_USERNAME)) == 0)
		strlcpy(cfg.db_username, config_line + (int)strlen(CONFIG_GLOBAL_DB_USERNAME), sizeof(cfg.db_username));

	if (strncmp(config_line, CONFIG_GLOBAL_DB_PASSWORD, strlen(CONFIG_GLOBAL_DB_PASSWORD)) == 0)
		strlcpy(cfg.db_password, config_line + (int)strlen(CONFIG_GLOBAL_DB_PASSWORD), sizeof(cfg.db_password));

	if (strncmp(config_line, CONFIG_GLOBAL_DB_TABLE, strlen(CONFIG_GLOBAL_DB_TABLE)) == 0)
		strlcpy(cfg.db_table, config_line + (int)strlen(CONFIG_GLOBAL_DB_TABLE), sizeof(cfg.db_table));

	if (strncmp(config_line, CONFIG_GLOBAL_COLUMN_USERNAME, strlen(CONFIG_GLOBAL_COLUMN_USERNAME)) == 0)
		strlcpy(cfg.column_username, config_line + (int)strlen(CONFIG_GLOBAL_COLUMN_USERNAME), sizeof(cfg.column_username));

	if (strncmp(config_line, CONFIG_GLOBAL_COLUMN_PASSWORD, strlen(CONFIG_GLOBAL_COLUMN_PASSWORD)) == 0)
		strlcpy(cfg.column_password, config_line + (int)strlen(CONFIG_GLOBAL_COLUMN_PASSWORD), sizeof(cfg.column_password));

	if (strncmp(config_line, CONFIG_GLOBAL_COLUMN_SCHEME, strlen(CONFIG_GLOBAL_COLUMN_SCHEME)) == 0)
		strlcpy(cfg.column_scheme, config_line + (int)strlen(CONFIG_GLOBAL_COLUMN_SCHEME), sizeof(cfg.column_scheme));

	if (strncmp(config_line, CONFIG_GLOBAL_COLUMN_ENABLED, strlen(CONFIG_GLOBAL_COLUMN_ENABLED)) == 0)
		strlcpy(cfg.column_enabled, config_line + (int)strlen(CONFIG_GLOBAL_COLUMN_ENABLED), sizeof(cfg.column_enabled));

	if (strncmp(config_line, CONFIG_GLOBAL_PW_SCHEME, strlen(CONFIG_GLOBAL_PW_SCHEME)) == 0)
		strlcpy(cfg.pw_scheme, config_line + (int)strlen(CONFIG_GLOBAL_PW_SCHEME), sizeof(cfg.pw_scheme));

	if (strncmp(config_line, CONFIG_GLOBAL_EMPTY_PASSWORD, strlen(CONFIG_GLOBAL_EMPTY_PASSWORD)) == 0)
		strlcpy(cfg.empty_password, config_line + (int)strlen(CONFIG_GLOBAL_EMPTY_PASSWORD), sizeof(cfg.empty_password));

#ifdef _PGSQL_BACKEND
	if (strncmp(config_line, CONFIG_PGSQL_DBCONNECTION, strlen(CONFIG_PGSQL_DBCONNECTION)) == 0)
		strlcpy(cfg_pgsql.dbconnection, config_line + (int)strlen(CONFIG_PGSQL_DBCONNECTION), sizeof(cfg_pgsql.dbconnection));
#endif

#ifdef _MYSQL_BACKEND
	if (strncmp(config_line, CONFIG_MYSQL_KEY, strlen(CONFIG_MYSQL_KEY)) == 0)
		strlcpy(cfg_mysql.key, config_line + (int)strlen(CONFIG_MYSQL_KEY), sizeof(cfg_mysql.key));

	if (strncmp(config_line, CONFIG_MYSQL_CERT, strlen(CONFIG_MYSQL_CERT)) == 0)
		strlcpy(cfg_mysql.cert, config_line + (int)strlen(CONFIG_MYSQL_CERT), sizeof(cfg_mysql.cert));

	if (strncmp(config_line, CONFIG_MYSQL_CA, strlen(CONFIG_MYSQL_CA)) == 0)
		strlcpy(cfg_mysql.ca, config_line + (int)strlen(CONFIG_MYSQL_CA), sizeof(cfg_mysql.ca));

	if (strncmp(config_line, CONFIG_MYSQL_CAPATH, strlen(CONFIG_MYSQL_CAPATH)) == 0)
		strlcpy(cfg_mysql.capath, config_line + (int)strlen(CONFIG_MYSQL_CAPATH), sizeof(cfg_mysql.capath));

	if (strncmp(config_line, CONFIG_MYSQL_CIPHER, strlen(CONFIG_MYSQL_CIPHER)) == 0)
		strlcpy(cfg_mysql.cipher, config_line + (int)strlen(CONFIG_MYSQL_CIPHER), sizeof(cfg_mysql.cipher));
#endif
} /* parse_config() */

char
check_config(void)
{
	/* option specific checkings */

	if (!strlen(cfg.sql_backend)) {
		syslog(LOG_ERR, "%s is empty!", CONFIG_GLOBAL_SQL_BACKEND);
		return(0);
	}

	if (!strlen(cfg.db_host)  &&  strcmp(cfg.sql_backend, "sqlite") != 0) {
		syslog(LOG_ERR, "%s is empty!", CONFIG_GLOBAL_DB_HOST);
		return(0);
	}

	if (	(cfg.db_port <= 0  ||  cfg.db_port > 65535)  &&
		cfg.db_host[0] != '/'  &&
		strcmp(cfg.sql_backend, "sqlite") != 0) {

		syslog(LOG_ERR, "%s set to an invalid port number!", CONFIG_GLOBAL_DB_PORT);
		return(0);
	}

	if (!strlen(cfg.db_name)) {
		syslog(LOG_ERR, "%s is empty!", CONFIG_GLOBAL_DB_NAME);
		return(0);
	}

	if (!strlen(cfg.db_username)  &&  strcmp(cfg.sql_backend, "sqlite") != 0) {
		syslog(LOG_ERR, "%s is empty!", CONFIG_GLOBAL_DB_USERNAME);
		return(0);
	}

	if (!strlen(cfg.db_table)) {
		syslog(LOG_ERR, "%s is empty!", CONFIG_GLOBAL_DB_TABLE);
		return(0);
	}

	if (!strlen(cfg.column_username)) {
		syslog(LOG_ERR, "%s is empty!", CONFIG_GLOBAL_COLUMN_USERNAME);
		return(0);
	}

	if (!strlen(cfg.column_password)) {
		syslog(LOG_ERR, "%s is empty!", CONFIG_GLOBAL_COLUMN_PASSWORD);
		return(0);
	}

	if (!strlen(cfg.column_scheme)) {
		syslog(LOG_ERR, "%s is empty!", CONFIG_GLOBAL_COLUMN_SCHEME);
		return(0);
	}

	if (	strcmp(cfg.empty_password, "yes") != 0  &&
		strcmp(cfg.empty_password, "no") != 0) {

		syslog(LOG_ERR, "%s can be either yes or no!", CONFIG_GLOBAL_EMPTY_PASSWORD);
		return(0);
	}

	return(1);
} /* check_config() */
