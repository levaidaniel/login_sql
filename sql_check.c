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

#include "common.h"
#include "sql_check.h"

#ifdef PGSQL_BACKEND
#include "pgsql_check.h"
#endif

#ifdef MYSQL_BACKEND
#include "mysql_check.h"
#endif


#include <unistd.h>

/* OpenSSL stuff for the message digest algorithms */
#include <openssl/evp.h>


extern char	*config_file;


int sql_check(const char *got_username, const char *got_password)
{
FILE		*cfg_file_stream = NULL;
char		cfg_input_str[MAX_CFG_LINE];
int		cfg_file_error = 0;

#ifdef PGSQL_BACKEND
pgsql_connection	pgsql_conn = {
	"",	/* dbconnection */
	"",	/* table */
	"",	/* user_col */
	"",	/* pass_col */
	"",	/* host */
	""	/* db */
};
#endif
#ifdef MYSQL_BACKEND
mysql_connection	mysql_conn = {
	"",	/* host */
	"",	/* socket */
	0,	/* port */
	"",	/* db */
	"",	/* user */
	"",	/* pass */
	"",	/* table */
	"",	/* user_col */
	"",	/* pass_col */
	"",	/* key */
	"",	/* cert */
	"",	/* ca */
	"",	/* capath */
	""	/* cipher */
};
#endif
char		*where_str = NULL;	/* for the parameter searching */

char		digest_alg[MAX_PARAM] = "";
char		sql_backend[MAX_PARAM] = "";

char		password[MAX_PASSWORD] = "";	/* the db specific functions will (over)write the password to this variable */

char		salt[BLOWFISH_SALT_LEN + 1] = "";	/* to use with crypt() */

/* OpenSSL stuff for the message digest algorithms */
EVP_MD_CTX	mdctx;
const EVP_MD	*md = NULL;
unsigned char	got_password_digest[EVP_MAX_MD_SIZE] = "";
char		*got_password_digest_string = NULL;
char		*digest_tmp = NULL;
unsigned int	md_len = 0, i = 0, di = 0;


	/* if there was no config file defined in login.conf(5), use the default filename */
	if (!config_file) {
		config_file = CFG_FILE_DEFAULT;
	}
	cfg_file_stream = fopen(config_file, "r");
	if (cfg_file_stream == NULL ) {
		syslog(LOG_ERR, "error opening %s: %s\n", config_file, strerror(errno));
		return(EXIT_FAILURE);
	}

	/* parse the config file */
	while (fgets(cfg_input_str, sizeof(cfg_input_str), cfg_file_stream)) {
		cfg_file_error = errno;

#ifdef PGSQL_BACKEND
		if (strncmp(cfg_input_str, CFG_PARAM_PGSQL_DBCONNECTION, strlen(CFG_PARAM_PGSQL_DBCONNECTION)) == 0) {
			strlcpy(pgsql_conn.dbconnection, cfg_input_str + (int)strlen(CFG_PARAM_PGSQL_DBCONNECTION), MAX_CFG_LINE);
			if (pgsql_conn.dbconnection[(int)strlen(pgsql_conn.dbconnection) - 1] == '\n') {	/* strip the newline */
				pgsql_conn.dbconnection[(int)strlen(pgsql_conn.dbconnection) - 1] = '\0';
			}

			/* Extract the dbname parameter. */
			where_str = strstr(pgsql_conn.dbconnection, "dbname=");
			if (where_str) {	/* if the parameter is found */
				strlcpy(pgsql_conn.db, where_str + (int)strlen("dbname="), MAX_PARAM);
				pgsql_conn.db[(int)strcspn(pgsql_conn.db, " ")] = '\0';	/* close the string where the first space appears */
			}

			/* Extract the host/hostaddr parameter.
			 * The hostaddr parameter takes precedence over the host parameter.
			 */
			where_str = strstr(pgsql_conn.dbconnection, "host=");
			if (where_str) {	/* if the parameter is found */
				strlcpy(pgsql_conn.host, where_str + (int)strlen("host="), MAX_PARAM);
				pgsql_conn.host[(int)strcspn(pgsql_conn.host, " ")] = '\0';	/* close the string where the first space appears */
			}
			where_str = strstr(pgsql_conn.dbconnection, "hostaddr=");
			if (where_str) {
				strlcpy(pgsql_conn.host, where_str + (int)strlen("hostaddr="), MAX_PARAM);
				pgsql_conn.host[(int)strcspn(pgsql_conn.host, " ")] = '\0';	/* close the string where the first space appears */
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_PGSQL_TABLE, strlen(CFG_PARAM_PGSQL_TABLE)) == 0) {
			strlcpy(pgsql_conn.table, cfg_input_str + (int)strlen(CFG_PARAM_PGSQL_TABLE), MAX_PARAM);
			if (pgsql_conn.table[(int)strlen(pgsql_conn.table) - 1] == '\n') {	/* strip the newline */
				pgsql_conn.table[(int)strlen(pgsql_conn.table) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_PGSQL_USER_COL, strlen(CFG_PARAM_PGSQL_USER_COL)) == 0) {
			strlcpy(pgsql_conn.user_col, cfg_input_str + (int)strlen(CFG_PARAM_PGSQL_USER_COL), MAX_PARAM);
			if (pgsql_conn.user_col[(int)strlen(pgsql_conn.user_col) - 1] == '\n') {	/* strip the newline */
				pgsql_conn.user_col[(int)strlen(pgsql_conn.user_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_PGSQL_PASS_COL, strlen(CFG_PARAM_PGSQL_PASS_COL)) == 0) {
			strlcpy(pgsql_conn.pass_col, cfg_input_str + (int)strlen(CFG_PARAM_PGSQL_PASS_COL), MAX_PARAM);
			if (pgsql_conn.pass_col[(int)strlen(pgsql_conn.pass_col) - 1] == '\n') {	/* strip the newline */
				pgsql_conn.pass_col[(int)strlen(pgsql_conn.pass_col) - 1] = '\0';
			}
		}
#endif
#ifdef MYSQL_BACKEND
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_HOST, strlen(CFG_PARAM_MYSQL_HOST)) == 0) {
			strlcpy(mysql_conn.host, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_HOST), MAX_PARAM);
			if (mysql_conn.host[(int)strlen(mysql_conn.host) - 1] == '\n') {	/* strip the newline */
				mysql_conn.host[(int)strlen(mysql_conn.host) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_PORT, strlen(CFG_PARAM_MYSQL_PORT)) == 0) {
			sscanf(cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_PORT), "%d", &mysql_conn.port);
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_DB, strlen(CFG_PARAM_MYSQL_DB)) == 0) {
			strlcpy(mysql_conn.db, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_DB), MAX_PARAM);
			if (mysql_conn.db[(int)strlen(mysql_conn.db) - 1] == '\n') {	/* strip the newline */
				mysql_conn.db[(int)strlen(mysql_conn.db) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_USER, strlen(CFG_PARAM_MYSQL_USER)) == 0) {
			strlcpy(mysql_conn.user, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_USER), MAX_PARAM);
			if (mysql_conn.user[(int)strlen(mysql_conn.user) - 1] == '\n') {	/* strip the newline */
				mysql_conn.user[(int)strlen(mysql_conn.user) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_PASS, strlen(CFG_PARAM_MYSQL_PASS)) == 0) {
			strlcpy(mysql_conn.pass, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_PASS), MAX_PARAM);
			if (mysql_conn.pass[(int)strlen(mysql_conn.pass) - 1] == '\n') {	/* strip the newline */
				mysql_conn.pass[(int)strlen(mysql_conn.pass) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_TABLE, strlen(CFG_PARAM_MYSQL_TABLE)) == 0) {
			strlcpy(mysql_conn.table, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_TABLE), MAX_PARAM);
			if (mysql_conn.table[(int)strlen(mysql_conn.table) - 1] == '\n') {	/* strip the newline */
				mysql_conn.table[(int)strlen(mysql_conn.table) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_USER_COL, strlen(CFG_PARAM_MYSQL_USER_COL)) == 0) {
			strlcpy(mysql_conn.user_col, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_USER_COL), MAX_PARAM);
			if (mysql_conn.user_col[(int)strlen(mysql_conn.user_col) - 1] == '\n') {	/* strip the newline */
				mysql_conn.user_col[(int)strlen(mysql_conn.user_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_PASS_COL, strlen(CFG_PARAM_MYSQL_PASS_COL)) == 0) {
			strlcpy(mysql_conn.pass_col, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_PASS_COL), MAX_PARAM);
			if (mysql_conn.pass_col[(int)strlen(mysql_conn.pass_col) - 1] == '\n') {	/* strip the newline */
				mysql_conn.pass_col[(int)strlen(mysql_conn.pass_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_KEY, strlen(CFG_PARAM_MYSQL_KEY)) == 0) {
			strlcpy(mysql_conn.key, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_KEY), MAX_PARAM);
			if (mysql_conn.key[(int)strlen(mysql_conn.key) - 1] == '\n') {	/* strip the newline */
				mysql_conn.key[(int)strlen(mysql_conn.key) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_CERT, strlen(CFG_PARAM_MYSQL_CERT)) == 0) {
			strlcpy(mysql_conn.cert, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_CERT), MAX_PARAM);
			if (mysql_conn.cert[(int)strlen(mysql_conn.cert) - 1] == '\n') {	/* strip the newline */
				mysql_conn.cert[(int)strlen(mysql_conn.cert) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_CA, strlen(CFG_PARAM_MYSQL_CA)) == 0) {
			strlcpy(mysql_conn.ca, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_CA), MAX_PARAM);
			if (mysql_conn.ca[(int)strlen(mysql_conn.ca) - 1] == '\n') {	/* strip the newline */
				mysql_conn.ca[(int)strlen(mysql_conn.ca) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_CAPATH, strlen(CFG_PARAM_MYSQL_CAPATH)) == 0) {
			strlcpy(mysql_conn.capath, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_CAPATH), MAX_PARAM);
			if (mysql_conn.capath[(int)strlen(mysql_conn.capath) - 1] == '\n') {	/* strip the newline */
				mysql_conn.capath[(int)strlen(mysql_conn.capath) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_CIPHER, strlen(CFG_PARAM_MYSQL_CIPHER)) == 0) {
			strlcpy(mysql_conn.cipher, cfg_input_str + (int)strlen(CFG_PARAM_MYSQL_CIPHER), MAX_PARAM);
			if (mysql_conn.cipher[(int)strlen(mysql_conn.cipher) - 1] == '\n') {	/* strip the newline */
				mysql_conn.cipher[(int)strlen(mysql_conn.cipher) - 1] = '\0';
			}
		}
#endif
		if (strncmp(cfg_input_str, CFG_PARAM_DIGEST_ALG, strlen(CFG_PARAM_DIGEST_ALG)) == 0) {
			strlcpy(digest_alg, cfg_input_str + (int)strlen(CFG_PARAM_DIGEST_ALG), (size_t)MAX_PARAM);
			if (digest_alg[(int)strlen(digest_alg) - 1] == '\n') {	/* strip the newline */
				digest_alg[(int)strlen(digest_alg) - 1] = '\0';
			}
		}

		if (strncmp(cfg_input_str, CFG_PARAM_SQL_BACKEND, strlen(CFG_PARAM_SQL_BACKEND)) == 0) {
			strlcpy(sql_backend, cfg_input_str + (int)strlen(CFG_PARAM_SQL_BACKEND), MAX_PARAM);
			if (sql_backend[(int)strlen(sql_backend) - 1] == '\n') {	/* strip the newline */
				sql_backend[(int)strlen(sql_backend) - 1] = '\0';
			}
		}
	}
	/* error checkings of the file descriptor */
	if (ferror(cfg_file_stream) != 0) {
		syslog(LOG_ERR, "error while reading config file: %s\n", strerror(cfg_file_error));
		return(EXIT_FAILURE);
	}
	if(fclose(cfg_file_stream) != 0) {
		syslog(LOG_ERR, "error closing config file: %s\n", strerror(errno));
	}


	/* we write the queried password to the 'password' variable
	 * in one of the following database specific functions */
	if (strncmp(sql_backend, "pgsql", strlen("pgsql")) == 0) {
#ifdef PGSQL_BACKEND
		pgsql_check(got_username, password, &pgsql_conn);
#else
		syslog(LOG_ERR, "invalid sql backend: %s", sql_backend);
#endif
	} else if (strncmp(sql_backend, "mysql", strlen("mysql")) == 0) {
#ifdef MYSQL_BACKEND
		mysql_check(got_username, password, &mysql_conn);
#else
		syslog(LOG_ERR, "invalid sql backend: %s", sql_backend);
#endif
	} else {
		syslog(LOG_ERR, "invalid sql backend: %s", sql_backend);
	}


	/*
	 * Now that we have the stored/queried password, figure out what digest
	 * algorithm was used to create it (if any). The password is in the
	 * {algo}digest_string format (like in dovecot). If the {algo} prefix
	 * is missing, then we assume it was hashed with the global (defined in
	 * the config file) digest algorithm.
	 */

	/* Here we basically overwrite the globally define digest_alg with the
	 * one defined in the password string itself. */
	if (strncmp(password, "{cleartext}", strlen("{cleartext}")) == 0) {
		strlcpy(digest_alg, "cleartext", MAX_PARAM);
		strlcpy(password, password + (int)strlen(digest_alg) + 2, MAX_PASSWORD);
	} else if (strncmp(password, "{blowfish}", strlen("{blowfish}")) == 0) {
		strlcpy(digest_alg, "blowfish", MAX_PARAM);
		strlcpy(password, password + (int)strlen(digest_alg) + 2, MAX_PASSWORD);
	} else if (strncmp(password, "{md5crypt}", strlen("{md5crypt}")) == 0) {
		strlcpy(digest_alg, "md5crypt", MAX_PARAM);
		strlcpy(password, password + (int)strlen(digest_alg) + 2, MAX_PASSWORD);
	} else if (password[0] != '{'  ||  !strchr(password, '}')) {
		/* If there is no prefix, leave the digest_alg at the global
		 * value. */
	} else {
		/* Otherwise we just use the prefix, and hope that openssl will
		 * recognize it :) */
		i = 1; di = 0;
		while ( password[i] != '}'  &&  i <= strlen(password)  &&
				di < MAX_PARAM ) {
			digest_alg[di++] = password[i];
			i++;
		}	/* ^^^ copy the digest alg to digest_alg without the
			   	curly brackets */
		digest_alg[di] = '\0';

		strlcpy(password, password + (int)strlen(digest_alg) + 2, MAX_PASSWORD);
	}


	/* apply the appropriate crypt/hash method */

	if (strncmp(digest_alg, "cleartext", strlen("cleartext")) == 0) {
		/* if the digest algorithm is cleartext, use the password as is ... */

		got_password_digest_string = (char *)malloc(strlen(got_password) + 1); malloc_check(got_password_digest_string);
		strlcpy(got_password_digest_string, got_password, strlen(got_password) + 1);
	} else if (strncmp(digest_alg, "blowfish", strlen("blowfish")) == 0) {
		/* ... if it is blowfish, use the crypt() function in blowfish
		 * mode ... */

		strlcpy(salt, password, BLOWFISH_SALT_LEN + 1);	/* extract the salt from the queried password */
		got_password_digest_string = crypt(got_password, salt);
		if (!got_password_digest_string) {
			syslog(LOG_ERR, "error encrypting password: %s\n", strerror(errno));
			return(EXIT_FAILURE);
		}
	} else if (strncmp(digest_alg, "md5crypt", strlen("md5crypt")) == 0) {
		/* ... if it is md5crypt, use the crypt() function in md5 mode
		 * ... */

		/* extract the salt from the queried password
		 * It spans from the first character until the third '$' sign. */
		i = 0; di = 0;
		while (	di != 3  &&  i <= strlen(password)  &&  i < BLOWFISH_SALT_LEN + 1 ) {
			salt[i] = password[i];
			if (password[i] == '$')
				di++;
			i++;
		}
		got_password_digest_string = crypt(got_password, salt);
		if (!got_password_digest_string) {
			syslog(LOG_ERR, "error encrypting password: %s\n", strerror(errno));
			return(EXIT_FAILURE);
		}
	} else {
		/* ... if something else, then pass it to openssl, and see if it
		 * can make something out of it :) */

		OpenSSL_add_all_digests();
		md = EVP_get_digestbyname(digest_alg);
		if (!md) {
			syslog(LOG_ERR, "invalid message digest algorithm: %s", digest_alg);
			return(EXIT_FAILURE);
		}

		EVP_DigestInit(&mdctx, md);
		EVP_DigestUpdate(&mdctx, got_password, strlen(got_password));
		EVP_DigestFinal(&mdctx, got_password_digest, &md_len);
		EVP_MD_CTX_cleanup(&mdctx);

		/* create a string which contains the message digest as a string from the above generated message digest */
		got_password_digest_string = (char *)calloc(1, EVP_MAX_MD_SIZE * 2 + 1); malloc_check(got_password_digest_string);
		digest_tmp = (char *)malloc(sizeof(got_password_digest) * 2 + 1); malloc_check(digest_tmp);
		for(i = 0; i < md_len; i++) {
			snprintf(digest_tmp, sizeof(got_password_digest[i]) * 2 + 1, "%02x", got_password_digest[i]);	/* copy out each hex char to a temp var */
			strlcat(got_password_digest_string, digest_tmp, md_len * 2 + 1);	/* append the temp var to the final digest string */
		}
		free(digest_tmp);
	}

	if ( got_password_digest_string == NULL  ||
			strlen(got_password_digest_string) == 0  ||
			strlen(got_password) == 0 ) {
		return(EXIT_FAILURE);
	}


	/* compare the compiled message digest and the queried one */
	if (strcmp(password, got_password_digest_string) == 0) {
		//free(got_password_digest_string);
		return(EXIT_SUCCESS);
	} else {
		//free(got_password_digest_string);
		return(EXIT_FAILURE);
	}
} /* int sql_check() */
