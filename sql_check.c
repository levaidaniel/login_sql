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
	""	/* pass_col */
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
char		digest_alg[MAX_PARAM] = "";

char		password[MAX_PASSWORD] = "";	/* the db specific functions will (over)write the password to this variable */

/* OpenSSL stuff for the message digest algorithms */
EVP_MD_CTX	mdctx;
const EVP_MD	*md = NULL;
unsigned char	got_password_digest[EVP_MAX_MD_SIZE] = "";
char		*got_password_digest_string = NULL;
char		*digest_tmp = NULL;
int		i = 0, md_len = 0;


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
			strlcpy(pgsql_conn.dbconnection, cfg_input_str + strlen(CFG_PARAM_PGSQL_DBCONNECTION), MAX_CFG_LINE);
			if (pgsql_conn.dbconnection[strlen(pgsql_conn.dbconnection) - 1] == '\n') {	/* strip the newline */
				pgsql_conn.dbconnection[strlen(pgsql_conn.dbconnection) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_PGSQL_TABLE, strlen(CFG_PARAM_PGSQL_TABLE)) == 0) {
			strlcpy(pgsql_conn.table, cfg_input_str + strlen(CFG_PARAM_PGSQL_TABLE), MAX_PARAM);
			if (pgsql_conn.table[strlen(pgsql_conn.table) - 1] == '\n') {	/* strip the newline */
				pgsql_conn.table[strlen(pgsql_conn.table) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_PGSQL_USER_COL, strlen(CFG_PARAM_PGSQL_USER_COL)) == 0) {
			strlcpy(pgsql_conn.user_col, cfg_input_str + strlen(CFG_PARAM_PGSQL_USER_COL), MAX_PARAM);
			if (pgsql_conn.user_col[strlen(pgsql_conn.user_col) - 1] == '\n') {	/* strip the newline */
				pgsql_conn.user_col[strlen(pgsql_conn.user_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_PGSQL_PASS_COL, strlen(CFG_PARAM_PGSQL_PASS_COL)) == 0) {
			strlcpy(pgsql_conn.pass_col, cfg_input_str + strlen(CFG_PARAM_PGSQL_PASS_COL), MAX_PARAM);
			if (pgsql_conn.pass_col[strlen(pgsql_conn.pass_col) - 1] == '\n') {	/* strip the newline */
				pgsql_conn.pass_col[strlen(pgsql_conn.pass_col) - 1] = '\0';
			}
		}
#endif
#ifdef MYSQL_BACKEND
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_HOST, strlen(CFG_PARAM_MYSQL_HOST)) == 0) {
			strlcpy(mysql_conn.host, cfg_input_str + strlen(CFG_PARAM_MYSQL_HOST), MAX_PARAM);
			if (mysql_conn.host[strlen(mysql_conn.host) - 1] == '\n') {	/* strip the newline */
				mysql_conn.host[strlen(mysql_conn.host) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_PORT, strlen(CFG_PARAM_MYSQL_PORT)) == 0) {
			sscanf(cfg_input_str + strlen(CFG_PARAM_MYSQL_PORT), "%d", &mysql_conn.port);
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_DB, strlen(CFG_PARAM_MYSQL_DB)) == 0) {
			strlcpy(mysql_conn.db, cfg_input_str + strlen(CFG_PARAM_MYSQL_DB), MAX_PARAM);
			if (mysql_conn.db[strlen(mysql_conn.db) - 1] == '\n') {	/* strip the newline */
				mysql_conn.db[strlen(mysql_conn.db) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_USER, strlen(CFG_PARAM_MYSQL_USER)) == 0) {
			strlcpy(mysql_conn.user, cfg_input_str + strlen(CFG_PARAM_MYSQL_USER), MAX_PARAM);
			if (mysql_conn.user[strlen(mysql_conn.user) - 1] == '\n') {	/* strip the newline */
				mysql_conn.user[strlen(mysql_conn.user) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_PASS, strlen(CFG_PARAM_MYSQL_PASS)) == 0) {
			strlcpy(mysql_conn.pass, cfg_input_str + strlen(CFG_PARAM_MYSQL_PASS), MAX_PARAM);
			if (mysql_conn.pass[strlen(mysql_conn.pass) - 1] == '\n') {	/* strip the newline */
				mysql_conn.pass[strlen(mysql_conn.pass) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_TABLE, strlen(CFG_PARAM_MYSQL_TABLE)) == 0) {
			strlcpy(mysql_conn.table, cfg_input_str + strlen(CFG_PARAM_MYSQL_TABLE), MAX_PARAM);
			if (mysql_conn.table[strlen(mysql_conn.table) - 1] == '\n') {	/* strip the newline */
				mysql_conn.table[strlen(mysql_conn.table) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_USER_COL, strlen(CFG_PARAM_MYSQL_USER_COL)) == 0) {
			strlcpy(mysql_conn.user_col, cfg_input_str + strlen(CFG_PARAM_MYSQL_USER_COL), MAX_PARAM);
			if (mysql_conn.user_col[strlen(mysql_conn.user_col) - 1] == '\n') {	/* strip the newline */
				mysql_conn.user_col[strlen(mysql_conn.user_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_PASS_COL, strlen(CFG_PARAM_MYSQL_PASS_COL)) == 0) {
			strlcpy(mysql_conn.pass_col, cfg_input_str + strlen(CFG_PARAM_MYSQL_PASS_COL), MAX_PARAM);
			if (mysql_conn.pass_col[strlen(mysql_conn.pass_col) - 1] == '\n') {	/* strip the newline */
				mysql_conn.pass_col[strlen(mysql_conn.pass_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_KEY, strlen(CFG_PARAM_MYSQL_KEY)) == 0) {
			strlcpy(mysql_conn.key, cfg_input_str + strlen(CFG_PARAM_MYSQL_KEY), MAX_PARAM);
			if (mysql_conn.key[strlen(mysql_conn.key) - 1] == '\n') {	/* strip the newline */
				mysql_conn.key[strlen(mysql_conn.key) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_CERT, strlen(CFG_PARAM_MYSQL_CERT)) == 0) {
			strlcpy(mysql_conn.cert, cfg_input_str + strlen(CFG_PARAM_MYSQL_CERT), MAX_PARAM);
			if (mysql_conn.cert[strlen(mysql_conn.cert) - 1] == '\n') {	/* strip the newline */
				mysql_conn.cert[strlen(mysql_conn.cert) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_CA, strlen(CFG_PARAM_MYSQL_CA)) == 0) {
			strlcpy(mysql_conn.ca, cfg_input_str + strlen(CFG_PARAM_MYSQL_CA), MAX_PARAM);
			if (mysql_conn.ca[strlen(mysql_conn.ca) - 1] == '\n') {	/* strip the newline */
				mysql_conn.ca[strlen(mysql_conn.ca) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_CAPATH, strlen(CFG_PARAM_MYSQL_CAPATH)) == 0) {
			strlcpy(mysql_conn.capath, cfg_input_str + strlen(CFG_PARAM_MYSQL_CAPATH), MAX_PARAM);
			if (mysql_conn.capath[strlen(mysql_conn.capath) - 1] == '\n') {	/* strip the newline */
				mysql_conn.capath[strlen(mysql_conn.capath) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, CFG_PARAM_MYSQL_CIPHER, strlen(CFG_PARAM_MYSQL_CIPHER)) == 0) {
			strlcpy(mysql_conn.cipher, cfg_input_str + strlen(CFG_PARAM_MYSQL_CIPHER), MAX_PARAM);
			if (mysql_conn.cipher[strlen(mysql_conn.cipher) - 1] == '\n') {	/* strip the newline */
				mysql_conn.cipher[strlen(mysql_conn.cipher) - 1] = '\0';
			}
		}
#endif
		if (strncmp(cfg_input_str, CFG_PARAM_DIGEST_ALG, strlen(CFG_PARAM_DIGEST_ALG)) == 0) {
			strlcpy(digest_alg, cfg_input_str + strlen(CFG_PARAM_DIGEST_ALG), MAX_PARAM);
			if (digest_alg[strlen(digest_alg) - 1] == '\n') {	/* strip the newline */
				digest_alg[strlen(digest_alg) - 1] = '\0';
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


	if (strncmp(digest_alg, "cleartext", strlen("cleartext")) == 0) {
		/* if the digest algorithm is cleartext, use the password as is ... */

		got_password_digest_string = (char *)got_password;
	} else {
		/* ... otherwise create a message digest from the user supplied password */

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
		got_password_digest_string = (char *)malloc(EVP_MAX_MD_SIZE * 2 + 1);
		digest_tmp = (char *)malloc(sizeof(got_password_digest) * 2 + 1);
		for(i = 0; i < md_len; i++) {
			snprintf(digest_tmp, sizeof(got_password_digest[i]) * 2 + 1, "%02x", got_password_digest[i]);	/* copy out each hex char to a temp var */
			strlcat(got_password_digest_string, digest_tmp, md_len * 2 + 1);	/* append the temp var to the final digest string */
		}
		free(digest_tmp);

		if (got_password_digest_string == NULL  ||  strlen(got_password_digest_string) <= 0) {
			return(EXIT_FAILURE);
		}
	}


	/* we write the queried password to the 'password' variable in one of the following functions */
#ifdef PGSQL_BACKEND
	pgsql_check(got_username, password, &pgsql_conn);
#elif MYSQL_BACKEND
	mysql_check(got_username, password, &mysql_conn);
#endif

	/* compare the compiled message digest and the queried one */
	if (strcmp(password, got_password_digest_string) == 0) {
		free(got_password_digest_string);
		return(EXIT_SUCCESS);
	} else {
		free(got_password_digest_string);
		return(EXIT_FAILURE);
	}
} /* int sql_check() */
