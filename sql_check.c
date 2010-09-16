/*                                                                                                                                         
 * Copyright (c) 2010, LEVAI Daniel                                                                                                        
 * All rights reserved.                                                                                                                    
 *                                                                                                                                         
 * Redistribution and use in source and binary forms, with or without                                                                      
 * modification, are permitted provided that the following conditions are met:                                                             
 *   * Redistributions of source code must retain the above copyright                                                                      
 *     notice, this list of conditions and the following disclaimer.                                                                       
 *   * Redistributions in binary form must reproduce the above copyright                                                                   
 *     notice, this list of conditions and the following disclaimer in the                                                                 
 *     documentation and/or other materials provided with the distribution.                                                                
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

#ifdef PGSQL_BACKEND
#include <libpq-fe.h>
#elif MYSQL_BACKEND
#include <mysql.h>
#endif

#include "common.h"

/* OpenSSL stuff for the message digest algorithms */
#include <openssl/evp.h>


extern char	*config_file;

/* common variables for the ?sql_check functions */
char		sql_dbname[MAX_PG_PARAM] = "", sql_dbuser[MAX_PG_PARAM] = "", sql_dbpass[MAX_PG_PARAM] = "",
		sql_user_col[MAX_PG_PARAM] = "", sql_pass_col[MAX_PG_PARAM] = "", sql_table[MAX_PG_PARAM] = "";
char		password[MAX_PASSWORD] = "";


int sql_check(const char *got_username, const char *got_password)
{
FILE		*cfg_file_stream = NULL;
char		cfg_input_str[MAX_CFG_LINE];
int		cfg_file_error = 0;

char		digest_alg[MAX_PG_PARAM] = "";

/* OpenSSL stuff for the message digest algorithms */
EVP_MD_CTX      mdctx;
const EVP_MD	*md = NULL;
unsigned char	got_password_digest[EVP_MAX_MD_SIZE] = "";
char		*got_password_digest_string = (char *)malloc(EVP_MAX_MD_SIZE * 2 + 1);
char		digest_tmp[sizeof(unsigned char) * 2 + 1];
int             i = 0, md_len = 0;


	/* if there was no config file defined in login.conf(5), use the default filename */
	if (!config_file) {
		config_file = CONFIG_FILE_DEFAULT;
	}
	cfg_file_stream = fopen(config_file, "r");
	if (cfg_file_stream == NULL ) {
		syslog(LOG_ERR, "error opening %s: %s\n", config_file, strerror(errno));
		return(EXIT_FAILURE);
	}

	/* parse the config file */
	while (fgets(cfg_input_str, sizeof(cfg_input_str), cfg_file_stream)) {
		cfg_file_error = errno;

		if (strncmp(cfg_input_str, "dbname=", strlen("dbname=")) == 0) {
			strlcpy(sql_dbname, cfg_input_str + strlen("dbname="), MAX_PG_PARAM);
			if (sql_dbname[strlen(sql_dbname) - 1] == '\n') {	/* strip the newline */
				sql_dbname[strlen(sql_dbname) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "dbuser=", strlen("dbuser=")) == 0) {
			strlcpy(sql_dbuser, cfg_input_str + strlen("dbuser="), MAX_PG_PARAM);
			if (sql_dbuser[strlen(sql_dbuser) - 1] == '\n') {	/* strip the newline */
				sql_dbuser[strlen(sql_dbuser) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "dbpass=", strlen("dbpass=")) == 0) {
			strlcpy(sql_dbpass, cfg_input_str + strlen("dbpass="), MAX_PG_PARAM);
			if (sql_dbpass[strlen(sql_dbpass) - 1] == '\n') {	/* strip the newline */
				sql_dbpass[strlen(sql_dbpass) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "table=", strlen("table=")) == 0) {
			strlcpy(sql_table, cfg_input_str + strlen("table="), MAX_PG_PARAM);
			if (sql_table[strlen(sql_table) - 1] == '\n') {		/* strip the newline */
				sql_table[strlen(sql_table) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "user_col=", strlen("user_col=")) == 0) {
			strlcpy(sql_user_col, cfg_input_str + strlen("user_col="), MAX_PG_PARAM);
			if (sql_user_col[strlen(sql_user_col) - 1] == '\n') {	/* strip the newline */
				sql_user_col[strlen(sql_user_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "pass_col=", strlen("pass_col=")) == 0) {
			strlcpy(sql_pass_col, cfg_input_str + strlen("pass_col="), MAX_PG_PARAM);
			if (sql_pass_col[strlen(sql_pass_col) - 1] == '\n') {	/* strip the newline */
				sql_pass_col[strlen(sql_pass_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "digest_alg=", strlen("digest_alg=")) == 0) {
			strlcpy(digest_alg, cfg_input_str + strlen("digest_alg="), MAX_PG_PARAM);
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


	/* create a message digest from the user supplied password */
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
	for(i = 0; i < md_len; i++) {
		snprintf(digest_tmp, sizeof(got_password_digest[i]) * 2 + 1, "%02x", got_password_digest[i]);	/* copy out each hex char to a temp var */
		strlcat(got_password_digest_string, digest_tmp, md_len * 2 + 1);	/* append the temp var to the final digest string */
	}

	if (got_password_digest_string == NULL  ||  strlen(got_password_digest_string) <= 0) {
		return(EXIT_FAILURE);
	}


	/* we write the queried password to the global 'password' variable in one of the following functions */
#ifdef PGSQL_BACKEND
	pgsql_check(got_username);
#elif MYSQL_BACKEND
	mysql_check(got_username);
#endif

	/* compare the compiled message digest and the queried one */
printf("pass: %s, got_pass: %s\n", password, got_password_digest_string); /* XXX DEBUG */
	if (strcmp(password, got_password_digest_string) == 0) {
		free(got_password_digest_string);
		return(EXIT_SUCCESS);
	} else {
		free(got_password_digest_string);
		return(EXIT_FAILURE);
	}
} /* int sql_check() */


#ifdef PGSQL_BACKEND
void
pgsql_check(const char *got_username)
{
PGconn		*pg_conn = NULL;
char		pg_conninfo[MAX_PG_QUERY_CMD] = "";

PGresult	*pg_result = NULL;
ExecStatusType	pg_result_status = 0;

int		pg_num_rows = 0;

char		*pg_user_col_escaped = NULL, *pg_pass_col_escaped = NULL, *pg_table_escaped = NULL;
const char	*pg_query_tpl = "SELECT %s FROM %s WHERE %s = '%s';";
char		pg_query_cmd[MAX_PG_QUERY_CMD] = "";

char		username[MAX_USERNAME] = "";
char		*username_escaped = NULL;



	/* connect to the postgresql server */
	snprintf(pg_conninfo, MAX_PG_QUERY_CMD, "dbname=%s user=%s password=%s", sql_dbname, sql_dbuser, sql_dbpass);
	pg_conn = PQconnectdb(pg_conninfo);

	switch (PQstatus(pg_conn)) {
		case CONNECTION_OK:
			break;
		case CONNECTION_BAD:
			syslog(LOG_ERR, "postgresql connection is not complete!\n\t%s\n", PQerrorMessage(pg_conn));
			PQfinish(pg_conn);
			return;
		default:
			syslog(LOG_ERR, "postgresql connection state is not determinable!\n\t%s\n", PQerrorMessage(pg_conn));
			return;
	}


	strlcpy(username, got_username, MAX_USERNAME);

	/* escape the provided parameters */
	pg_user_col_escaped = malloc(strlen(sql_user_col) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_user_col_escaped, sql_user_col, sizeof(sql_user_col), NULL);

	pg_pass_col_escaped = malloc(strlen(sql_pass_col) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_pass_col_escaped, sql_pass_col, sizeof(sql_pass_col), NULL);

	pg_table_escaped = malloc(strlen(sql_table) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_table_escaped, sql_table, sizeof(sql_table), NULL);

	username_escaped = malloc(strlen(username) * 2 + 1);
	PQescapeStringConn(pg_conn, username_escaped, username, sizeof(username), NULL);

	/* fill the template sql command with the required fields */
	snprintf(pg_query_cmd, MAX_PG_QUERY_CMD, pg_query_tpl, pg_pass_col_escaped, pg_table_escaped, pg_user_col_escaped, username_escaped);

	free(pg_user_col_escaped);
	free(pg_pass_col_escaped);
	free(pg_table_escaped);
	free(username_escaped);

	/* execute the query */
	pg_result = PQexec(pg_conn, pg_query_cmd);
	switch (pg_result_status = PQresultStatus(pg_result)) {
		case PGRES_TUPLES_OK:	/* this what we want. we got back some data */
			pg_num_rows = PQntuples(pg_result);
			if (pg_num_rows < 1) {
				syslog(LOG_ERR, "postgresql command have returned no rows!\n");
				return;
			}
			if (pg_num_rows > 1) {
				syslog(LOG_ERR, "postgresql command have returned more than one rows!\n");
				return;
			}
			strlcpy(password, PQgetvalue(pg_result, 0, 0), MAX_PASSWORD);

			break;
		case PGRES_COMMAND_OK:
			syslog(LOG_ERR, "postgresql command result: OK(%s) - but no data has been returned!\n", PQresStatus(pg_result_status));
			break;
		case PGRES_EMPTY_QUERY:
			syslog(LOG_ERR, "postgresql command result: ERROR(%s) - empty command string.\n", PQresStatus(pg_result_status));
			break;
		case PGRES_BAD_RESPONSE:
			syslog(LOG_ERR, "postgresql command result: ERROR(%s) - bad response from server.\n", PQresStatus(pg_result_status));
			break;
		case PGRES_NONFATAL_ERROR:
			syslog(LOG_ERR, "postgresql command result: ERROR(%s) - non fatal error occured.\n", PQresStatus(pg_result_status));
			break;
		case PGRES_FATAL_ERROR:
			syslog(LOG_ERR, "postgresql command result: ERROR(%s) - fatal error occured.\n", PQresStatus(pg_result_status));
			break;
		default:
			syslog(LOG_ERR, "postgresql command result: %s\n", PQresStatus(pg_result_status));
			break;
	}

	PQclear(pg_result);
	PQfinish(pg_conn);
} /* void pgsql_check() */
#endif


#ifdef MYSQL_BACKEND
void
mysql_check(const char *got_username)
{
MYSQL		*mysql = NULL;


	mysql = mysql_init(NULL);
	if (mysql) {
		mysql_close(mysql);
	} else {
		puts("error in mysql");
	}
} /* void mysql_check() */
#endif
