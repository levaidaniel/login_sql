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

#include <sys/param.h>

#include <libpq-fe.h>

#include "common.h"

/* OpenSSL stuff for the message digest algorithms */
#include <openssl/evp.h>


extern char	*config_file;


int
pgsql_check(const char *got_username, const char *got_password)
{
FILE		*cfg_file_stream = NULL;
char		cfg_input_str[64];
int		cfg_file_error = 0;

PGconn		*pg_conn = NULL;
char		pg_conninfo[MAX_PG_QUERY_CMD] = "";

PGresult	*pg_result = NULL;
ExecStatusType	pg_result_status = 0;

int		pg_num_rows = 0;

char		pg_dbname[MAX_PG_PARAM] = "", pg_dbuser[MAX_PG_PARAM] = "", pg_dbpass[MAX_PG_PARAM] = "",
		pg_user_col[MAX_PG_PARAM] = "", pg_pass_col[MAX_PG_PARAM] = "", pg_table[MAX_PG_PARAM] = "",
		digest_alg[MAX_PG_PARAM] = "";
char		*pg_user_col_escaped = NULL, *pg_pass_col_escaped = NULL, *pg_table_escaped = NULL;
const char	*pg_query_tpl = "SELECT %s FROM %s WHERE %s = '%s';";
char		pg_query_cmd[MAX_PG_QUERY_CMD] = "";

char		username[EVP_MAX_MD_SIZE * 2 + 1] = "", password[EVP_MAX_MD_SIZE * 2 + 1] = "";
char		*username_escaped = NULL;

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
			strlcpy(pg_dbname, cfg_input_str + strlen("dbname="), MAX_PG_PARAM);
			if (pg_dbname[strlen(pg_dbname) - 1] == '\n') {	/* strip the newline */
				pg_dbname[strlen(pg_dbname) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "dbuser=", strlen("dbuser=")) == 0) {
			strlcpy(pg_dbuser, cfg_input_str + strlen("dbuser="), MAX_PG_PARAM);
			if (pg_dbuser[strlen(pg_dbuser) - 1] == '\n') {	/* strip the newline */
				pg_dbuser[strlen(pg_dbuser) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "dbpass=", strlen("dbpass=")) == 0) {
			strlcpy(pg_dbpass, cfg_input_str + strlen("dbpass="), MAX_PG_PARAM);
			if (pg_dbpass[strlen(pg_dbpass) - 1] == '\n') {	/* strip the newline */
				pg_dbpass[strlen(pg_dbpass) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "table=", strlen("table=")) == 0) {
			strlcpy(pg_table, cfg_input_str + strlen("table="), MAX_PG_PARAM);
			if (pg_table[strlen(pg_table) - 1] == '\n') {	/* strip the newline */
				pg_table[strlen(pg_table) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "user_col=", strlen("user_col=")) == 0) {
			strlcpy(pg_user_col, cfg_input_str + strlen("user_col="), MAX_PG_PARAM);
			if (pg_user_col[strlen(pg_user_col) - 1] == '\n') {	/* strip the newline */
				pg_user_col[strlen(pg_user_col) - 1] = '\0';
			}
		}
		if (strncmp(cfg_input_str, "pass_col=", strlen("pass_col=")) == 0) {
			strlcpy(pg_pass_col, cfg_input_str + strlen("pass_col="), MAX_PG_PARAM);
			if (pg_pass_col[strlen(pg_pass_col) - 1] == '\n') {	/* strip the newline */
				pg_pass_col[strlen(pg_pass_col) - 1] = '\0';
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

	/* connect to the postgresql server */
	snprintf(pg_conninfo, MAX_PG_QUERY_CMD, "dbname=%s user=%s password=%s", pg_dbname, pg_dbuser, pg_dbpass);
	pg_conn = PQconnectdb(pg_conninfo);

	switch (PQstatus(pg_conn)) {
		case CONNECTION_OK:
			break;
		case CONNECTION_BAD:
			syslog(LOG_ERR, "postgresql connection is not complete!\n\t%s\n", PQerrorMessage(pg_conn));
			PQfinish(pg_conn);
			return(EXIT_FAILURE);
		default:
			syslog(LOG_ERR, "postgresql connection state is not determinable!\n\t%s\n", PQerrorMessage(pg_conn));
			return(EXIT_FAILURE);
	}


	strlcpy(username, got_username, EVP_MAX_MD_SIZE * 2 + 1);

	/* escape the provided parameters */
	pg_user_col_escaped = malloc(strlen(pg_user_col) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_user_col_escaped, pg_user_col, sizeof(pg_user_col), NULL);

	pg_pass_col_escaped = malloc(strlen(pg_pass_col) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_pass_col_escaped, pg_pass_col, sizeof(pg_pass_col), NULL);

	pg_table_escaped = malloc(strlen(pg_table) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_table_escaped, pg_table, sizeof(pg_table), NULL);

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
				return(EXIT_FAILURE);
			}
			if (pg_num_rows > 1) {
				syslog(LOG_ERR, "postgresql command have returned more than one rows!\n");
				return(EXIT_FAILURE);
			}
			strlcpy(password, PQgetvalue(pg_result, 0, 0), EVP_MAX_MD_SIZE * 2 + 1);
			break;
		case PGRES_COMMAND_OK:
			syslog(LOG_ERR, "postgresql command result: OK(%s) - but no data has been returned!\n", PQresStatus(pg_result_status));
			PQclear(pg_result);
			PQfinish(pg_conn);

			return(EXIT_FAILURE);
		case PGRES_EMPTY_QUERY:
			syslog(LOG_ERR, "postgresql command result: ERROR(%s) - empty command string.\n", PQresStatus(pg_result_status));
			PQclear(pg_result);
			PQfinish(pg_conn);

			return(EXIT_FAILURE);
		case PGRES_BAD_RESPONSE:
			syslog(LOG_ERR, "postgresql command result: ERROR(%s) - bad response from server.\n", PQresStatus(pg_result_status));
			PQclear(pg_result);
			PQfinish(pg_conn);

			return(EXIT_FAILURE);
		case PGRES_NONFATAL_ERROR:
			syslog(LOG_ERR, "postgresql command result: ERROR(%s) - non fatal error occured.\n", PQresStatus(pg_result_status));
			PQclear(pg_result);
			PQfinish(pg_conn);

			return(EXIT_FAILURE);
		case PGRES_FATAL_ERROR:
			syslog(LOG_ERR, "postgresql command result: ERROR(%s) - fatal error occured.\n", PQresStatus(pg_result_status));
			PQclear(pg_result);
			PQfinish(pg_conn);

			return(EXIT_FAILURE);
		default:
			syslog(LOG_ERR, "postgresql command result: %s\n", PQresStatus(pg_result_status));
			PQclear(pg_result);
			PQfinish(pg_conn);

			return(EXIT_FAILURE);
	}

	PQclear(pg_result);
	PQfinish(pg_conn);

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


	/* compare the two message digests */
	if (strncmp(password, got_password_digest_string, strlen(password)) == 0) {
		free(got_password_digest_string);
		return(EXIT_SUCCESS);
	} else {
		free(got_password_digest_string);
		return(EXIT_FAILURE);
	}
} /* int pgsql_check() */
