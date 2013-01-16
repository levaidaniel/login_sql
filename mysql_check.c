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

#ifdef _MYSQL_BACKEND

#include <mysql.h>

#include "common.h"
#include "sql_check.h"
#include "mysql_check.h"


void
mysql_check(const char *got_username, char *password,
		char *digest_alg, mysql_connection *mysql_conn)
{
	MYSQL		mysql;
	MYSQL_RES	*mysql_result = NULL;
	MYSQL_ROW	mysql_row;
	my_ulonglong	mysql_numrows = 0;
	unsigned long	*mysql_lengths = NULL;

	char		*user_col_escaped = NULL, *pass_col_escaped = NULL, *scheme_col_escaped = NULL, *table_escaped = NULL;
	const char	*query_tpl = "SELECT %s, %s FROM %s WHERE %s = '%s'";
	char		query_cmd[MAX_QUERY_CMD] = "";

	char		username[MAX_USERNAME] = "";
	char		*username_escaped = NULL;


	mysql_init(&mysql);

	/* try to start an ssl connection later. any unused SSL parameters may be given as NULL */
	mysql_ssl_set(&mysql,	(strlen(mysql_conn->key) == 0) ? NULL : mysql_conn->key,
				(strlen(mysql_conn->cert) == 0) ? NULL : mysql_conn->cert,
				(strlen(mysql_conn->ca) == 0) ? NULL : mysql_conn->ca,
				(strlen(mysql_conn->capath) == 0) ? NULL : mysql_conn->capath,
				(strlen(mysql_conn->cipher) == 0) ? NULL : mysql_conn->cipher);
	/* if we give a "no-value" value to a parameter, the default will be used,
		and we've initialized these values as empty strings or zero */
	if (!mysql_real_connect(&mysql,	mysql_conn->host,
					mysql_conn->user,
					mysql_conn->pass,
					mysql_conn->db,
					mysql_conn->port,
					(strlen(mysql_conn->socket) == 0 ) ? NULL : mysql_conn->socket,	/* this can not be given as an empty string */
					0)) {
		syslog(LOG_ERR, "mysql: error connecting to %s(%s): %s", mysql_conn->host, mysql_conn->db, mysql_error(&mysql));
		return;
	}
	syslog(LOG_INFO, "mysql: connected to %s(%s)", mysql_conn->host, mysql_conn->db);


	/* escape the provided parameters */
	user_col_escaped = malloc(strlen(mysql_conn->user_col) * 2 + 1); malloc_check(user_col_escaped);
	mysql_real_escape_string(&mysql, user_col_escaped, mysql_conn->user_col, strlen(mysql_conn->user_col));

	pass_col_escaped = malloc(strlen(mysql_conn->pass_col) * 2 + 1); malloc_check(pass_col_escaped);
	mysql_real_escape_string(&mysql, pass_col_escaped, mysql_conn->pass_col, strlen(mysql_conn->pass_col));

	scheme_col_escaped = malloc(strlen(mysql_conn->scheme_col) * 2 + 1); malloc_check(scheme_col_escaped);
	mysql_real_escape_string(&mysql, scheme_col_escaped, mysql_conn->scheme_col, strlen(mysql_conn->scheme_col));

	table_escaped = malloc(strlen(mysql_conn->table) * 2 + 1); malloc_check(table_escaped);
	mysql_real_escape_string(&mysql, table_escaped, mysql_conn->table, strlen(mysql_conn->table));

	strlcpy(username, got_username, MAX_USERNAME);
	username_escaped = malloc(strlen(username) * 2 + 1); malloc_check(username_escaped);
	mysql_real_escape_string(&mysql, username_escaped, username, strlen(username));

	/* fill the template sql command with the required fields */
	snprintf(query_cmd, MAX_QUERY_CMD, query_tpl, pass_col_escaped, scheme_col_escaped, table_escaped, user_col_escaped, username_escaped);

	free(user_col_escaped); user_col_escaped = NULL;
	free(pass_col_escaped); pass_col_escaped = NULL;
	free(scheme_col_escaped); scheme_col_escaped = NULL;
	free(table_escaped); table_escaped = NULL;
	free(username_escaped); username_escaped = NULL;

	/* execute the query */
	if (mysql_query(&mysql, query_cmd) != 0) {
		syslog(LOG_ERR, "mysql: error executing query: %s", mysql_error(&mysql));
		mysql_close(&mysql);
		return;
	}

	mysql_result = mysql_store_result(&mysql);
	if (!mysql_result) {
		syslog(LOG_ERR, "mysql: query returned no result");

		mysql_close(&mysql);
		return;
	}

	mysql_numrows = mysql_num_rows(mysql_result);
	if (mysql_numrows < 1) {
		syslog(LOG_ERR, "mysql: query returned no rows!");

		mysql_free_result(mysql_result);
		mysql_close(&mysql);
		return;
	}
	if (mysql_numrows > 1) {
		syslog(LOG_ERR, "mysql: query returned more than one rows!");

		mysql_free_result(mysql_result);
		mysql_close(&mysql);
		return;
	}

	if ((mysql_row = mysql_fetch_row(mysql_result))) {
		mysql_lengths = mysql_fetch_lengths(mysql_result);
		if ( mysql_lengths == NULL ) {
			syslog(LOG_ERR, "mysql: error getting column lengths: %s", mysql_error(&mysql));

			mysql_free_result(mysql_result);
			mysql_close(&mysql);
			return;
		}

		if ( mysql_lengths[0] > 0 )
			/* write the queried password to the 'password' variable */
			strlcpy(password, mysql_row[0], MAX_PASSWORD);

		if ( mysql_lengths[1] > 0 ) {
			/* if the field is empty or NULL, we use the globally
			 * defined digest_alg from the configuration file else,
			 * write the queried scheme to the 'digest_alg' variable
			 */
			strlcpy(digest_alg, mysql_row[1], MAX_PARAM);
	}

	mysql_free_result(mysql_result);
	mysql_close(&mysql);
} /* void mysql_check() */
#endif
