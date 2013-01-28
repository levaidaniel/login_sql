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

#include <mysql.h>

#include "common.h"
#include "sql_check.h"
#include "mysql_check.h"


char	mysql_quit(MYSQL *, MYSQL_RES *, char);


char
mysql_check(const char *got_username, char *password,
		config_global *cfg, config_mysql *cfg_mysql)
{
	MYSQL		mysql;
	MYSQL_RES	*mysql_result = NULL;
	MYSQL_ROW	mysql_row;
	my_ulonglong	mysql_numrows = 0;
	unsigned long	*mysql_lengths = NULL;

	char		*user_col_escaped = NULL, *pass_col_escaped = NULL,
			*scheme_col_escaped = NULL, *enabled_col_escaped = NULL,
			*table_escaped = NULL;
	const char	*query_tpl = "SELECT %s, %s FROM %s WHERE %s = '%s' and %s = 1; --";
	char		query_cmd[MAX_QUERY_CMD] = "";

	char		username[MAX_USERNAME] = "";
	char		*username_escaped = NULL;


	mysql_init(&mysql);

	/* try to start an ssl connection later. any unused SSL parameters may be given as NULL */
	mysql_ssl_set(&mysql,	(strlen(cfg_mysql->key) == 0) ? NULL : cfg_mysql->key,
				(strlen(cfg_mysql->cert) == 0) ? NULL : cfg_mysql->cert,
				(strlen(cfg_mysql->ca) == 0) ? NULL : cfg_mysql->ca,
				(strlen(cfg_mysql->capath) == 0) ? NULL : cfg_mysql->capath,
				(strlen(cfg_mysql->cipher) == 0) ? NULL : cfg_mysql->cipher);

	if (!mysql_real_connect(&mysql,	cfg->db_host[0] != '/' ? cfg->db_host : NULL,	/* if NULL or "localhost", connect to Unix socket */
					cfg->db_username,
					cfg->db_password,
					cfg->db_name,
					cfg->db_port,
					cfg->db_host[0] == '/' ? cfg->db_host : NULL,	/* If this resembles an absolute path, then treat it as a socket */
					0)) {

		syslog(LOG_ERR, "mysql: error connecting to %s(%s): %s",
			cfg->db_host, cfg->db_name, mysql_error(&mysql));

		return(0);
	}
	syslog(LOG_INFO, "mysql: connected to %s(%s)", cfg->db_host, cfg->db_name);


	/* escape the provided parameters */
	user_col_escaped = malloc(strlen(cfg->column_username) * 2 + 1); malloc_check(user_col_escaped);
	mysql_real_escape_string(&mysql, user_col_escaped, cfg->column_username, strlen(cfg->column_username));

	pass_col_escaped = malloc(strlen(cfg->column_password) * 2 + 1); malloc_check(pass_col_escaped);
	mysql_real_escape_string(&mysql, pass_col_escaped, cfg->column_password, strlen(cfg->column_password));

	scheme_col_escaped = malloc(strlen(cfg->column_scheme) * 2 + 1); malloc_check(scheme_col_escaped);
	mysql_real_escape_string(&mysql, scheme_col_escaped, cfg->column_scheme, strlen(cfg->column_scheme));

	if (strlen(cfg->column_enabled)) {
		enabled_col_escaped = malloc(strlen(cfg->column_enabled) * 2 + 1); malloc_check(enabled_col_escaped);
		mysql_real_escape_string(&mysql, enabled_col_escaped, cfg->column_enabled, strlen(cfg->column_enabled));
	}

	table_escaped = malloc(strlen(cfg->db_table) * 2 + 1); malloc_check(table_escaped);
	mysql_real_escape_string(&mysql, table_escaped, cfg->db_table, strlen(cfg->db_table));

	strlcpy(username, got_username, MAX_USERNAME);
	username_escaped = malloc(strlen(username) * 2 + 1); malloc_check(username_escaped);
	mysql_real_escape_string(&mysql, username_escaped, username, strlen(username));

	/* fill the template sql command with the required fields */
	snprintf(query_cmd, MAX_QUERY_CMD, query_tpl,
			pass_col_escaped, scheme_col_escaped, table_escaped,
			user_col_escaped, username_escaped,
			strlen(cfg->column_enabled) ? enabled_col_escaped : "1");

	free(user_col_escaped); user_col_escaped = NULL;
	free(pass_col_escaped); pass_col_escaped = NULL;
	free(scheme_col_escaped); scheme_col_escaped = NULL;
	free(enabled_col_escaped); enabled_col_escaped = NULL;
	free(table_escaped); table_escaped = NULL;
	free(username_escaped); username_escaped = NULL;

	/* execute the query */
	if (mysql_query(&mysql, query_cmd) != 0) {
		syslog(LOG_ERR, "mysql: error executing query: %s", mysql_error(&mysql));

		return(mysql_quit(&mysql, mysql_result, 0));
	}

	mysql_result = mysql_store_result(&mysql);
	if (!mysql_result) {
		syslog(LOG_ERR, "mysql: query returned no result");

		return(mysql_quit(&mysql, mysql_result, 0));
	}

	mysql_numrows = mysql_num_rows(mysql_result);
	if (mysql_numrows < 1) {
		syslog(LOG_ERR, "mysql: query returned no row!");

		return(mysql_quit(&mysql, mysql_result, 0));
	}
	if (mysql_numrows > 1) {
		syslog(LOG_ERR, "mysql: query returned more than one row!");

		return(mysql_quit(&mysql, mysql_result, 0));
	}

	/* Got what we wanted, this is the only place
	 * where we would give back AUTH_OK
	 */
	if ((mysql_row = mysql_fetch_row(mysql_result))) {
		mysql_lengths = mysql_fetch_lengths(mysql_result);
		if (mysql_lengths == NULL) {
			syslog(LOG_ERR, "mysql: error getting column lengths: %s",
				mysql_error(&mysql));

			return(mysql_quit(&mysql, mysql_result, 0));
		}

		if (mysql_lengths[0] > 0)
			/* write the queried password to the 'password' variable */
			strlcpy(password, mysql_row[0], MAX_PASSWORD);

		if (mysql_lengths[1] > 0)
			/* if the field is empty or NULL, we use the globally
			 * defined password scheme from the configuration file else,
			 * write the queried scheme to the 'cfg->pw_scheme' variable
			 */
			strlcpy(cfg->pw_scheme, mysql_row[1], MAX_PARAM);

		return(mysql_quit(&mysql, mysql_result, 1));
	}

	return(mysql_quit(&mysql, mysql_result, 0));
} /* mysql_check() */

char
mysql_quit(MYSQL *mysql, MYSQL_RES *mysql_result, char retval)
{
	if (mysql_result)
		mysql_free_result(mysql_result);

	mysql_close(&(*mysql));

	return(retval);
} /* mysql_quit() */
