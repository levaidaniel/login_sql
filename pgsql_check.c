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

#include <libpq-fe.h>

#include "common.h"
#include "sql_check.h"
#include "pgsql_check.h"


char
pgsql_check(const char *got_username, char *password,
		config_global *cfg, config_pgsql *cfg_pgsql)
{
	PGconn		*pg_conn = NULL;

	PGresult	*pg_result = NULL;
	ExecStatusType	pg_result_status;

	int		pg_numrows = 0;

	char		dbconnection[MAX_PARAM * 3];

	char		*user_col_escaped = NULL, *pass_col_escaped = NULL,
			*scheme_col_escaped = NULL, *enabled_col_escaped = NULL,
			*table_escaped = NULL;
	const char	*query_tpl = "SELECT %s, %s FROM %s WHERE %s = '%s' and %s = true; --";
	char		query_cmd[MAX_QUERY_CMD] = "";

	char		username[MAX_USERNAME] = "";
	char		*username_escaped = NULL;


	/* Construct the PostgreSQL conninfo string from the given database parameters,
	 * and append the extra 'dbconnection=' configuration parameter's value.
	 */
	snprintf(dbconnection, sizeof(dbconnection),
			"host=%s port=%u dbname=%s user=%s password=%s %s",
			cfg->db_host, cfg->db_port, cfg->db_name, cfg->db_username, cfg->db_password,
			cfg_pgsql->dbconnection);

	/* connect to the postgresql server */
	pg_conn = PQconnectdb(dbconnection);

	switch (PQstatus(pg_conn)) {
		case CONNECTION_OK:
			break;
		case CONNECTION_BAD:
			syslog(LOG_ERR, "pgsql: connection is not complete to %s(%s)!\n\t%s",
				cfg->db_host, cfg->db_name, PQerrorMessage(pg_conn));

			PQfinish(pg_conn);
			return(0);
		default:
			syslog(LOG_ERR, "pgsql: connection state is unknown when connecting to %s(%s)!\n\t%s",
				cfg->db_host, cfg->db_name, PQerrorMessage(pg_conn));

			return(0);
	}
	syslog(LOG_INFO, "pgsql: connected to %s(%s)", cfg->db_host, cfg->db_name);


	/* escape the provided parameters */
	user_col_escaped = malloc(strlen(cfg->column_username) * 2 + 1); malloc_check(user_col_escaped);
	PQescapeStringConn(pg_conn, user_col_escaped, cfg->column_username, strlen(cfg->column_username), NULL);

	pass_col_escaped = malloc(strlen(cfg->column_password) * 2 + 1); malloc_check(pass_col_escaped);
	PQescapeStringConn(pg_conn, pass_col_escaped, cfg->column_password, strlen(cfg->column_password), NULL);

	scheme_col_escaped = malloc(strlen(cfg->column_scheme) * 2 + 1); malloc_check(scheme_col_escaped);
	PQescapeStringConn(pg_conn, scheme_col_escaped, cfg->column_scheme, strlen(cfg->column_scheme), NULL);

	if (strlen(cfg->column_enabled)) {
		enabled_col_escaped = malloc(strlen(cfg->column_enabled) * 2 + 1); malloc_check(enabled_col_escaped);
		PQescapeStringConn(pg_conn, enabled_col_escaped, cfg->column_enabled, strlen(cfg->column_enabled), NULL);
	}

	table_escaped = malloc(strlen(cfg->db_table) * 2 + 1); malloc_check(table_escaped);
	PQescapeStringConn(pg_conn, table_escaped, cfg->db_table, strlen(cfg->db_table), NULL);

	strlcpy(username, got_username, MAX_USERNAME);
	username_escaped = malloc(strlen(username) * 2 + 1); malloc_check(username_escaped);
	PQescapeStringConn(pg_conn, username_escaped, username, strlen(username), NULL);

	/* fill the template sql command with the required fields */
	snprintf(query_cmd, MAX_QUERY_CMD, query_tpl,
			pass_col_escaped, scheme_col_escaped, table_escaped,
			user_col_escaped, username_escaped,
			strlen(cfg->column_enabled) ? enabled_col_escaped : "true");

	free(user_col_escaped); user_col_escaped = NULL;
	free(pass_col_escaped); pass_col_escaped = NULL;
	free(scheme_col_escaped); scheme_col_escaped = NULL;
	free(enabled_col_escaped); enabled_col_escaped = NULL;
	free(table_escaped); table_escaped = NULL;
	free(username_escaped); username_escaped = NULL;

	/* execute the query */
	pg_result = PQexec(pg_conn, query_cmd);
	switch (pg_result_status = PQresultStatus(pg_result)) {
		case PGRES_TUPLES_OK:	/* this is what we want. we got back some data */
			pg_numrows = PQntuples(pg_result);
			if (pg_numrows < 1) {
				syslog(LOG_ERR, "pgsql: query returned no rows!");

				PQclear(pg_result);
				PQfinish(pg_conn);
				return(0);
			}
			if (pg_numrows > 1) {
				syslog(LOG_ERR, "pgsql: query returned more than one rows!");

				PQclear(pg_result);
				PQfinish(pg_conn);
				return(0);
			}

			if (	PQgetlength(pg_result, 0, 0) > 0  &&
				!PQgetisnull(pg_result, 0, 0))
				/* write the queried password to the 'password' variable */
				strlcpy(password, PQgetvalue(pg_result, 0, 0), MAX_PASSWORD);


			if (	PQgetlength(pg_result, 0, 1) > 0  &&
				!PQgetisnull(pg_result, 0, 1))
				/* if the field is empty or NULL, we use the globally
				 * defined password scheme from the configuration file else,
				 * write the queried scheme to the 'cfg->pw_scheme' variable
				 */
				strlcpy(cfg->pw_scheme, PQgetvalue(pg_result, 0, 1), MAX_PARAM);

			break;
		case PGRES_COMMAND_OK:
			syslog(LOG_ERR, "pgsql: command result OK(%s) - but no data has been returned!",
				PQresStatus(pg_result_status));

			PQclear(pg_result);
			PQfinish(pg_conn);
			return(0);
			break;
		case PGRES_EMPTY_QUERY:
			syslog(LOG_ERR, "pgsql: command result ERROR(%s) - empty command string.",
				PQresStatus(pg_result_status));

			PQclear(pg_result);
			PQfinish(pg_conn);
			return(0);
			break;
		case PGRES_BAD_RESPONSE:
			syslog(LOG_ERR, "pgsql: command result ERROR(%s) - bad response from server.",
				PQresStatus(pg_result_status));

			PQclear(pg_result);
			PQfinish(pg_conn);
			return(0);
			break;
		case PGRES_NONFATAL_ERROR:
			syslog(LOG_ERR, "pgsql: command result ERROR(%s) - non fatal error occured.",
				PQresStatus(pg_result_status));

			PQclear(pg_result);
			PQfinish(pg_conn);
			return(0);
			break;
		case PGRES_FATAL_ERROR:
			syslog(LOG_ERR, "pgsql: command result ERROR(%s) - fatal error occured.",
				PQresStatus(pg_result_status));

			PQclear(pg_result);
			PQfinish(pg_conn);
			return(0);
			break;
		default:
			syslog(LOG_ERR, "pgsql: command result unknown(%s)",
				PQresStatus(pg_result_status));

			PQclear(pg_result);
			PQfinish(pg_conn);
			return(0);
			break;
	}

	PQclear(pg_result);
	PQfinish(pg_conn);

	return(1);
} /* pgsql_check() */
