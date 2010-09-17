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

#include "common.h"
#include "sql_check.h"
#include "pgsql_check.h"


void
pgsql_check(const char *got_username, char password[], pgsql_connection *pgsql_conn)
{
PGconn		*pg_conn = NULL;

PGresult	*pg_result = NULL;
ExecStatusType	pg_result_status = 0;

int		pg_num_rows = 0;

char		*pg_user_col_escaped = NULL, *pg_pass_col_escaped = NULL, *pg_table_escaped = NULL;
const char	*pg_query_tpl = "SELECT %s FROM %s WHERE %s = '%s';";
char		pg_query_cmd[MAX_QUERY_CMD] = "";

char		username[MAX_USERNAME] = "";
char		*username_escaped = NULL;



	/* connect to the postgresql server */
	pg_conn = PQconnectdb(pgsql_conn->dbconnection);

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


	/* escape the provided parameters */
	pg_user_col_escaped = malloc(strlen(pgsql_conn->user_col) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_user_col_escaped, pgsql_conn->user_col, sizeof(pgsql_conn->user_col), NULL);

	pg_pass_col_escaped = malloc(strlen(pgsql_conn->pass_col) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_pass_col_escaped, pgsql_conn->pass_col, sizeof(pgsql_conn->pass_col), NULL);

	pg_table_escaped = malloc(strlen(pgsql_conn->table) * 2 + 1);
	PQescapeStringConn(pg_conn, pg_table_escaped, pgsql_conn->table, sizeof(pgsql_conn->table), NULL);

	strlcpy(username, got_username, MAX_USERNAME);
	username_escaped = malloc(strlen(username) * 2 + 1);
	PQescapeStringConn(pg_conn, username_escaped, username, sizeof(username), NULL);

	/* fill the template sql command with the required fields */
	snprintf(pg_query_cmd, MAX_QUERY_CMD, pg_query_tpl, pg_pass_col_escaped, pg_table_escaped, pg_user_col_escaped, username_escaped);

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
