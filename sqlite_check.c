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

#ifdef _SQLITE_BACKEND

#include <sqlite3.h>

#include "common.h"
#include "sql_check.h"
#include "sqlite_check.h"


int sqlite_cb(void *, int, char *[], char *[]);


void
sqlite_check(const char *got_username, char *password,
		char *digest_alg, sqlite_connection *sqlite_conn)
{
	sqlite3		*db = NULL;
	sqlite3_stmt	*query_prepared;

	int		result = -1;
	const char	*query_tpl = "SELECT %q, %q FROM %q WHERE %q = '%q'";
	char		query_cmd[MAX_QUERY_CMD] = "";


	if (sqlite3_open(sqlite_conn->database, &db)) {
		syslog(LOG_ERR, "sqlite: can not open database %s: %s", sqlite_conn->database, sqlite3_errmsg(db));

		sqlite3_close(db);
		return;
	}
	syslog(LOG_INFO, "sqlite: opened database(%s)", sqlite_conn->database);

	/* Fill the template sql command with the required fields.
	 * Escaping done by the %q format character of sqlite3_snprintf().
	 */
	sqlite3_snprintf(MAX_QUERY_CMD, query_cmd, query_tpl, sqlite_conn->pass_col, sqlite_conn->scheme_col, sqlite_conn->table, sqlite_conn->user_col, got_username);

	/* We will write the queried password to the 'password' variable
	 * in the callback function.
	 */
	if (sqlite3_prepare_v2(db, query_cmd, MAX_QUERY_CMD, &query_prepared, NULL) != SQLITE_OK) {
		syslog(LOG_ERR, "sqlite: error preparing statement: %s\n", sqlite3_errmsg(db));

		sqlite3_close(db);
		return;
	}
	if (!query_prepared) {
		syslog(LOG_ERR, "sqlite: error preparing statement: %s\n", sqlite3_errmsg(db));

		sqlite3_close(db);
		return;
	}

	result = sqlite3_step(query_prepared);
	switch (result) {
		case SQLITE_ROW:
			if (sqlite3_column_text(query_prepared, 0) != NULL)
				if (strlen((const char *)sqlite3_column_text(query_prepared, 0)) > 0)
					/* write the queried password to the 'password' variable */
					strlcpy(password, (const char *)sqlite3_column_text(query_prepared, 0), MAX_PASSWORD);

			if (sqlite3_column_text(query_prepared, 1) != NULL)
				if (strlen((const char *)sqlite3_column_text(query_prepared, 1)) > 0)
					/* if the field is NULL or empty, we use the globally
					 * defined digest_alg from the configuration file otherwise,
					 * write the queried scheme to the 'digest_alg' variable
					 */
					strlcpy(digest_alg, (const char *)sqlite3_column_text(query_prepared, 1), MAX_PARAM);
			break;
		case SQLITE_DONE:
			syslog(LOG_ERR, "sqlite: query returned no rows!\n");
			break;
		default:
			syslog(LOG_ERR, "sqlite: unknown error code(%d): %s\n", result, sqlite3_errmsg(db));
			break;
	}
	/* if there are more results (rows) */
	if (sqlite3_step(query_prepared) == SQLITE_ROW) {
		syslog(LOG_ERR, "sqlite: query returned more than one rows!\n");
		memset(password, '\0', MAX_PASSWORD);

		sqlite3_finalize(query_prepared);
		sqlite3_close(db);
		return;
	}

	sqlite3_finalize(query_prepared);
	sqlite3_close(db);
} /* void sqlite_check() */
#endif
