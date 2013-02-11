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

#include <sqlite3.h>

#include "common.h"
#include "sql_check.h"
#include "sqlite_check.h"


char	sqlite_quit(sqlite3 *, sqlite3_stmt *, char);


char
sqlite_check(const char *got_username, char *password,
		config_global *cfg)
{
	sqlite3		*db = NULL;
	sqlite3_stmt	*query_prepared = NULL;

	int		result = -1;
	const char	*query_tpl = "SELECT %q, %q FROM %q WHERE %q = '%q' and %q = 1; --";
	char		query_cmd[MAX_QUERY_CMD + 1] = "";


	if (sqlite3_open(cfg->db_name, &db)) {
		syslog(LOG_ERR, "sqlite: can not open database %s: %s",
			cfg->db_name, sqlite3_errmsg(db));

		return(sqlite_quit(db, query_prepared, 0));
	}
	syslog(LOG_INFO, "sqlite: opened database(%s)", cfg->db_name);

	/* Fill the template sql command with the required fields.
	 * Escaping done by the %q format character of sqlite3_snprintf().
	 */
	sqlite3_snprintf(sizeof(query_cmd), query_cmd, query_tpl,
				cfg->column_password, cfg->column_scheme, cfg->db_table,
				cfg->column_username, got_username,
				strlen(cfg->column_enabled) ? cfg->column_enabled : "1");


	if (sqlite3_prepare_v2(db, query_cmd, strlen(query_cmd), &query_prepared, NULL) != SQLITE_OK) {
		syslog(LOG_ERR, "sqlite: error preparing statement: %s",
			sqlite3_errmsg(db));

		return(sqlite_quit(db, query_prepared, 0));
	}
	if (!query_prepared) {
		syslog(LOG_ERR, "sqlite: error preparing statement: %s",
			sqlite3_errmsg(db));

		return(sqlite_quit(db, query_prepared, 0));
	}

	result = sqlite3_step(query_prepared);
	switch (result) {
		case SQLITE_ROW:
		/*
		 * This must be the only place in the switch()
		 * where we don't quit from sqlite_check().
		 */
			if (sqlite3_column_text(query_prepared, 0) != NULL)
				if (strlen((const char *)sqlite3_column_text(query_prepared, 0)) > 0)
					/* write the queried password to the 'password' variable */
					strlcpy(password,
						(const char *)sqlite3_column_text(query_prepared, 0),
						MAX_PASSWORD + 1);

			if (sqlite3_column_text(query_prepared, 1) != NULL)
				if (strlen((const char *)sqlite3_column_text(query_prepared, 1)) > 0)
					/* if the field is NULL or empty, we use the globally
					 * defined password scheme from the configuration file otherwise,
					 * write the queried scheme to the 'cfg->pw_scheme' variable
					 */
					strlcpy(cfg->pw_scheme,
						(const char *)sqlite3_column_text(query_prepared, 1),
						sizeof(cfg->pw_scheme));
			break;
		case SQLITE_DONE:
			syslog(LOG_ERR, "sqlite: query returned no row!");

			return(sqlite_quit(db, query_prepared, 0));
			break;
		default:
			syslog(LOG_ERR, "sqlite: unknown error code(%d): %s",
				result, sqlite3_errmsg(db));

			return(sqlite_quit(db, query_prepared, 0));
			break;
	}
	/* if there are more results (rows) */
	if (sqlite3_step(query_prepared) == SQLITE_ROW) {
		syslog(LOG_ERR, "sqlite: query returned more than one row!");

		return(sqlite_quit(db, query_prepared, 0));
	} else
		/*
		 * This is the only place where we would give back AUTH_OK
		 */
		return(sqlite_quit(db, query_prepared, 1));


	return(sqlite_quit(db, query_prepared, 0));
} /* sqlite_check() */

char
sqlite_quit(sqlite3 *db, sqlite3_stmt *query_prepared, char retval)
{
	if (query_prepared)
		sqlite3_finalize(query_prepared);

	sqlite3_close(db);

	return(retval);
} /* sqlite_quit() */
