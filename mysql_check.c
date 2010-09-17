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

#ifdef MYSQL_BACKEND

#include <mysql.h>

#include "common.h"
#include "sql_check.h"
#include "mysql_check.h"


extern char	*config_file;


void
mysql_check(const char *got_username, char password[], mysql_connection *mysql_conn)
{
MYSQL		mysql;

char		*user_col_escaped = NULL, *pass_col_escaped = NULL, *table_escaped = NULL;
const char	*query_tpl = "SELECT %s FROM %s WHERE %s = '%s';";
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
		syslog(LOG_ERR, "error connecting to mysql: %s", mysql_error(&mysql));
		return;
	}

        /* escape the provided parameters */                                                                                               
	user_col_escaped = malloc(strlen(mysql_conn->user_col) * 2 + 1);                                                                
	//PQescapeStringConn(pg_conn, pg_user_col_escaped, mysql_conn->user_col, sizeof(mysql_conn->user_col), NULL);                        
					   
	pass_col_escaped = malloc(strlen(mysql_conn->pass_col) * 2 + 1);                                                                
	//PQescapeStringConn(pg_conn, pg_pass_col_escaped, mysql_conn->pass_col, sizeof(mysql_conn->pass_col), NULL);                        
							   
	table_escaped = malloc(strlen(mysql_conn->table) * 2 + 1);                                                                      
	//PQescapeStringConn(pg_conn, pg_table_escaped, mysql_conn->table, sizeof(mysql_conn->table), NULL);                                 
									   
	strlcpy(username, got_username, MAX_USERNAME);                                                                                     
	username_escaped = malloc(strlen(username) * 2 + 1);                                                                               
	//PQescapeStringConn(pg_conn, username_escaped, username, sizeof(username), NULL);                                                   
												   
	/* fill the template sql command with the required fields */                                                                       
	snprintf(query_cmd, MAX_QUERY_CMD, query_tpl, pass_col_escaped, table_escaped, user_col_escaped, username_escaped); 
													   
	free(user_col_escaped);                                                                                                         
	free(pass_col_escaped);                                                                                                         
	free(table_escaped);                                                                                                            
	free(username_escaped);
	mysql_query(&mysql, query_cmd);

	mysql_close(&mysql);
} /* void mysql_check() */
#endif
