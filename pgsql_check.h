#ifndef _PGSQL_CHECK_H
#define _PGSQL_CHECK_H

typedef struct pgsql_connection {
	char	dbconnection[MAX_CFG_LINE];
	char	table[MAX_PARAM];
	char	user_col[MAX_PARAM];
	char	pass_col[MAX_PARAM];
	char	scheme_col[MAX_PARAM];
	char	host[MAX_PARAM];
	char	db[MAX_PARAM];
} pgsql_connection;

void	pgsql_check(const char *, char *, char *, pgsql_connection *);

#endif
