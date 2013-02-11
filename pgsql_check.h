#ifndef _PGSQL_CHECK_H
#define _PGSQL_CHECK_H

#define	CONFIG_PGSQL_DBCONNECTION	"pgsql_dbconnection="


typedef struct config_pgsql {
	char	dbconnection[MAX_PARAM + 1];
} config_pgsql;


char	pgsql_check(const char *, char *, config_global *, config_pgsql *);

#endif
