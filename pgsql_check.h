#ifndef PGSQL_CHECK_H
#define PGSQL_CHECK_H 

#define		MAX_PG_QUERY_CMD	256

#define		CONFIG_FILE_DEFAULT	"/etc/login_pgsql.conf"

int		pgsql_check(const char *got_username, const char *got_password);

#endif
