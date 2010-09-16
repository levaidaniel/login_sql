#ifndef SQL_CHECK_H
#define SQL_CHECK_H 

#define		MAX_PG_QUERY_CMD	512
#define		MAX_CFG_LINE		128
#define		MAX_USERNAME		256
#define		MAX_PASSWORD		256

#define		CONFIG_FILE_DEFAULT	"/etc/login_sql.conf"

int		sql_check(const char *got_username, const char *got_password);
void		pgsql_check(const char *got_username);
void		mysql_check(const char *got_username);

#endif
