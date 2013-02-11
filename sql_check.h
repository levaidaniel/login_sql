#ifndef _SQL_CHECK_H
#define _SQL_CHECK_H

#include <sys/param.h>


#define		MAX_QUERY_CMD		512
#define		MAX_CONFIG_LINE		MAXPATHLEN + 32
#define		MAX_PARAM		128
#define		MAX_USERNAME		128
#define		MAX_PASSWORD		128

#define		CRYPT_SALT_LEN		29
#define		SSHA_SALT_LEN		4

#define		CONFIG_FILE_DEFAULT		"/etc/login_sql.conf"

#define		CONFIG_GLOBAL_SQL_BACKEND	"sql_backend="

#define		CONFIG_GLOBAL_DB_HOST		"db_host="
#define		CONFIG_GLOBAL_DB_PORT		"db_port="
#define		CONFIG_GLOBAL_DB_NAME		"db_name="
#define		CONFIG_GLOBAL_DB_USERNAME	"db_username="
#define		CONFIG_GLOBAL_DB_PASSWORD	"db_password="
#define		CONFIG_GLOBAL_DB_TABLE		"db_table="

#define		CONFIG_GLOBAL_COLUMN_USERNAME	"column_username="
#define		CONFIG_GLOBAL_COLUMN_PASSWORD	"column_password="
#define		CONFIG_GLOBAL_COLUMN_SCHEME	"column_scheme="
#define		CONFIG_GLOBAL_COLUMN_ENABLED	"column_enabled="

#define		CONFIG_GLOBAL_PW_SCHEME		"pw_scheme="

#define		CONFIG_GLOBAL_EMPTY_PASSWORD	"empty_password="


char	sql_check(const char *, const char *, const char *);


typedef struct config_global {
	char	sql_backend[MAX_PARAM + 1];

	char	db_host[MAX_PARAM + 1];
	int	db_port;
	char	db_name[MAXPATHLEN + 1];
	char	db_username[MAX_PARAM + 1];
	char	db_password[MAX_PARAM + 1];
	char	db_table[MAX_PARAM + 1];

	char	column_username[MAX_PARAM + 1];
	char	column_password[MAX_PARAM + 1];
	char	column_scheme[MAX_PARAM + 1];
	char	column_enabled[MAX_PARAM + 1];

	char	pw_scheme[MAX_PARAM + 1];

	char	empty_password[MAX_PARAM + 1];
} config_global;

#endif
