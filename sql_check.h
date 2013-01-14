#ifndef _SQL_CHECK_H
#define _SQL_CHECK_H 

#define		MAX_QUERY_CMD		512
#define		MAX_CFG_LINE		1024
#define		MAX_PARAM		64
#define		MAX_USERNAME		256
#define		MAX_PASSWORD		256

#define		CFG_FILE_DEFAULT	"/etc/login_sql.conf"

#define		CFG_PARAM_PGSQL_DBCONNECTION	"pgsql_dbconnection="
#define		CFG_PARAM_PGSQL_TABLE		"pgsql_table="
#define		CFG_PARAM_PGSQL_USER_COL	"pgsql_user_col="
#define		CFG_PARAM_PGSQL_PASS_COL	"pgsql_pass_col="
#define		CFG_PARAM_PGSQL_SCHEME_COL	"pgsql_scheme_col="

#define		CFG_PARAM_MYSQL_HOST		"mysql_host="
#define		CFG_PARAM_MYSQL_PORT		"mysql_port="
#define		CFG_PARAM_MYSQL_DB		"mysql_db="
#define		CFG_PARAM_MYSQL_USER		"mysql_user="
#define		CFG_PARAM_MYSQL_PASS		"mysql_pass="
#define		CFG_PARAM_MYSQL_TABLE		"mysql_table="
#define		CFG_PARAM_MYSQL_USER_COL	"mysql_user_col="
#define		CFG_PARAM_MYSQL_PASS_COL	"mysql_pass_col="
#define		CFG_PARAM_MYSQL_SCHEME_COL	"mysql_scheme_col="
#define		CFG_PARAM_MYSQL_KEY		"mysql_key="
#define		CFG_PARAM_MYSQL_CERT		"mysql_cert="
#define		CFG_PARAM_MYSQL_CA		"mysql_ca="
#define		CFG_PARAM_MYSQL_CAPATH		"mysql_capath="
#define		CFG_PARAM_MYSQL_CIPHER		"mysql_cipher="

#define		CFG_PARAM_DIGEST_ALG		"digest_alg="
#define		CFG_PARAM_SQL_BACKEND		"sql_backend="

#define		BLOWFISH_SALT_LEN		29

int		sql_check(const char *, const char *, const char *);

#endif
