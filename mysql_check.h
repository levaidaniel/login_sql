#ifndef _MYSQL_CHECK_H
#define _MYSQL_CHECK_H

#include <sys/param.h>


#define	CONFIG_MYSQL_KEY	"mysql_key="
#define	CONFIG_MYSQL_CERT	"mysql_cert="
#define	CONFIG_MYSQL_CA		"mysql_ca="
#define	CONFIG_MYSQL_CAPATH	"mysql_capath="
#define	CONFIG_MYSQL_CIPHER	"mysql_cipher="


typedef struct config_mysql {
	char	key[MAXPATHLEN];
	char	cert[MAXPATHLEN];
	char	ca[MAXPATHLEN];
	char	capath[MAXPATHLEN];
	char	cipher[MAX_PARAM];
} config_mysql;


char	mysql_check(const char *, char *, config_global *, config_mysql *);

#endif
