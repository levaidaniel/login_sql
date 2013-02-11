#ifndef _MYSQL_CHECK_H
#define _MYSQL_CHECK_H

#include <sys/param.h>


#define	CONFIG_MYSQL_KEY	"mysql_key="
#define	CONFIG_MYSQL_CERT	"mysql_cert="
#define	CONFIG_MYSQL_CA		"mysql_ca="
#define	CONFIG_MYSQL_CAPATH	"mysql_capath="
#define	CONFIG_MYSQL_CIPHER	"mysql_cipher="


typedef struct config_mysql {
	char	key[MAXPATHLEN + 1];
	char	cert[MAXPATHLEN + 1];
	char	ca[MAXPATHLEN + 1];
	char	capath[MAXPATHLEN + 1];
	char	cipher[MAX_PARAM + 1];
} config_mysql;


char	mysql_check(const char *, char *, config_global *, config_mysql *);

#endif
