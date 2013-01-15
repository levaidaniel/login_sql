#ifndef _MYSQL_CHECK_H
#define _MYSQL_CHECK_H

#include <sys/syslimits.h>


typedef struct mysql_connection {
	char		host[MAX_PARAM];
	char		socket[MAX_PARAM];
	unsigned int	port;
	char		db[MAX_PARAM];
	char		user[MAX_PARAM];
	char		pass[MAX_PARAM];
	char		table[MAX_PARAM];
	char		user_col[MAX_PARAM];
	char		pass_col[MAX_PARAM];
	char		scheme_col[MAX_PARAM];
	char		key[PATH_MAX];
	char		cert[PATH_MAX];
	char		ca[PATH_MAX];
	char		capath[PATH_MAX];
	char		cipher[PATH_MAX];
} mysql_connection;

void	mysql_check(const char *, char *, char *, mysql_connection *);

#endif
