#ifndef _SQLITE_CHECK_H
#define _SQLITE_CHECK_H

#include <sys/syslimits.h>


typedef struct sqlite_connection {
	char	database[PATH_MAX];
	char	table[MAX_PARAM];
	char	user_col[MAX_PARAM];
	char	pass_col[MAX_PARAM];
	char	scheme_col[MAX_PARAM];
} sqlite_connection;

void	sqlite_check(const char *, char *, char *, sqlite_connection *);

#endif
