#ifndef _SQLITE_CHECK_H
#define _SQLITE_CHECK_H

typedef struct sqlite_connection {
	char	filename[MAX_CFG_LINE];
} sqlite_connection;

void	sqlite_check(const char *, char *, char *, sqlite_connection *);

#endif
