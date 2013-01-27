#ifndef _COMMON_H
#define _COMMON_H

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define	AUTH_OK		0
#define	AUTH_FAILED	-1

#define	VERSION	"1.4-dev"

void	malloc_check(void *);

#endif
