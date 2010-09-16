#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "pgsql_check.h"

#define		VERSION			"0.9"

#define		MAX_PG_PARAM		32
