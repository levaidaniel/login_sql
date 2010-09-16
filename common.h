#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "sql_check.h"

#define		LOGIN_SQL_VERSION	"0.9"

#define		MAX_PG_PARAM		32
