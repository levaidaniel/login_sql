LOCALBASE ?=	/usr/local

BINGRP =	auth
BINDIR =	${LOCALBASE}/libexec/auth
PROG =		login_sql

MANDIR =	${LOCALBASE}/man/cat
MAN =		login_sql.8

DOCDIR =	${LOCALBASE}/share/doc/login_sql
DOC =		README


SRCS =		login_sql.c sql_check.c malloc_check.c
.ifdef PGSQL_BACKEND
SRCS +=		pgsql_check.c
.endif
.ifdef MYSQL_BACKEND
SRCS +=		mysql_check.c
.endif
.ifdef SQLITE_BACKEND
SRCS +=		sqlite_check.c
.endif


CFLAGS +=	-pedantic -Wall -g
.ifdef PGSQL_BACKEND
CFLAGS +=	-I`pg_config --includedir` `pg_config --cflags` -D_PGSQL_BACKEND
.endif
.ifdef MYSQL_BACKEND
CFLAGS +=	`mysql_config --cflags` -D_MYSQL_BACKEND
.endif
.ifdef SQLITE_BACKEND
CFLAGS +=	-D_SQLITE_BACKEND
.endif


LDADD +=	-lcrypto
.ifdef PGSQL_BACKEND
LDADD +=	-L`pg_config --libdir`
LDADD +=	-lpq `pg_config --libs`
.endif
.ifdef MYSQL_BACKEND
LDADD +=	`mysql_config --libs`
.endif
.ifdef SQLITE_BACKEND
LDADD +=	-lsqlite3
.endif


beforeinstall:
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} \
		${DESTDIR}${BINDIR}
	${INSTALL} -d -o ${DOCOWN} -g ${DOCGRP} -m ${DIRMODE} \
		${DESTDIR}${DOCDIR}

afterinstall:
	${INSTALL} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${DOC} ${DESTDIR}${DOCDIR}/

.include <bsd.prog.mk>
