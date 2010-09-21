LOCALBASE?=	/usr/local

BINOWN=		root
BINGRP=		auth
BINDIR=		${LOCALBASE}/libexec/auth
PROG=		login_sql

MANDIR=		${LOCALBASE}/man/cat
MAN=		login_sql.8

DOCOWN=		root
DOCGRP=		bin
DOCDIR=		${LOCALBASE}/share/doc/login_sql
DOC=		README


SUBDIR+=	blowcrypt

PGSQL_BACKEND?=
MYSQL_BACKEND?=

SRCS=		login_sql.c sql_check.c malloc_check.c
.if ${PGSQL_BACKEND:L:My} || ${PGSQL_BACKEND:L:Myes}
SRCS+=		pgsql_check.c
.endif
.if ${MYSQL_BACKEND:L:My} || ${MYSQL_BACKEND:L:Myes}
SRCS+=		mysql_check.c
.endif

CFLAGS+=	-Wall

LDADD+=		-lcrypto -lssl -lcom_err

.if ${PGSQL_BACKEND:L:My} || ${PGSQL_BACKEND:L:Myes}
CFLAGS+=	-I`pg_config --includedir` `pg_config --cflags` -DPGSQL_BACKEND
.endif
.if ${PGSQL_BACKEND:L:My} || ${PGSQL_BACKEND:L:Myes}
LDADD+=		-L`pg_config --libdir`
LDADD+=		-lpq `pg_config --libs`
.endif

.if ${MYSQL_BACKEND:L:My} || ${MYSQL_BACKEND:L:Myes}
CFLAGS+=	`mysql_config --cflags` -DMYSQL_BACKEND
.endif
.if ${MYSQL_BACKEND:L:My} || ${MYSQL_BACKEND:L:Myes}
LDADD+=		`mysql_config --libs`
.endif


CLEANFILES+=	*.cat[0-9]


all: ${PROG}

${PROG}: ${SRCS}
	${CC} -o ${PROG} ${CFLAGS} ${LDADD} \
		${SRCS}

beforeinstall:
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} \
		${DESTDIR}${BINDIR}
	${INSTALL} -d -o ${DOCOWN} -g ${DOCGRP} -m ${DIRMODE} \
		${DESTDIR}${DOCDIR}

afterinstall:
	${INSTALL} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${DOC} ${DESTDIR}${DOCDIR}/

.include <bsd.prog.mk>
