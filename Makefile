PROG=		login_-sql
SRCS=		login_sql.c sql_check.c
OBJ=		login_sql.o sql_check.o
MAN=		login_sql.8
DOCS=		README

DOCDIR=		$(LOCALBASE)/share/doc/login_sql
MANDIR=		$(LOCALBASE)/man/cat
BINDIR=		$(LOCALBASE)/libexec/auth

SQL_BACKEND?=

CFLAGS+=	-Wall
.if ${SQL_BACKEND:L:Mpgsql}
CFLAGS+=	-I`pg_config --includedir` -DPGSQL_BACKEND
.elif ${SQL_BACKEND:L:Mmysql}
CFLAGS+=	`mysql_config --include` -DMYSQL_BACKEND
.endif


LDADD+=		-lcrypto -lssl -lcom_err
.if ${SQL_BACKEND:L:Mpgsql}
LDADD+=		-L`pg_config --libdir`
LDADD+=		-lpq
.elif ${SQL_BACKEND:L:Mmysql}
LDADD+=		`mysql_config --libs`
.endif

CLEANFILES+=	*.cat[0-9]


all: ${PROG}

${OBJ}: ${SRCS}
	${CC} -c ${CFLAGS} ${SRCS}

${PROG}: ${OBJ}
	${CC} -o ${PROG} ${CFLAGS} ${LDADD} \
		${OBJ}

beforeinstall:
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} \
		${DESTDIR}${BINDIR}
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} \
		${DESTDIR}${DOCDIR}

afterinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
		-m 444 ${DOCS} ${DESTDIR}${DOCDIR}/

.include <bsd.prog.mk>
