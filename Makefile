PROG=		login_-pgsql
SRCS=		login_pgsql.c pgsql_check.c
OBJ=		login_pgsql.o pgsql_check.o
MAN=		login_pgsql.8
DOCS=		README

DOCDIR=		$(LOCALBASE)/share/doc/login_pgsql
MANDIR=		$(LOCALBASE)/man/cat
BINDIR=		$(LOCALBASE)/libexec/auth

CFLAGS+=	-Wall
PGSQL_INCLUDE!=	pg_config --includedir

LDADD+=		-lpq -lcrypto -lssl -lcom_err
PGSQL_LIB!=	pg_config --libdir

CLEANFILES+=	*.cat[0-9]


all: ${PROG}

${OBJ}: ${SRCS}
	${CC} -c -I${PGSQL_INCLUDE} ${CFLAGS} ${SRCS}

${PROG}: ${OBJ}
	${CC} -o ${PROG} -L${PGSQL_LIB} ${CFLAGS} ${LDADD} \
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
