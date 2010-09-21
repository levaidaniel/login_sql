LOCALBASE?=	/usr/local

PROG=		blowcrypt
SRCS=		blowcrypt.c
OBJ=		blowcrypt.o
MAN=		blowcrypt.1

MANDIR=		${LOCALBASE}/man/cat
BINDIR=		${LOCALBASE}/bin

CFLAGS+=	-Wall


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

.include <bsd.prog.mk>
