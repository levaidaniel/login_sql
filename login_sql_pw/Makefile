LOCALBASE ?=	/usr/local

BINDIR =	${LOCALBASE}/bin
PROG =		login_sql_pw

MANDIR =	${LOCALBASE}/man/man
MAN =		login_sql_pw.1

SRCS =		login_sql_pw.c

CFLAGS +=	-pedantic -Wall -g

LDADD +=	-lcrypto

.include <bsd.prog.mk>
