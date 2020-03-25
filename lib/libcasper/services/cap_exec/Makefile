# $FreeBSD$

SHLIBDIR?=	/lib/casper

.include <src.opts.mk>

PACKAGE=	runtime

SHLIB_MAJOR=	1
INCSDIR?=	${INCLUDEDIR}/casper

.if ${MK_CASPER} != "no"
SHLIB=	cap_exec

SRCS=	cap_exec.c
.endif

LIBADD=	nv

CFLAGS+=-I${.CURDIR}

MAN+=	cap_exec.3

MLINKS+=cap_exec.3 libcap_exec.3

.include <bsd.lib.mk>
