# $Id: os.Linux.mk 3784 2020-01-06 08:06:52Z jkoshy $
#
# Build recipes for GNU/Linux based operating systems.

OS_DISTRIBUTION         != lsb_release -s -i || echo unknown
OS_DISTRIBUTION_VERSION != lsb_release -s -r || echo unknown

.if ${OS_DISTRIBUTION} == "unknown" || \
    ${OS_DISTRIBUTION_VERSION} == "unknown"
.error ERROR: Unknown host OS distribution.
.endif

MKDOC?=		yes	# Build documentation.
MKLINT?=	no
MKPIC?=		no
MKNOWEB?=	yes	# Build literate programs.
MKTESTS?=	yes	# Enable the test suites.
MKTEX?=		yes	# Build TeX-based documentation.

OBJECT_FORMAT=	ELF	# work around a bug in the pmake package

YFLAGS+=	-d		# force bison to write y.tab.h

EPSTOPDF?=	/usr/bin/epstopdf
MAKEINDEX?=	/usr/bin/makeindex
MPOST?=		/usr/bin/mpost
MPOSTTEX?=	/usr/bin/latex
NOWEB?=		/usr/bin/noweb
PDFJAM?=	/usr/bin/pdfjam
PDFLATEX?=	/usr/bin/pdflatex
