KMOD = if_brcmfmac

SRCS = \
	src/cfg.c \
	src/core.c \
	src/debug.c \
	src/fwil.c \
	src/main.c \
	src/msgbuf.c \
	src/pcie.c \
	src/scan.c \
	src/security.c

SRCS+= device_if.h bus_if.h pci_if.h

CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${.CURDIR}/src

.include <bsd.kmod.mk>
