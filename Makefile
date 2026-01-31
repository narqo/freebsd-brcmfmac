.SUFFIXES: .zig

ZIG:= zig
ZIGFLAGS=

KMOD = if_brcmfmac

SRCS = \
	src/brcmfmac.zig \
	src/main.c

# LinuxKPI generated sources
SRCS+= ${LINUXKPI_GENSRCS}

# Include paths - must come before LINUXKPI_INCLUDES for header override
CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${.CURDIR}/src
CFLAGS+= -I${.CURDIR}/include

# LinuxKPI includes come after our local includes
CFLAGS+= ${LINUXKPI_INCLUDES}

.include <bsd.kmod.mk>

ZIGFLAGS+= -O ReleaseFast

# Extract all -I (includes) and -D (defines) from CFLAGS
ZIGFLAGS+= ${CFLAGS:M-I*}
ZIGFLAGS+= ${CFLAGS:M-D*}

ZIGFLAGS+= -mcmodel=kernel \
	-mno-red-zone \

.if ${MACHINE_CPUARCH} == "amd64"
ZIGFLAGS+= -target x86_64-freebsd-none
.elif ${MACHINE_CPUARCH} == "aarch64"
ZIGFLAGS+= -target aarch64-freebsd-none
.endif

ZIGFLAGS+= \
	-fno-omit-frame-pointer \
	-fno-stack-check \
	-fno-stack-protector \
	-fno-unwind-tables \

.zig.o:
	${ZIG} build-obj ${ZIGFLAGS} ${.IMPSRC} -femit-bin=${.TARGET}
