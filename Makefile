PROGRAM     = phscan
CFLAGS      = -c -I. -Inet -Wall -Wextra -Wpedantic -fPIC -std=c11 -g
LDFLAGS     = -fPIC -lm -pthread
CC          := gcc
OUTPFX      := build
NETPFX      := net

SRCS        := main.c colors.h \
               common.c common.h \
			   timings.c timings.h \
			   progress.c progress.h \
			   process.c process.h \
               $(NETPFX)/net.c $(NETPFX)/net.h \
			   $(NETPFX)/scan/tcpconnect.c $(NETPFX)/scan/tcpconnect.h \
			   $(NETPFX)/scan/tcphalfopen.c $(NETPFX)/scan/tcphalfopen.h

OBJS        := main.o timings.o common.o progress.o process.o
include net/Makefile

OBJS := $(addprefix $(OUTPFX)/, $(OBJS))
PROGRAM := $(addprefix $(OUTPFX)/, $(PROGRAM))

all: $(OUTPFX) $(PROGRAM)

$(OUTPFX):
	mkdir -p $@/$(NETPFX)/scan

${PROGRAM}: ${OBJS}
	${CC} $^ ${LDFLAGS} -o $@
	rm -f $(shell basename $@)
	ln -s $(PROGRAM)

$(OUTPFX)/main.o: $(SRCS)
	${CC} ${CFLAGS} $< -o $@

$(OUTPFX)/%.o: %.c %.h
	${CC} ${CFLAGS} $< -o $@

clean:
	rm -rf $(OUTPFX) $(shell basename $(PROGRAM)) *~
