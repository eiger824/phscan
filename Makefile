PROGRAM     = phscan
CFLAGS      = -c -I. -Wall -Wextra -Wpedantic -fPIC -std=c11 -g
LDFLAGS     = -fPIC -lm
CC          := gcc
OUTPFX      := build
NETPFX      := net

SRCS        := main.c colors.h \
               common.c common.h \
               time.c time.h \
               $(NETPFX)/net.c $(NETPFX)/net.h \
               $(NETPFX)/scan/tcpconnect.c $(NETPFX)/scan/tcpconnect.h

OBJS        := main.o time.o common.o
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
