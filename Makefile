PROGRAM      = phscan
PHSCAN_ROOT  = $(shell echo ${PWD})
CFLAGS       = -c -I. -Inet -Wall -Wextra -Wpedantic -fPIC -std=c11 -g
LDFLAGS      = -fPIC -lm -pthread
CC           := gcc
OUTPFX       := build
NETPFX       := net

SRCS        := main.c colors.h \
               common.c common.h \
			   timings.c timings.h \
			   progress.c progress.h \
			   process.c process.h \
			   opts.c opts.h \
               $(NETPFX)/net.c $(NETPFX)/net.h \
			   $(NETPFX)/scan/tcpconnect.c $(NETPFX)/scan/tcpconnect.h \
			   $(NETPFX)/scan/tcphalfopen.c $(NETPFX)/scan/tcphalfopen.h \
			   $(NETPFX)/scan/icmpping.c $(NETPFX)/scan/icmpping.h \

OBJS        := main.o timings.o common.o progress.o process.o opts.o

include net/Makefile
include test/Makefile

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


####################### Test related ######################
test: $(TEST_FULLPROGRAM) 

$(TEST_FULLPROGRAM): $(TEST_SRCS) 
	${CC} ${TEST_CFLAGS} $^ -o $@ 
	rm -f $(TEST_PROGRAM) 
	ln -s $@ $(TEST_PROGRAM) 

###########################################################

clean:
	rm -rf $(OUTPFX) $(shell basename $(PROGRAM)) $(TEST_PROGRAM) $(TEST_FULLPROGRAM) *~
