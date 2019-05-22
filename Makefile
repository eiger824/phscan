PROGRAM 	= phscan
CFLAGS		= -c -Wall -Wextra -Wpedantic -fPIC -std=c11 -g
LDFLAGS		= -fPIC -lm
CC			:= gcc
OUTDIR 		:= build

SRCS 		:= main.c colors.h \
				net.c net.h \
				common.c common.h \
				time.c time.h

OBJS 		:= main.o net.o time.o common.o

OBJS := $(addprefix $(OUTDIR)/, $(OBJS))
PROGRAM := $(addprefix $(OUTDIR)/, $(PROGRAM))


all: $(OUTDIR) $(PROGRAM)

$(OUTDIR):
	test -d $@ || mkdir $@

${PROGRAM}: ${OBJS}
	${CC} $^ ${LDFLAGS} -o $@
	rm -f $(shell basename $@)
	ln -s $(PROGRAM)

$(OUTDIR)/main.o: $(SRCS)
	${CC} ${CFLAGS} $< -o $@

$(OUTDIR)/%.o: %.c %.h
	${CC} ${CFLAGS} $< -o $@

clean:
	rm -rf $(OUTDIR) $(shell basename $(PROGRAM)) *~
