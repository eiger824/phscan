PROGRAM 	= phscan
CFLAGS		= -c -Wall -Wextra -Wpedantic -fPIC --std=c11 -g
LDFLAGS		= -fPIC -lpthread
CC			:= gcc
OUTDIR 		:= build

OBJS += main.o net.o threads.o time.o common.o

OBJS := $(addprefix $(OUTDIR)/, $(OBJS))
PROGRAM := $(addprefix $(OUTDIR)/, $(PROGRAM))


all: $(OUTDIR) $(PROGRAM)

$(OUTDIR):
	test -d $@ || mkdir $@

${PROGRAM}: ${OBJS}
	${CC} $^ ${LDFLAGS} -o $@
	rm -f $(shell basename $@)
	ln -s $(PROGRAM)

$(OUTDIR)/main.o: main.c utils.h colors.h
	${CC} ${CFLAGS} $< -o $@

$(OUTDIR)/%.o: %.c %.h
	${CC} ${CFLAGS} $< -o $@

clean:
	rm -rf $(OUTDIR) $(shell basename $(PROGRAM)) *~
