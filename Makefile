PROGRAM=phscan
CFLAGS=-c -Wall -Wextra -Wpedantic -fPIC --std=c11 -g
LDFLAGS=-fPIC -lpthread
CC=gcc

OBJS += main.o net.o threads.o time.o

${PROGRAM}: ${OBJS}
	${CC} $^ ${LDFLAGS} -o $@

main.o: main.c utils.h colors.h
	${CC} ${CFLAGS} $< -o $@

net.o: net.c net.h
	${CC} ${CFLAGS} $< -o $@

threads.o: threads.c threads.h
	${CC} ${CFLAGS} $< -o $@

time.o: time.c time.h
	${CC} ${CFLAGS} $< -o $@

clean:
	rm -f ${PROGRAM} *.o *~
