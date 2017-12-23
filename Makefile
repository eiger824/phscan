PROGRAM=phscan

${PROGRAM}: main.c net.h threads.h utils.h time.h
	${CC} -g -Wall -Wextra -Wpedantic main.c -lpthread -o $@

clean:
	rm -f ${PROGRAM}
