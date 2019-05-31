#ifndef __TIME_H_
#define __TIME_H_

#include <sys/time.h>

void start_timer(struct timeval* t0);
void stop_timer(struct timeval* t0, char* units);


#endif  /* __TIME_H_ */
