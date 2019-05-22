#ifndef __TIME_H_
#define __TIME_H_

#include <sys/time.h>

/*
 * Function:	set_timer
 * Brief:	    Given a time structure, this function initializes it
 * @param t0:	Time structure to initialize with current UNIX timestamp
 * Returns:	    Nothing
*/
void set_timer(struct timeval* t0);

/*
 * Function:	get_elapsed_secs
 * Brief:	    Given a time structure, it computes the elapsed seconds since it
                was first initialized 
 * @param t0:	Time structure that was initialized some time ago
 * Returns:	    The elapsed seconds betwenn "t0" and the call to this function
*/
double get_elapsed_secs(struct timeval* t0);


#endif  /* __TIME_H_ */
