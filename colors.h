#ifndef __COLORS_H_
#define __COLORS_H_

// ANSI colors
#define     RED     "\x1b[31m"
#define     GREEN   "\x1b[32m"
#define     YELLOW  "\x1b[33m"
#define     BLUE    "\x1b[34m"
#define     MAGENTA "\x1b[35m"
#define     CYAN    "\x1b[36m"
#define     RESET   "\x1b[0m"

#define     COLOR_IF(X) get_color() ? X : ""

#endif  /* __COLORS_H_ */
