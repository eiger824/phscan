#ifndef COMMON_H_
#define COMMON_H_

#include <stdarg.h>

#define     port_t  uint16_t

void err(const char* msg, ...);
void info(const char* msg, ...);
void die(void (*usage_fun)(char*), char* program, const char* msg, ...);
void dbg(const char* msg, ...);
char *get_basename(char* str);
int regex_match(const char* str, const char* regex);
char find_delim(const char* str);
int verify_port(int port);
void set_verbose(int verbose);

#endif /* COMMON_H_ */
