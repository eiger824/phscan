#ifndef COMMON_UTILS_H_
#define COMMON_UTILS_H_

#include <stdio.h>

void set_bar_length();
void set_bar_header(const char* text);
void set_bar(size_t progress, const char* delim);
void notify_progress(size_t current, size_t total);

#endif /* COMMON_UTILS_H_ */
