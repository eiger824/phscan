#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdlib.h>
#include <string.h>

char *get_basename(char* str)
{
    char *stripped = str;
    while ((stripped = strchr(stripped, '/')) != NULL)
    {
        stripped++;
        if (strchr(stripped, '/') == NULL) break;
    }
    return stripped;
}


#endif  /* __UTILS_H_ */
