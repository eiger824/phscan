#include <string.h>

#include "progress.h"
#include "common.h"
#include "colors.h"

size_t g_width;
const char* g_header;

void set_bar_length()
{
    g_width = get_win_size(); 
}

void set_bar_header(const char* text)
{
    if (!text)
        return;
    g_header = text;
    size_t trimsize =
        strlen(text) // The text to write
        + 2          // The opening and closing brackets '[' and ']'
        + 8;         // The percentage at the end, XX.XX%

    g_width -= trimsize; 
}

void set_bar(size_t progress, const char* delim)
{
    size_t i;
    printf("%s[", g_header);
    for (i = 0; i < g_width; ++i)
    {
        if (i < progress)
            printf("%s|", COLOR_IF(YELLOW));
        else
            printf("%s.", COLOR_IF(BLUE));
    }
    printf("%s] %.2f%%%s",
            COLOR_IF(RESET),
            ((float)progress / (float) g_width) * 100,
            delim);
    fflush(stdout);
}

void notify_progress(size_t current, size_t total)
{
    if (get_verbose() > 0)
        set_bar((g_width * current) / total, current == total ? "\n" : "\r");
}

