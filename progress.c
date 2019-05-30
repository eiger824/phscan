#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#include "progress.h"
#include "common.h"

size_t g_width;
const char* g_header;

void set_bar_length()
{
    struct winsize ws;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    // Adjust width so we have space for other information
    g_width = ws.ws_col;
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
            printf("|");
        else
            printf(".");
    }
    printf("] %.2f%%%s",
            ((float)progress / (float) g_width) * 100,
            delim);
    fflush(stdout);
}

void notify_progress(size_t current, size_t total)
{
    if (get_verbose() > 0)
        set_bar((g_width * current) / total, current == total ? "\n" : "\r");
}

