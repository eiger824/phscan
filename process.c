#include <signal.h>
#include <stdlib.h>

#include "process.h"
#include "net/net.h"
#include "common.h"

void signal_handler(int signo)
{
    if (signo == SIGINT)
    {
        info("\nSIGINT caught, cleaning up.\n");
        net_cleanup();
        exit(signo);
    }
}
