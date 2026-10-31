/*
 * HANDLER: os_pid_from_file
 *
 * Function copied VERBATIM from OneWifi lib/common/os.c. No fixes.
 * Its only array, buf[64], is a local stack array filled solely by
 * fgets(buf, sizeof(buf), f) (size-bounded). There is no caller-owned
 * buffer and no helper taking one, so no __asan_poison applies here; ASan
 * instruments buf's stack red-zones automatically, and the test includes a
 * line longer than 64 bytes so any fgets overrun would be caught.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/common/os.c --- */
pid_t os_pid_from_file(char *pid_file)
{
    char buf[64];
    long pid;

    FILE *f = NULL;
    pid_t retval = 0;

    /* Open PID file */
    f = fopen(pid_file, "r");
    if (f == NULL)
    {
        goto error;
    }

    /* Read first line */
    if (fgets(buf, sizeof(buf), f) == NULL)
    {
        goto error;
    }

    /* Convert it to string */
    pid = atol(buf);
    if (pid == 0)
    {
        goto error;
    }

    /* Check if PID exists */
    if (kill(pid, 0) != 0)
    {
        goto error;
    }

    retval = (pid_t)pid;

error:
    if (f != NULL) fclose(f);

    return retval;
}
