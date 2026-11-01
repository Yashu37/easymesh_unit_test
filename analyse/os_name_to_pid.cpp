/*
 * HANDLER: os_name_to_pid
 *
 * Function copied VERBATIM from OneWifi lib/osa/os_proc.c. No fixes.
 * Local rbuff[1024] is filled by a bounded fread (sizeof-1) and NUL-set at
 * rc (<=1023). The pid-extraction loop rbuff[j++]=*pidstr++ has no explicit
 * bound, but pidstr is a /proc/<pid>/comm path so the digit run is a short
 * pid -- safe in practice. Caller input proc_name is poisoned by the runner;
 * rbuff is internal (auto-guarded by ASan).
 *
 * Scaffolding: os_strtoul stubbed (decimal parse); LOG no-op.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <glob.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
static bool os_strtoul(char *str, long *out, int base)
{
    char *end = NULL;
    long v = strtol(str, &end, base);
    if (end == str || *end != '\0') return false;
    *out = v;
    return true;
}

/* --- copied verbatim from lib/osa/os_proc.c --- */
pid_t os_name_to_pid(const char *proc_name)
{
    pid_t       pid = -1;
    long        lextr;
    glob_t      g;
    char        rbuff[1024];
    uint32_t    i;
    FILE        *f;
    int         rc;
    char *      newline;

    /* process name is stored in /proc/pid/comm */
    if (glob("/proc/*/comm", 0, NULL, &g) != 0)
    {
        goto exit;
    }

    for (i = 0; i < g.gl_pathc; i++)
    {

        /* Read the contents of the file */
        if (NULL == (f = fopen(g.gl_pathv[i], "r")))
        {
            /* error opening file, ignore, continue */
            continue;
        }
        else
        {
            /* try to read comm file */
            // use size-1 for zero termination
            rc = fread(rbuff, 1, sizeof(rbuff) - 1, f);
            fclose(f);
            if (rc <= 0) continue;
            // zero terminate
            rbuff[rc] = 0;
            // trim newline
            if (NULL != (newline = strrchr(rbuff, '\n')))
            {
               *newline = '\0';
            }
        }

        /*
         *  Find the match. If there is a match, extract pid
         */
        if (0 == strcmp(rbuff, proc_name))
        {
            int j = 0;
            char * pidstr = g.gl_pathv[i];

            /* reset read buffer */
            memset(rbuff, 0, sizeof(rbuff));

            /* find begging of pid string */
            while ((*pidstr != '\0') && (!isdigit(*pidstr)))
                pidstr++;

            /* extract pid string */
            while ((*pidstr != '\0') && (isdigit(*pidstr)))
                rbuff[j++] = *pidstr++;

            /* convert it to a number */
            if (false == os_strtoul(rbuff, &lextr, 0))
            {
                LOG(ERR, "Extracting pid from %s failed", g.gl_pathv[i]);
            }
            else
            {
                pid = (pid_t)lextr;
            }

            break; /* for loop */
        }
    }

exit:
    /* Clean up. */
    globfree(&g);

    return pid;
}
