/*
 * HANDLER: cmd_log
 *
 * Function copied VERBATIM from OneWifi lib/common/os.c:333. No fixes.
 * The harness only observes whether the function, as shipped, crashes
 * under ASan on an out-of-bounds access to its local array buf[1024].
 *
 * cmd_log() uses OneWifi's LOG() macro and severity names (DEBUG/INFO/ERR)
 * from lib/log/log.h, which is not part of this harness. A minimal no-op
 * LOG stub is provided here ONLY so the verbatim body compiles; it does
 * not change what cmd_log does with buf.
 *
 * NOTE: cmd_log() runs its argument through popen() (i.e. /bin/sh -c ...),
 * so the test suite only passes harmless commands (echo/seq/printf/true).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- LOG scaffolding (stub, not part of the function under test) --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)

/* --- copied verbatim from lib/common/os.c:333 --- */
int cmd_log(const char *shell_cmd)
{
    char buf[1024];

    FILE *fcmd = NULL;
    int rc =  -1;

    fcmd = popen(shell_cmd, "r");
    if (fcmd ==  NULL)
    {
        LOG(DEBUG, "Error executing command.::shell_cmd=%s", shell_cmd);
        goto exit;
    }

    LOG(DEBUG, "Executing command.::shell_cmd=%s ", shell_cmd);

    while (fgets(buf, sizeof(buf), fcmd) != NULL)
    {
        LOG(INFO, ">>::output=%s", buf);
    }

    if (ferror(fcmd))
    {
        LOG(ERR, "fgets() failed.");
        goto exit;
    }

    LOG(DEBUG, "EOF");
    rc = pclose(fcmd);

    fcmd = NULL;

exit:
    if (fcmd != NULL)
    {
        pclose(fcmd);
    }

    return rc;
}
