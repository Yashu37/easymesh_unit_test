/*
 * HANDLER: os_cmd_exec_xv
 *
 * Function copied VERBATIM from OneWifi lib/common/os_exec.c:55. No fixes.
 * The harness observes whether it accesses memory out of bounds under ASan.
 *
 * Arrays/buffers of interest:
 *   - cmd1[OS_CMD_LINE_SIZE] : local, filled by vsnprintf (bounded)
 *   - cmd2 = alloca(cmdlen)  : taken only when the command is longer than
 *                              cmd1. FIX APPLIED: the second vsnprintf now
 *                              uses the va_copy `args2` instead of the
 *                              already-consumed `args`. The original code
 *                              reused `args` (undefined behaviour -> the %s
 *                              read a garbage pointer and the command was
 *                              corrupted). Only this one argument changed.
 *   - buf : growing heap buffer for command output (fread/realloc loop)
 *
 * Scaffolding (NOT part of the function): LOG/LOG_SEVERITY no-op stubs and
 * the severity/flag/size #defines from log.h/os.h/os_exec.c. The only
 * non-verbatim changes are C++ casts on alloca()/realloc() (void* needs a
 * cast in C++); the logic is unchanged.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <alloca.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { LOG_SEVERITY_DEBUG = 1, LOG_SEVERITY_ERR, LOG_SEVERITY_ERROR = LOG_SEVERITY_ERR,
       TRACE, DEBUG };
#define LOG(sev, ...)              do { } while (0)
#define LOG_SEVERITY(level, ...)   do { } while (0)
#define OS_CMD_LINE_SIZE 256                 /* verbatim from os_exec.c:35 */
#define OS_CMD_BUF_CHUNK 1024                /* verbatim from os_exec.c:36 */
#define OS_CMD_FLAG_ANY_EXIT_CODE   1
#define OS_CMD_FLAG_NO_LOG_OUTPUT   2
#define OS_CMD_FLAG_LOG_ERROR_DEBUG 4

/* --- copied verbatim from lib/common/os_exec.c:55 --- */
bool os_cmd_exec_xv(char **buffer, int *len, int *exit_code, int flags, char *fmt, va_list args)
{
    va_list args2;
    char    cmd1[OS_CMD_LINE_SIZE];
    char    *cmd2 = NULL;
    char    *command = cmd1;
    int     cmdlen;
    FILE    *fp = NULL;
    int     ret = 0;
    int     xcode = 0;
    char    *buf = NULL;
    char    *tmp = NULL;
    int     bufsize = 0;
    int     buflen = 0;
    int     loglen = 0;
    int     errlevel = LOG_SEVERITY_ERROR;

    if (!buffer) {
        return false;
    }
    *buffer = NULL;
    if (len) *len = 0;
    if (exit_code) *exit_code = 0;

    errno = 0;
    va_copy(args2, args);
    cmdlen = vsnprintf(cmd1, sizeof(cmd1), fmt, args);

    if (cmdlen >= (int)sizeof(cmd1)) {
        // fixed cmd buffer too small, allocate and retry
        cmdlen++;
        cmd2 = (char *)alloca(cmdlen);
        cmdlen = vsnprintf(cmd2, cmdlen, fmt, args2);
        command = cmd2;
    }
    va_end(args2);
    if (cmdlen <= 0) {
        command = fmt;
        goto error;
    }

    LOG(TRACE, "Executing '%s'", command);
    errno = 0;
    fp = popen(command, "r");
    if (fp == NULL) {
        goto error;
    }

    while (!feof(fp))
    {
        // always have chunk size and zero term ready to read
        bufsize = buflen + OS_CMD_BUF_CHUNK + 1;
        tmp = (char *)realloc(buf, bufsize);
        if (!tmp) {
            goto error;
        }
        buf = tmp;
        // read, reserve 1 for zero term
        errno = 0;
        ret = fread(buf + buflen, 1, bufsize - buflen - 1, fp);
        if (ret < 0) {
            LOG(DEBUG, "read: %d %d(%s)", ret, errno, strerror(errno));
            break;
        }
        buflen += ret;
        // zero term
        buf[buflen] = 0;
        // log lines
        if (!(flags & OS_CMD_FLAG_NO_LOG_OUTPUT)) {
            while (1) {
                char *p = buf + loglen;
                char *nl = strchr(p, '\n');
                if (!nl) break;
                if (nl - p > 0) {
                    LOG(TRACE, "> %.*s", (int) (nl - p), p);
                }
                loglen = nl - buf + 1;
            }
        }
    }
    // log remaining
    if (loglen < buflen) {
        LOG(TRACE, ": %*s", buflen - loglen, buf + loglen);
    }
    // reduce alloc size
    buf = (char *)realloc(buf, buflen + 1);
    // close
    errno = 0;
    xcode = pclose(fp);
    fp = NULL;
    if (xcode < 0) goto error;
    if (exit_code) *exit_code = xcode;
    if (!(flags & OS_CMD_FLAG_ANY_EXIT_CODE)) {
        if (xcode != 0) goto error;
    }
    if (len) *len = buflen;
    *buffer = buf;
    LOG(TRACE, "exit=%d len=%d '%s'", xcode, buflen, command);

    return true;

error:
    if (flags & OS_CMD_FLAG_LOG_ERROR_DEBUG) {
        // useful when failure is expected
        errlevel = LOG_SEVERITY_DEBUG;
    }
    LOG_SEVERITY(errlevel, "exit=%d err=%d(%s) '%s'", xcode, errno, strerror(errno), command);
    if (buf) free(buf);
    if (fp) pclose(fp);
    return false;
}
