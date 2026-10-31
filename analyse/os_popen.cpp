/*
 * HANDLER: os_popen
 *
 * Function copied VERBATIM from OneWifi lib/common/os.c. No fixes.
 * Its only array, pipefd[2], is filled by pipe(pipefd) (which writes
 * exactly two ints) and is only ever indexed [0]/[1], so it cannot
 * overflow. It is an internal stack array (ASan auto-guards it); there is
 * no caller-owned buffer to __asan_poison here.
 *
 * Scaffolding: LOG no-op stub + severity names + OS_ERROR_PID.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
#define OS_ERROR_PID  (-1)               /* verbatim from os.h:71 */

/* --- copied verbatim from lib/common/os.c --- */
pid_t os_popen(const char *shell_cmd, int *pipe_desc)
{
    int32_t pipefd[2];
    pid_t pid;

    if (pipe(pipefd) != 0)
    {
        LOG(ERR, "pipe creation failed:");
        return OS_ERROR_PID;
    }

    pid = fork();
    if (pid < 0)
    {
        LOG(ERR, "fork creation failed:");
        close(pipefd[0]);
        close(pipefd[1]);
        return OS_ERROR_PID;
    }
    else if (pid == 0)
    {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        execl("/bin/sh","sh", "-c", shell_cmd, NULL);
        LOG(INFO, "execl cmd failed:");
        exit(1);
    }

    close(pipefd[1]);
    *pipe_desc=pipefd[0];
    return pid;
}
