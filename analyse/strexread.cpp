/*
 * HANDLER: strexread
 *
 * Function copied VERBATIM from OneWifi lib/common/util.c. No fixes.
 * Its only array, fd[2], is filled by pipe(fd) and indexed [0]/[1] only.
 * It forks, execvp's prog with argv in the child, and reads the child's
 * stdout into a growing heap buffer in the parent.
 *
 * Scaffolding (NOT part of the function): strfmta()/argvstra() build only a
 * log context string, so they are stubbed to "" ; LOG* are no-op stubs.
 * No logic changed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
#define LOGW(...) do { } while (0)
#define LOGT(...) do { } while (0)
#define strfmta(...)  ((char *)"")      /* builds only the log context */
#define argvstra(a)   ((char *)"")

/* --- copied verbatim from lib/common/util.c --- */
char *strexread(const char *prog, const char *const*argv)
{
    const char *ctx = strfmta("%s(%s, [%s]", __func__, prog ?: "", argvstra(argv) ?: "");
    char **args, *p, *q, c;
    int fd[2], pid, status, i, j, n;
    if (!prog || !argv) {
        LOGW("%s: invalid arguments (prog=%p, argv=%p)", ctx, prog, argv);
        return NULL;
    }
    if (pipe(fd) < 0) {
        LOGW("%s: failed to pipe(): %d (%s)", ctx, errno, strerror(errno));
        return NULL;
    }
    switch ((pid = fork())) {
        case -1:
            LOGW("%s: failed to fork(): %d (%s)", ctx, errno, strerror(errno));
            close(fd[0]);
            close(fd[1]);
            return NULL;
        case 0:
            close(0);
            close(1);
            close(2);
            open("/dev/null", O_RDONLY);
            dup2(fd[1], 1);
            close(fd[0]);
            close(fd[1]);
            for (n=0; argv[n]; n++);
            args = (char **)calloc((size_t)++n, sizeof(args[0]));
            for (n=0; argv[n]; n++) args[n] = strdup(argv[n]);
            args[n] = 0;
            execvp(prog, args);
            LOGW("%s: failed to execvp(): %d (%s)", ctx, errno, strerror(errno));
            exit(1);
        default:
            close(fd[1]);
            for (n=0,i=0,p=0;;) {
                if (i+1 >= n) {
                    if ((q = (char *)realloc(p,(size_t)(n+=4096))))
                        p = q;
                    else
                        break;
                }
                if ((j = (int)read(fd[0], p+i, (size_t)(n-i-1))) <= 0)
                    break;
                i += j;
            }
            p[i] = 0;
            while (read(fd[0], &c, 1) == 1);
            close(fd[0]);
            waitpid(pid, &status, 0);
            LOGT("%s: status=%d output='%s'", ctx, status, p);
            if ((errno = (WIFEXITED(status) ? WEXITSTATUS(status) : -1)) == 0)
                return p;
            free(p);
            return NULL;
    }
    LOGW("%s: unreachable", ctx);
    return NULL;
}
