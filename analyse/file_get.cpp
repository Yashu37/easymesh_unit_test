/*
 * HANDLER: file_get
 *
 * Function copied VERBATIM from OneWifi lib/common/util.c:1060. No fixes.
 * The harness only observes whether the function, as shipped, crashes
 * under ASan on an out-of-bounds access to its local array hunk[4096]
 * (or the growing heap buffer it fills).
 *
 * file_get() uses OneWifi's LOGT() trace macro from lib/log/log.h, which
 * is not part of this harness. A no-op LOGT stub is provided here ONLY so
 * the verbatim body compiles; it does not change what file_get does.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- LOGT scaffolding (stub, not part of the function under test) --- */
#define LOGT(...) do { } while (0)

/* --- copied verbatim from lib/common/util.c:1060 --- */
char *file_get(const char *path)
{
    ssize_t n;
    ssize_t size = 0;
    ssize_t len = 0;
    char *buf = NULL;
    char *nbuf = NULL;
    char hunk[4096];
    int fd;
    if ((fd = open(path, O_RDONLY)) < 0)
        goto err;
    while ((n = read(fd, hunk, sizeof(hunk))) > 0) {
        if (!(nbuf = (char *)realloc(buf, (size_t)(size += n) + 1)))
            goto err_free;
        buf = nbuf;
        memcpy(buf + len, hunk, (size_t)n);
        len += n;
        buf[len] = 0;
    }
    if (n < 0)
        goto err_free;
    close(fd);
    LOGT("%s: read %-100s", path, (const char *)buf);
    return buf;
err_free:
    free(buf);
    close(fd);
err:
    LOGT("%s: failed to read: %d (%s)", path, errno, strerror(errno));
    return NULL;
}
