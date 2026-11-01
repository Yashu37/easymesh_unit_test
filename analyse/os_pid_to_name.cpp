/*
 * HANDLER: os_pid_to_name
 *
 * Function copied VERBATIM from OneWifi lib/osa/os_proc.c, plus one FIX line.
 * Local buf[64] holds the /proc/<pid>/comm path, then the comm read by
 * fgets(buf, sizeof(buf), fp) -- both bounded. The result is copied to the
 * caller's proc_name with strscpy(proc_name, buf, len). len is int32_t and
 * was passed straight to strscpy's size_t size with NO check: a negative len
 * became a huge size (e.g. -1 -> SIZE_MAX), so the comm was copied untruncated
 * and wrote past the caller's buffer.
 * FIX APPLIED: "if (len < 0) goto func_exit;" before strscpy (returns -1).
 * Only that line was added.
 * Caller output proc_name is poisoned past its real size by the runner;
 * buf is internal (auto-guarded by ASan).
 *
 * Scaffolding: strscpy copied verbatim from lib/common/util.c.
 * C++-only change: "int l = strlen(buf);" is split into a declaration plus
 * assignment, because C++ rejects a goto that jumps over an initialisation
 * (C allows it). Same behaviour.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding: verbatim from lib/common/util.c --- */
static ssize_t strscpy(char *dest, const char *src, size_t size)
{
    size_t len;
    if (size == 0) return -E2BIG;
    len = strnlen(src, size - 1);
    memcpy(dest, src, len);
    dest[len] = 0;
    if (src[len]) return -E2BIG;
    return (ssize_t)len;
}

/* --- copied verbatim from lib/osa/os_proc.c --- */
int32_t os_pid_to_name(pid_t pid, char *proc_name, int32_t len)
{
    char buf[64];

    FILE *fp = NULL;
    int32_t rc = -1;

    memset(buf, 0x00, sizeof(buf));
    snprintf(buf, sizeof(buf), "/proc/%d/comm", pid);

    fp = fopen(buf, "r+");
    if (NULL == fp)
        goto func_exit;

    if (fgets(buf, sizeof(buf), fp) == 0)
        goto func_exit;

    // remove newline if present
    int l;              /* C++ only: split from "int l = strlen(buf);" so the goto may jump past it */
    l = strlen(buf);
    if (l > 0 && buf[l-1] == '\n') {
        buf[l-1] = 0;
    }

    if (len < 0) goto func_exit;   /* FIX: reject negative len (would become a huge size_t) */
    strscpy(proc_name, buf, len);
    rc = 0;

func_exit:
    if (fp != NULL) fclose(fp);

    return rc;
}
