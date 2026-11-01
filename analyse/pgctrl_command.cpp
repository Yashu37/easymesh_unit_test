/*
 * HANDLER: pgctrl_command
 *
 * Function copied VERBATIM from OneWifi lib/pktgen/pktgen.c. No fixes.
 * (Only change: "static" dropped so the runner can call it.)
 * Local cmd[BUF_LEN_MAX = 512] is filled by vsnprintf(cmd, BUF_LEN_MAX,
 * format, argptr) and then written with write(fd, cmd, strlen(cmd)).
 *
 * Poison route:
 *   - vsnprintf() is redirected to pgc_vsnprintf(), which runs the real
 *     vsnprintf on a runner-owned slot of the SAME size (512) whose tail
 *     is poisoned, then copies it into cmd -> a write past 512 aborts.
 *   - write() is redirected to pgc_write(), which copies the bytes into a
 *     runner capture buffer poisoned past 512 -> writing more than cmd
 *     holds aborts.
 *   - the file path, format and %s arguments are runner buffers, poisoned
 *     past their NUL by the runner.
 * cmd itself is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - open() / close(): stubs (open fails on request, returns fd 42).
 *   - LOGE: really formats its arguments (vsnprintf to scratch).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
static void pgc_log(const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define LOGE(...) pgc_log(__VA_ARGS__)

#define BUF_LEN_MAX                 512

static int pgc_open(const char *path, int flags)
{
    (void)flags;
    pgc_open_path_len = strlen(path);
    return pgc_open_fail ? -1 : 42;
}
static int pgc_close(int fd) { (void)fd; return 0; }
static ssize_t pgc_write(int fd, const void *buf, size_t n)
{
    (void)fd;
    if (n > PGC_SLOT_SZ) n = PGC_SLOT_SZ + PGC_SLOT_PAD;   /* would run into the poison -> ASan */
    memset(pgc_out, 0, sizeof(pgc_out));
    __asan_poison_memory_region(pgc_out + PGC_SLOT_SZ, PGC_SLOT_PAD);
    memcpy(pgc_out, buf, n);
    __asan_unpoison_memory_region(pgc_out + PGC_SLOT_SZ, PGC_SLOT_PAD);
    pgc_out_len = n;
    return pgc_write_fail ? -1 : (ssize_t)n;
}
static int pgc_vsnprintf(char *out, size_t sz, const char *fmt, va_list ap)
{
    int r;
    if (sz > PGC_SLOT_SZ) sz = PGC_SLOT_SZ;
    memset(pgc_slot, 0, sz);
    __asan_poison_memory_region(pgc_slot + sz, sizeof(pgc_slot) - sz);
    r = vsnprintf(pgc_slot, sz, fmt, ap);
    __asan_unpoison_memory_region(pgc_slot + sz, sizeof(pgc_slot) - sz);
    memcpy(out, pgc_slot, sz);
    pgc_vs_ret = r;
    return r;
}
#define open(p, f)          pgc_open((p), (f))
#define close(fd)           pgc_close(fd)
#define write(fd, b, n)     pgc_write((fd), (b), (n))
#define vsnprintf(o, s, f, a)  pgc_vsnprintf((o), (s), (f), (a))

/* --- copied verbatim from lib/pktgen/pktgen.c --- */
int pgctrl_command(char *file, char *format, ...)
{
    va_list argptr;
    char cmd[BUF_LEN_MAX];
    int pgctrl_fd;
    ssize_t res;

    pgctrl_fd = open(file, O_WRONLY);
    if (pgctrl_fd < 0) {
        LOGE("%s: Failed to open %s", __func__, file);
        return -1;
    }

    va_start(argptr, format);
    vsnprintf(cmd, BUF_LEN_MAX, format, argptr);
    va_end(argptr);

    res = write(pgctrl_fd, cmd, strlen(cmd));
    close(pgctrl_fd);

    if (res < 0) {
        LOGE("%s: Failed to execute command: [%s].", __func__, cmd);
        return -1;
    }

    return 0;
}
