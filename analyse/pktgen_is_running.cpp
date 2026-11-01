/*
 * HANDLER: onewifi_pktgen_is_running
 *
 * Function copied VERBATIM from OneWifi lib/pktgen/pktgen.c. No fixes.
 * Local arrays:
 *   - str[BUF_LEN_MAX = 512]    <- fgets(str, BUF_LEN_MAX, fp)  (<= 511 chars)
 *   - run_if[BUF_LEN_MAX = 512] <- sscanf(str, "Running: %s", run_if)
 *     "%s" has NO width, but its source is str (<= 511 chars), so the token
 *     is at most 511 - 9 = 502 chars -> fits.
 *
 * Poison route:
 *   - fopen(PKTGEN_THREAD_FILE_0) -> fmemopen over the runner's file buffer
 *     (tail past the content poisoned by the runner).
 *   - fgets() -> pgr_fgets(): real fgets into the runner slot pgr_slot_str
 *     with the SAME size (512), then copied into str.
 *   - sscanf() -> pgr_sscanf(): real sscanf into the runner slot pgr_slot_if
 *     (512), then copied into run_if.
 *   The runner poisons both slots past 512 around the call, so a token
 *   longer than 511 would write into the poison -> ASan aborts.
 * str / run_if are also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): LOGD formats its arguments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
static void pgr_log(const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define LOGD(...) pgr_log(__VA_ARGS__)

#define BUF_LEN_MAX                 512
#define PKTGEN_DEVICE_FILE_PATH     "/proc/net/pktgen/"
#define PKTGEN_THREAD_FILE_0        PKTGEN_DEVICE_FILE_PATH "kpktgend_0"

static FILE *pgr_fopen(const char *path, const char *mode)
{
    (void)path;
    if (pgr_fopen_fail) return NULL;
    if (pgr_data_len == 0) return fmemopen((void *)"", 1, mode);
    return fmemopen(pgr_data, pgr_data_len, mode);
}
static char *pgr_fgets(char *s, int size, FILE *fp)
{
    if (size > PGR_SLOT_SZ) size = PGR_SLOT_SZ;
    memset(pgr_slot_str, 0, (size_t)size);
    char *r = fgets(pgr_slot_str, size, fp);
    memcpy(s, pgr_slot_str, (size_t)size);
    pgr_str_len = strnlen(pgr_slot_str, (size_t)size);
    return r ? s : NULL;
}
static int pgr_sscanf(const char *str, const char *fmt, char *out)
{
    memset(pgr_slot_if, 0, PGR_SLOT_SZ);   /* run_if is 512 */
    int r = sscanf(str, fmt, pgr_slot_if);
    memcpy(out, pgr_slot_if, PGR_SLOT_SZ);
    pgr_if_len = strnlen(pgr_slot_if, PGR_SLOT_SZ);
    return r;
}
#define fopen(p, m)        pgr_fopen((p), (m))
#define fgets(s, n, f)     pgr_fgets((s), (n), (f))
#define sscanf(s, f, o)    pgr_sscanf((s), (f), (o))

/* --- copied verbatim from lib/pktgen/pktgen.c --- */
int onewifi_pktgen_is_running(void)
{
    FILE *fp;
    char str[BUF_LEN_MAX];
    char run_if[BUF_LEN_MAX] = "";
    int retval = 0;

    fp = fopen(PKTGEN_THREAD_FILE_0, "r");
    if (fp == NULL)
    {
        LOGD("%s: Failed to open [%s] file. Pktgen is not running", __func__, PKTGEN_THREAD_FILE_0);
        return retval;
    }

    if (fgets(str, BUF_LEN_MAX, fp) != NULL)
    {
        if (sscanf(str, "Running: %s", run_if) == 1)
        {
            LOGD("%s: Packetgen is already running on interface [%s].", __func__, run_if);
            retval = 1;
        }
    }

    fclose(fp);
    return retval;
}
