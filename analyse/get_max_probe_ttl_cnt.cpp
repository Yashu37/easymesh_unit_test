/*
 * HANDLER: get_max_probe_ttl_cnt
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes).
 * Local array:
 *   - char buff[64] : fgets(buff, 64, fp) reads at most 63 chars + NUL, the
 *     '\\n' strip uses strchr inside buff, atoi reads the NUL-terminated buff.
 * Bounded -> SAFE.
 *
 * Scaffolding (NOT under test): fopen of "/nvram/max_probe_ttl_cnt" is
 * #define-redirected to an fmemopen over gmt_file_buf (or NULL when the file
 * does not exist); fgets / fclose are the REAL libc calls.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define MAX_PROBE_MAP_TTL 500

static FILE *gmt_fopen(const char *path, const char *mode)
{
    (void)path; (void)mode;
    if (!gmt_have_file) return NULL;
    return fmemopen(gmt_file_buf, gmt_file_len, "r");
}
#define fopen(p, m) gmt_fopen((p), (m))

/* ================= VERBATIM from wifi_levl.c ================= */
unsigned int get_max_probe_ttl_cnt(void)
{
    FILE *fp;
    char buff[64];
    char *ptr;
    memset(buff, 0, sizeof(buff));

    if ((fp = fopen("/nvram/max_probe_ttl_cnt", "r")) == NULL) {
        return MAX_PROBE_MAP_TTL; /* default is 64 count */
    }

    fgets(buff, 64, fp);
    if ((ptr = strchr(buff, '\n')) != NULL) {
        *ptr = 0;
    }
    fclose(fp);

    return (atoi(buff) ? atoi(buff) : MAX_PROBE_MAP_TTL);
}
