/*
 * HANDLER: pktgen_configure
 *
 * Function copied VERBATIM from OneWifi lib/pktgen/pktgen.c. No fixes.
 * (Only change: "static" dropped so the runner can call it.)
 * Local dev_path[PATH_MAX = 4096] is filled by
 *   snprintf(dev_path, PATH_MAX, "%s%s", PKTGEN_DEVICE_FILE_PATH, if_name)
 * and then passed as the file to pgctrl_command() five times.
 *
 * Poison route:
 *   - snprintf() is redirected to pgf_snprintf(), which runs the real
 *     vsnprintf on a runner slot of the SAME size (PATH_MAX) with a
 *     poisoned tail, then copies it into dev_path -> a write past 4096
 *     aborts.
 *   - if_name / dest_mac are runner buffers poisoned past their NUL.
 * dev_path itself is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - pgctrl_command(): stub (pgctrl_command itself has its own harness);
 *     it formats the command into a 512 buffer, reads the file path
 *     (strlen), counts calls and fails at a chosen call number.
 *   - LOGE / LOGD: really format their arguments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <linux/limits.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
static void pgf_log(const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define LOGE(...) pgf_log(__VA_ARGS__)
#define LOGD(...) pgf_log(__VA_ARGS__)

#define PKTGEN_DEVICE_FILE_PATH     "/proc/net/pktgen/"
#define PKTGEN_CNTRL_FILE           PKTGEN_DEVICE_FILE_PATH "pgctrl"
#define PKTGEN_THREAD_FILE_0        PKTGEN_DEVICE_FILE_PATH "kpktgend_0"

static int pgctrl_command(char *file, char *format, ...)
{
    char cmd[512];
    va_list ap; va_start(ap, format);
    vsnprintf(cmd, sizeof(cmd), format, ap);
    va_end(ap);
    pgf_calls++;
    size_t fl = strlen(file);
    if (fl > pgf_max_path) pgf_max_path = fl;
    if (pgf_calls == pgf_fail_at) return -1;
    return 0;
}

static int pgf_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > PGF_SLOT_SZ) sz = PGF_SLOT_SZ;
    memset(pgf_slot, 0, sz);
    __asan_poison_memory_region(pgf_slot + sz, sizeof(pgf_slot) - sz);
    va_start(ap, fmt);
    r = vsnprintf(pgf_slot, sz, fmt, ap);
    va_end(ap);
    __asan_unpoison_memory_region(pgf_slot + sz, sizeof(pgf_slot) - sz);
    memcpy(out, pgf_slot, sz);
    pgf_dev_len = strnlen(pgf_slot, sz);
    return r;
}
#define snprintf(o, n, ...)  pgf_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from lib/pktgen/pktgen.c --- */
int pktgen_configure(char *if_name, char *dest_mac, int packet_size)
{
    char dev_path[PATH_MAX];
    int ret;

    ret = pgctrl_command(PKTGEN_CNTRL_FILE, "reset\n");
    if (ret < 0) {
        LOGE("%s: Failed to reset. Trying to continue.", __func__);
    }

    ret = pgctrl_command(PKTGEN_THREAD_FILE_0, "add_device %s\n", if_name);
    if (ret < 0) {
        LOGE("%s: Failed to configure new device.", __func__);
        return -1;
    }

    snprintf(dev_path, PATH_MAX, "%s%s", PKTGEN_DEVICE_FILE_PATH, if_name);
    ret = pgctrl_command(dev_path, "queue_map_min 2\n");
    if (ret < 0) {
        LOGE("%s: Failed to configure queue_map_min.", __func__);
        return -1;
    }

    ret = pgctrl_command(dev_path, "queue_map_max 2\n");
    if (ret < 0) {
        LOGE("%s: Failed to configure queue_map_max.", __func__);
        return -1;
    }

    // Set unlimited ("0") number of packets to be sent
    ret = pgctrl_command(dev_path, "count 0\n");
    if (ret < 0) {
        LOGE("%s: Failed to configure packets number.", __func__);
        return -1;
    }

    ret = pgctrl_command(dev_path, "pkt_size %d\n", packet_size);
    if (ret < 0) {
        LOGE("%s: Failed to configure pkt_size.", __func__);
        return -1;
    }

    ret = pgctrl_command(dev_path, "dst_mac %s\n", dest_mac);
    if (ret < 0) {
        LOGE("%s: Failed to configure dst_mac.", __func__);
        return -1;
    }

    LOGD("%s: PktGen Configured successfully..", __func__);
    return 0;
}
