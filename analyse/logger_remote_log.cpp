/*
 * HANDLER: logger_remote_log
 *
 * Function copied VERBATIM from OneWifi lib/log/log_remote.c. No fixes.
 * msg_str[1024] is filled by a bounded snprintf. It reads the caller's
 * msg->lm_timestamp / lm_tag / lm_text via %s (over-read surface; the
 * runner poisons those buffers' tails). msg_str is internal (auto-guarded).
 *
 * Scaffolding (NOT the function under test): log_remote_enabled global,
 * log_get_name() and qm_conn_send_log() are stubbed; logger_t/logger_msg_t
 * come from common.h (minimal versions carrying the fields the body uses).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
bool log_remote_enabled = true;
static const char *log_get_name(void) { return "OneWifi"; }

extern int lrl_send_count;                 /* bumped by the qm stub */
static void qm_conn_send_log(char *msg, void *unused) { (void)msg; (void)unused; lrl_send_count++; }

/* --- copied verbatim from lib/log/log_remote.c --- */
void logger_remote_log(logger_t *self, logger_msg_t *msg)
{
    static bool inside_log = false;
    char msg_str[1024];

    (void)self;
    if (!log_remote_enabled) return;

    if (inside_log) return; // prevent recursion

    inside_log = true;

    snprintf(msg_str, sizeof(msg_str), "[%5ld] %s %s: %s: %s\n",
            syscall(SYS_gettid),
            msg->lm_timestamp,
            log_get_name(),
            msg->lm_tag,
            msg->lm_text);

    qm_conn_send_log(msg_str, NULL);
    // ignore send errors

    inside_log = false;
}
