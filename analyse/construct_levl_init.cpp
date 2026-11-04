/*
 * TEST CASES / CONSTRUCTOR: construct_levl_init
 * Caller-owned buffers: lli_app_buf (levl wifi_app, written by levl_init),
 * lli_csi_buf (csi wifi_app returned by get_app_by_inst) and lli_ctrl_buf
 * (wifi_ctrl_t); the runner poisons the LLI_PAD tail of each.
 * The app is pre-filled with stale values (max clients 99, duration 1,
 * temperature_event_subscribed all true, csi_fd 42) so the init writes are
 * visible.
 *
 * Cases: ok, ok_lock_already_inited (no second mutex init), ok_big_tables
 * (radios=3 / vaps=24 reach the table rows), mkfifo_exists (EEXIST is fine),
 * app_init_fail, null_ctrl, null_csi, curr_map_fail, pending_map_fail,
 * mkfifo_fail (EACCES), bus_open_fail, bus_reg_fail (still returns OK).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"

alignas(16) char lli_app_buf[sizeof(struct wifi_app) + LLI_PAD];
alignas(16) char lli_csi_buf[sizeof(struct wifi_app) + LLI_PAD];
alignas(16) char lli_ctrl_buf[sizeof(wifi_ctrl_t) + LLI_PAD];
char lli_map_tokens[8];
int lli_app_init_ret, lli_null_ctrl, lli_null_csi, lli_map_fail_at, lli_mkfifo_err, lli_bus_open_ret, lli_bus_reg_ret;
int lli_radios, lli_vaps;
int lli_app_init_calls, lli_map_calls, lli_sched_calls, lli_mkfifo_calls, lli_open_calls, lli_reg_calls, lli_mutex_init_calls;
int lli_reg_n, lli_reg_names_ok, lli_reg_rows0, lli_reg_rows10;
char lli_reg_first[128], lli_reg_last[128];
int lli_sched_period;

lv_lli_test_case_t levl_init_suite[] = {
    /* name                 appinit nc ncsi mapfail mkfifo open reg radios vaps lock | ret reg inited */
    { "ok",                    0,    0, 0,   0,      0,     0,   0,   2,   16,  0,      0,  1,  1 },
    { "ok_lock_already_inited",0,    0, 0,   0,      0,     0,   0,   2,   16,  1,      0,  1,  1 },
    { "ok_big_tables",         0,    0, 0,   0,      0,     0,   0,   3,   24,  0,      0,  1,  1 },
    { "mkfifo_exists",         0,    0, 0,   0,  EEXIST,    0,   0,   2,   16,  0,      0,  1,  1 },
    { "app_init_fail",        -1,    0, 0,   0,      0,     0,   0,   2,   16,  0,     -1,  0,  0 },
    { "null_ctrl",             0,    1, 0,   0,      0,     0,   0,   2,   16,  0,     -1,  0,  0 },
    { "null_csi",              0,    0, 1,   0,      0,     0,   0,   2,   16,  0,     -1,  0,  0 },
    { "curr_map_fail",         0,    0, 0,   2,      0,     0,   0,   2,   16,  0,     -1,  0,  0 },
    { "pending_map_fail",      0,    0, 0,   3,      0,     0,   0,   2,   16,  0,     -1,  0,  0 },
    { "mkfifo_fail",           0,    0, 0,   0,  EACCES,    0,   0,   2,   16,  0,     -1,  0,  0 },
    { "bus_open_fail",         0,    0, 0,   0,      0,     1,   0,   2,   16,  0,     -1,  0,  1 },
    { "bus_reg_fail",          0,    0, 0,   0,      0,     0,   1,   2,   16,  0,      0,  1,  1 },
    { NULL, 0,0,0,0,0,0,0,0,0,0,0,0,0 }  /* sentinel */
};

void construct_levl_init_input(const lv_lli_test_case_t *tc)
{
    memset(lli_app_buf, 0, sizeof(lli_app_buf));
    memset(lli_csi_buf, 0, sizeof(lli_csi_buf));
    memset(lli_ctrl_buf, 0, sizeof(lli_ctrl_buf));
    lli_app_init_ret = tc->app_init_ret; lli_null_ctrl = tc->null_ctrl; lli_null_csi = tc->null_csi;
    lli_map_fail_at = tc->map_fail_at; lli_mkfifo_err = tc->mkfifo_err;
    lli_bus_open_ret = tc->bus_open_ret; lli_bus_reg_ret = tc->bus_reg_ret;
    lli_radios = tc->radios; lli_vaps = tc->vaps;
    lli_app_init_calls = lli_map_calls = lli_sched_calls = lli_mkfifo_calls = 0;
    lli_open_calls = lli_reg_calls = lli_mutex_init_calls = 0;
    lli_reg_n = 0; lli_reg_names_ok = 0; lli_reg_rows0 = lli_reg_rows10 = -1;
    lli_reg_first[0] = lli_reg_last[0] = 0; lli_sched_period = 0;

    struct wifi_app *app = (struct wifi_app *)lli_app_buf;
    app->data.u.levl.max_num_csi_clients = 99;
    app->data.u.levl.sounding_duration = 1;
    app->data.u.levl.csi_fd = 42;
    app->data.u.levl.csi_event_subscribed = true;
    for (int i = 0; i < 3; i++) app->data.u.levl.temperature_event_subscribed[i] = true;
    app->data.u.levl.lock_initialized = tc->lock_inited ? true : false;
}
