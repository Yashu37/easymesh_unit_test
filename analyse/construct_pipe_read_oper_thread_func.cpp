/*
 * TEST CASES / CONSTRUCTOR: construct_pipe_read_oper_thread_func
 * p_app at prt_app_buf (data.u.csi_analytics.csi_session_index chosen per case).
 * A real regular file at /tmp/csi_motion_pipe<idx> is created (or not) so
 * open() succeeds/fails. is_read_oper_thread_enabled is cleared so the single
 * read + EOF exits the loop.
 * Cases: open-fail (no file), one-read (file has buffer_len bytes).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   prt_slot[PRT_PATH_SZ + PRT_PAD];
int    prt_decode_calls, prt_process_calls, prt_clean_calls;
alignas(16) char prt_app_buf[sizeof(wifi_app_t) + PRT_PAD];

pipe_read_oper_thread_func_test_case_t pipe_read_oper_thread_func_suite[] = {
    /* name        session  make_file  expect_decode */
    { "open_fail",   7001,   0,         0 },
    { "one_read",    7002,   1,         1 },
    { NULL, 0, 0, 0 }
};

void construct_pipe_read_oper_thread_func_input(const pipe_read_oper_thread_func_test_case_t *tc)
{
    memset(prt_app_buf, 0, sizeof(prt_app_buf));
    wifi_app_t *app = (wifi_app_t *)prt_app_buf;
    app->data.u.csi_analytics.csi_session_index = tc->session;

    char path[64];
    snprintf(path, sizeof(path), "/tmp/csi_motion_pipe%d", tc->session);
    remove(path);
    if (tc->make_file) {
        FILE *f = fopen(path, "wb");
        if (f) { char z[512] = {0}; fwrite(z, 1, 100, f); fclose(f); }   /* buffer_len bytes */
    }
    prt_decode_calls = prt_process_calls = prt_clean_calls = 0;
}
