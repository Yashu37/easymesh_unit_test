/*
 * TEST RUNNER: levl_init
 *
 * Poisoned around the call:
 *   - the caller's levl wifi_app (lli_app_buf) past sizeof(struct wifi_app);
 *   - the csi wifi_app stand-in (lli_csi_buf) past sizeof(struct wifi_app);
 *   - the wifi_ctrl_t stand-in (lli_ctrl_buf) past sizeof(wifi_ctrl_t).
 * dataElements[12] is an internal stack array (ASan stack redzones guard it);
 * it is read-only and the registration count is sizeof/sizeof = 12.
 *
 * PASS = return code, bus registration (12 elements, all named, first/last
 * names, table row counts), and the init state written into the app match
 * the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int levl_init(wifi_app_t *app, unsigned int create_flag);

int test_levl_init(const lv_lli_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lli_app_buf[sizeof(struct wifi_app)], LLI_PAD);
    __asan_poison_memory_region(&lli_csi_buf[sizeof(struct wifi_app)], LLI_PAD);
    __asan_poison_memory_region(&lli_ctrl_buf[sizeof(wifi_ctrl_t)], LLI_PAD);

    int ret = levl_init((wifi_app_t *)lli_app_buf, 0);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lli_ctrl_buf[sizeof(wifi_ctrl_t)], LLI_PAD);
    __asan_unpoison_memory_region(&lli_csi_buf[sizeof(struct wifi_app)], LLI_PAD);
    __asan_unpoison_memory_region(&lli_app_buf[sizeof(struct wifi_app)], LLI_PAD);

    struct wifi_app *app = (struct wifi_app *)lli_app_buf;
    int inited = app->data.u.levl.csi_fd == -1;           /* set only after the mkfifo step */
    int ok = (ret == tc->want_ret) && (lli_reg_calls == tc->want_reg) && (inited == tc->want_inited);
    if (tc->want_reg) {
        ok = ok && lli_reg_n == 12 && lli_reg_names_ok &&
             strcmp(lli_reg_first, "Device.WiFi.Events.VAP.{i}.") == 0 &&
             strcmp(lli_reg_last, "Device.WiFi.Events.Radio.{i}.Temperature") == 0 &&
             lli_reg_rows0 == tc->vaps && lli_reg_rows10 == tc->radios;
    }
    if (ret == 0) {   /* full init: state written into the app */
        ok = ok && app->data.u.levl.max_num_csi_clients == 5 && app->data.u.levl.sounding_duration == 2000 &&
             app->data.u.levl.num_current_sounding == 0 && !app->data.u.levl.csi_event_subscribed &&
             !app->data.u.levl.temperature_event_subscribed[0] && !app->data.u.levl.temperature_event_subscribed[1] &&
             !app->data.u.levl.temperature_event_subscribed[2] &&
             app->data.u.levl.csi_app == (wifi_app_t *)lli_csi_buf && app->data.u.levl.lock_initialized &&
             app->data.u.levl.csi_fns.csi_start_fn && app->data.u.levl.csi_fns.csi_stop_fn &&
             lli_sched_calls == 1 && lli_sched_period == 1800000 && app->data.u.levl.probe_collector_sched_handler_id == 77 &&
             lli_mkfifo_calls == 1 && lli_open_calls == 1 && lli_map_calls == 3 &&
             lli_mutex_init_calls == (tc->lock_inited ? 0 : 1);
    }
    printf("    ret=%d (want %d) reg=%d n=%d first=\"%s\" last=\"%s\" rows=%d/%d fd=%d maps=%d sched=%d(%d ms)\n", ret, tc->want_ret,
           lli_reg_calls, lli_reg_n, lli_reg_first, lli_reg_last, lli_reg_rows0, lli_reg_rows10,
           app->data.u.levl.csi_fd, lli_map_calls, lli_sched_calls, lli_sched_period);
    return ok;
}

void run_all_tests_levl_init(void)
{
    for (int i = 0; levl_init_suite[i].test_name != NULL; i++) {
        lv_lli_test_case_t *test = &levl_init_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_levl_init_input(test);
        int pass = test_levl_init(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
