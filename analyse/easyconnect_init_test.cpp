/*
 * TEST RUNNER: easyconnect_init
 *
 * Poisoned around the call:
 *   - the caller's app (wifi_app_t): bytes past the struct;
 *   - the ctrl stand-in: bytes past the 256-byte handle stub.
 * data_elements[2] is an internal stack array (ASan stack redzones guard it).
 *
 * PASS = return code matches the stubbed app_init / bus_reg outcome, the bus
 * registration is called the expected number of times, and on the success
 * path exactly the two expected elements (BSSInfo + TriggerStaScan, with a
 * non-NULL scan method cb) were registered. easyconnect_init builds a fixed
 * 2-entry read-only table, so no out-of-bounds write is possible.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int easyconnect_init(wifi_app_t *app, unsigned int create_flags);

extern char eci_app_buf[];
extern char eci_ctrl_buf[];

int test_easyconnect_init(const easyconnect_init_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&eci_app_buf[sizeof(wifi_app_t)], EC_PAD);
    __asan_poison_memory_region(&eci_ctrl_buf[256], EC_PAD);

    int ret = easyconnect_init((wifi_app_t *)eci_app_buf, 0);

    /* UNPOISON */
    __asan_unpoison_memory_region(&eci_ctrl_buf[256], EC_PAD);
    __asan_unpoison_memory_region(&eci_app_buf[sizeof(wifi_app_t)], EC_PAD);

    int ok = (ret == tc->want_ret) && (ec_bus_reg_calls == tc->want_bus_calls) && (ec_app_init_calls == 1);
    if (ok && tc->want_bus_calls == 1 && tc->want_ret == 0) {
        ok = (ec_bus_reg_n == 2) &&
             (strcmp(ec_elem0_name, "Device.WiFi.EC.BSSInfo") == 0) &&
             (strcmp(ec_elem1_name, "Device.WiFi.EC.TriggerStaScan") == 0) &&
             (ec_elem1_set_cb != NULL);
    }
    printf("    ret=%d bus_calls=%d n=%d elem0=\"%s\" elem1=\"%s\" scan_cb=%s\n",
           ret, ec_bus_reg_calls, ec_bus_reg_n, ec_elem0_name, ec_elem1_name,
           ec_elem1_set_cb ? "set" : "null");
    return ok;
}

void run_all_tests_easyconnect_init(void)
{
    for (int i = 0; easyconnect_init_suite[i].test_name != NULL; i++) {
        easyconnect_init_test_case_t *test = &easyconnect_init_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_easyconnect_init_input(test);
        int pass = test_easyconnect_init(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
