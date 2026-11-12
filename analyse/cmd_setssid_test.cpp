/*
 * TEST RUNNER: cmd_setssid_test
 *
 * Poisoned around the call:
 *   - every input property's string value: bytes past raw_data_len (and past the
 *     whole value slot) - catches the tr181_copy_prop_string / strnlen / strcmp /
 *     memcpy reading past the value;
 *   - the configuration JSON that get_config() hands out: bytes past its NUL
 *     (cfg_store) - catches cJSON_Parse / the buffer copy reading past the text.
 * The internal arrays (ssid[33], passphrase[64], band[17], addremove[17],
 * HaulType[33], AKMsAllowed[33], buff[], tok_buf[33]) are guarded by ASan redzones.
 * PASS = return code matches expect_rc, the status output matches, accept cases
 * sent the JSON (io_process called once, substring present / absent), reject cases
 * sent nothing, and the heap is back at its starting size (a growth is a leak).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
extern "C" size_t __sanitizer_get_current_allocated_bytes(void);
#include "common.h"

namespace css {

static int call_once(const test_case_t *tc, ccs::bus_error_t *rc_out, ccs::bus_data_prop_t **out)
{
    size_t cfg_used = strlen(cfg_store) + 1;

    /* POISON */
    __asan_poison_memory_region(&cfg_store[cfg_used], sizeof(cfg_store) - cfg_used);              /* config JSON past NUL */
    for (int i = 0; i < num_props; i++) {
        if (props_buf[i].value.data_type == ccs::bus_data_type_string) {
            size_t used = props_buf[i].value.raw_data_len;
            __asan_poison_memory_region(&val_buf[i][used], (CSS_VAL_SZ + CSS_PAD) - used);        /* value past raw_data_len */
        }
    }

    *rc_out = invoke(tc->no_props ? NULL : (num_props ? &props_buf[0] : NULL), tc->no_out ? NULL : out);

    /* UNPOISON */
    for (int i = 0; i < num_props; i++) {
        if (props_buf[i].value.data_type == ccs::bus_data_type_string) {
            size_t used = props_buf[i].value.raw_data_len;
            __asan_unpoison_memory_region(&val_buf[i][used], (CSS_VAL_SZ + CSS_PAD) - used);
        }
    }
    __asan_unpoison_memory_region(&cfg_store[cfg_used], sizeof(cfg_store) - cfg_used);
    return 0;
}

static void free_out(ccs::bus_data_prop_t *out)
{
    if (!out) return;
    free(out->value.raw_data.bytes);
    free(out);
}

int test_one(const test_case_t *tc)
{
    ccs::bus_error_t rc = ccs::bus_error_general;
    ccs::bus_data_prop_t *out = NULL;
    io_calls = 0;
    last_status[0] = '\0';
    size_t before = __sanitizer_get_current_allocated_bytes();
    call_once(tc, &rc, &out);
    free_out(out);
    size_t after = __sanitizer_get_current_allocated_bytes();
    int ok = ((int)rc == tc->expect_rc);
    const char *want = (tc->expect_rc == 0) ? "Success" : "Failure";
    ok = ok && (tc->no_out || !strcmp(last_status, want));
    if (tc->expect_rc == 0) {
        ok = ok && io_calls == 1 && (!tc->json_has || strstr(io_json, tc->json_has)) && (!tc->json_not || !strstr(io_json, tc->json_not));
    } else {
        ok = ok && io_calls == 0;      /* nothing sent on reject */
    }
    printf("    rc=%d (expect %d) status=%s io_calls=%d", (int)rc, tc->expect_rc, last_status, io_calls);
    if (tc->expect_rc == 0 && io_calls == 1) printf(" json=%.150s", io_json);
    printf("\n");
    if (after != before) { printf("    LEAK: heap grew by %zu bytes\n", after - before); ok = 0; }
    return ok;
}

} /* namespace css */

void run_all_tests_cmd_setssid(void)
{
    int pass = 0, fail = 0;
    for (int i = 0; css::suite[i].test_name != NULL; i++) {
        css::test_case_t *test = &css::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        css::construct_input(test);
        int ok = css::test_one(test);
        if (ok) { pass++; printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("cmd_setssid: %d pass, %d fail\n", pass, fail);
}
