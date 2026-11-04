/*
 * TEST RUNNER: levl_get_handler
 *
 * Poisoned around the call:
 *   - the wifi_ctrl_t stand-in (lgh_ctrl_buf) past sizeof(wifi_ctrl_t);
 *   - the levl wifi_app stand-in (lgh_app_buf) past sizeof(struct wifi_app);
 *   - the caller's raw_data_t out parameter (lgh_pdata_buf) past its size;
 *   - the caller's event_name (lgh_name_buf, exactly strlen+1 bytes) past the
 *     terminating NUL: any over-read of the name by sscanf aborts.
 * parameter[200], mac_string[18] and buff[32] are internal stack arrays
 * guarded by ASan redzones; the result string is a heap block (freed here).
 *
 * PASS = return code, produced data type / value / string match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

typedef enum { bus_error_success = 0, bus_error_general = 1, bus_error_invalid_input = 2, bus_error_out_of_resources = 3 } bus_error_t;
typedef struct { int data_type; union { uint32_t u32; void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { int unused; } bus_user_data_t;
bus_error_t levl_get_handler(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

int test_levl_get_handler(const lv_lgh_test_case_t *tc)
{
    char *name = tc->name ? lgh_name_buf : NULL;
    raw_data_t *pd = (raw_data_t *)lgh_pdata_buf;

    /* POISON */
    __asan_poison_memory_region(&lgh_ctrl_buf[sizeof(wifi_ctrl_t)], LGH_PAD);
    __asan_poison_memory_region(&lgh_app_buf[sizeof(struct wifi_app)], LGH_PAD);
    __asan_poison_memory_region(&lgh_pdata_buf[sizeof(raw_data_t)], LGH_PAD);
    __asan_poison_memory_region(&lgh_name_buf[lgh_name_len], LGH_PAD);

    int ret = (int)levl_get_handler(name, pd, NULL);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lgh_name_buf[lgh_name_len], LGH_PAD);
    __asan_unpoison_memory_region(&lgh_pdata_buf[sizeof(raw_data_t)], LGH_PAD);
    __asan_unpoison_memory_region(&lgh_app_buf[sizeof(struct wifi_app)], LGH_PAD);
    __asan_unpoison_memory_region(&lgh_ctrl_buf[sizeof(wifi_ctrl_t)], LGH_PAD);

    int ok = (ret == tc->want_ret);
    int type = (ret == 0 && tc->want_type != -1) ? pd->data_type : -1;
    ok = ok && (type == tc->want_type || (tc->want_type == -1 && pd->data_type == 0));
    if (tc->want_type == 7) ok = ok && pd->raw_data.u32 == tc->want_u32 && pd->raw_data_len == 4;
    if (tc->want_type == 3) ok = ok && pd->raw_data.bytes && strcmp((char *)pd->raw_data.bytes, tc->want_str) == 0 &&
                                 pd->raw_data_len == strlen(tc->want_str) + 1;
    printf("    ret=%d (want %d) type=%d (want %d) u32=%u len=%zu str=\"%s\"\n", ret, tc->want_ret,
           pd->data_type, tc->want_type, pd->raw_data.u32, pd->raw_data_len,
           (tc->want_type == 3 && pd->raw_data.bytes) ? (char *)pd->raw_data.bytes : "");
    if (pd->data_type == 3 && pd->raw_data.bytes) { free(pd->raw_data.bytes); pd->raw_data.bytes = NULL; }
    return ok;
}

void run_all_tests_levl_get_handler(void)
{
    for (int i = 0; levl_get_handler_suite[i].test_name != NULL; i++) {
        lv_lgh_test_case_t *test = &levl_get_handler_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_levl_get_handler_input(test);
        int pass = test_levl_get_handler(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
