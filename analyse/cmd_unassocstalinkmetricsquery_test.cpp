/*
 * TEST RUNNER: cmd_unassocstalinkmetricsquery_test
 *
 * Poisoned around the call:
 *   - the caller's method_name: bytes past strlen+1 (catches name += 34 and
 *     get_table_instance() walking past the NUL);
 *   - every input property's string value: bytes past raw_data_len (and past
 *     the whole value slot's NUL) - catches tr181_copy_prop_string / strtol /
 *     strchr / strstr reading past the value.
 * The internal arrays (instance[32], bssid[33], ssid[33], elem_list[129],
 * ch_rep_items[6], buff[]) are guarded by ASan redzones.
 * PASS = return code matches expect_rc, the status output matches, accept cases
 * sent the JSON (io_process called once, substring present), reject cases sent
 * nothing, and the heap is back at its starting size (a growth is a leak).
 * Cases named crash_* are expected to abort: they run last and UNFORKED so a plain `make`
 * stops with the ASan report; FORK_CRASH=1 runs each in a forked child (passes when it aborts).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "cmd_unassocstalinkmetricsquery.h"
extern "C" size_t __sanitizer_get_current_allocated_bytes(void);

namespace cua {

static int call_once(const test_case_t *tc, ccs::bus_error_t *rc_out, ccs::bus_data_prop_t **out)
{
    const char *method = tc->method ? method_buf : NULL;
    size_t mlen = strlen(method_buf) + 1;

    /* POISON */
    if (tc->method) __asan_poison_memory_region(&method_buf[mlen], sizeof(method_buf) - mlen);   /* method_name past NUL */
    for (int i = 0; i < num_props; i++) {
        if (props_buf[i].value.data_type == ccs::bus_data_type_string) {
            size_t used = props_buf[i].value.raw_data_len;
            __asan_poison_memory_region(&val_buf[i][used], (CUA_VAL_SZ + CUA_PAD) - used);        /* value past raw_data_len */
        }
    }

    *rc_out = cua::invoke(method, tc->no_props ? NULL : (num_props ? &props_buf[0] : NULL), tc->no_out ? NULL : out);

    /* UNPOISON */
    for (int i = 0; i < num_props; i++) {
        if (props_buf[i].value.data_type == ccs::bus_data_type_string) {
            size_t used = props_buf[i].value.raw_data_len;
            __asan_unpoison_memory_region(&val_buf[i][used], (CUA_VAL_SZ + CUA_PAD) - used);
        }
    }
    if (tc->method) __asan_unpoison_memory_region(&method_buf[mlen], sizeof(method_buf) - mlen);
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
    if (tc->expect_rc == 0) ok = ok && io_calls == 1 && (!tc->json_has || strstr(io_json, tc->json_has));
    else                    ok = ok && io_calls == 0;      /* nothing sent on reject */
    printf("    rc=%d (expect %d) status=%s io_calls=%d", (int)rc, tc->expect_rc, last_status, io_calls);
    if (tc->expect_rc == 0 && io_calls == 1) printf(" json=%.150s", io_json);
    printf("\n");
    if (after != before) { printf("    LEAK: heap grew by %zu bytes\n", after - before); ok = 0; }
    return ok;
}

/* run one expected-abort case in a child; return 1 if it aborted */
static int test_crash(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        ccs::bus_error_t rc; ccs::bus_data_prop_t *out = NULL;
        call_once(tc, &rc, &out);
        _exit(0);                    /* survived: no abort */
    }
    int st = 0;
    waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}

} /* namespace cua */

void run_all_tests_cmd_unassocstalinkmetricsquery(void)
{
    int pass = 0, fail = 0, crashes = 0;
    bool fork_crash = getenv("FORK_CRASH") != NULL;
    for (int i = 0; cua::suite[i].test_name != NULL; i++) {
        cua::test_case_t *test = &cua::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        cua::construct_input(test);
        int ok;
        if (test->crash && fork_crash) { ok = cua::test_crash(test); if (ok) crashes++; }
        else                           ok = cua::test_one(test);      /* a crash case aborts the whole run here */
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("cmd_unassocstalinkmetricsquery: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
