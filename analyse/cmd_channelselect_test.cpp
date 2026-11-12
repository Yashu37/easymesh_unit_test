/*
 * TEST RUNNER: cmd_channelselect_test
 *
 * Poisoned around the call:
 *   - the caller's method_name: bytes past strlen+1 (catches name += 34 and
 *     get_table_instance() walking past the NUL);
 *   - every input property's string value: bytes past raw_data_len (and past
 *     the whole value slot's NUL) - catches strtol / strnlen / memcpy / the
 *     tr181 copy reading past the value.
 * The internal arrays (prop_name[128], tokens[6], list_str[256], buff[],
 * instance[32], classes[]) are guarded by ASan redzones / heap checks.
 * PASS = return code matches expect_rc, the status output matches, accept cases
 * sent the JSON (io_process called once, substring present) and reject cases
 * sent nothing. Cases named CRASH_* are expected to abort: each runs in a
 * forked child (ASan report goes to stderr) and passes when the child aborts.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

namespace ccs {

static int call_once(const test_case_t *tc, bus_error_t *rc_out, bus_data_prop_t **out)
{
    const char *method = tc->method ? method_buf : NULL;
    size_t mlen = strlen(method_buf) + 1;

    /* POISON */
    if (tc->method) __asan_poison_memory_region(&method_buf[mlen], sizeof(method_buf) - mlen);   /* method_name past NUL */
    for (int i = 0; i < num_props; i++) {
        if (props_buf[i].value.data_type == bus_data_type_string) {
            size_t used = props_buf[i].value.raw_data_len;
            __asan_poison_memory_region(&val_buf[i][used], (CCS_VAL_SZ + CCS_PAD) - used);        /* value past raw_data_len */
        }
    }

    *rc_out = invoke(method, tc->no_props ? NULL : (num_props ? &props_buf[0] : NULL), out);

    /* UNPOISON */
    for (int i = 0; i < num_props; i++) {
        if (props_buf[i].value.data_type == bus_data_type_string) {
            size_t used = props_buf[i].value.raw_data_len;
            __asan_unpoison_memory_region(&val_buf[i][used], (CCS_VAL_SZ + CCS_PAD) - used);
        }
    }
    if (tc->method) __asan_unpoison_memory_region(&method_buf[mlen], sizeof(method_buf) - mlen);
    return 0;
}

static void free_out(bus_data_prop_t *out)
{
    if (!out) return;
    free(out->value.raw_data.bytes);
    free(out);
}

int test_one(const test_case_t *tc)
{
    bus_error_t rc = bus_error_general;
    bus_data_prop_t *out = NULL;
    call_once(tc, &rc, &out);
    int ok = ((int)rc == tc->expect_rc);
    const char *want = (tc->expect_rc == 0) ? "Success" : "Failure";
    ok = ok && out && !strcmp(last_status, want);
    if (tc->expect_rc == 0) {
        ok = ok && io_calls == 1 && (!tc->json_has || strstr(io_json, tc->json_has));
    } else {
        ok = ok && io_calls == 0;      /* nothing sent on reject */
    }
    printf("    rc=%d (expect %d) status=%s io_calls=%d", (int)rc, tc->expect_rc, last_status, io_calls);
    if (tc->expect_rc == 0 && io_calls == 1) printf(" json=%.110s", io_json);
    printf("\n");
    free_out(out);
    return ok;
}

/* run one expected-abort case in a child; return 1 if it aborted */
static int test_crash(const test_case_t *tc)
{
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        bus_error_t rc; bus_data_prop_t *out = NULL;
        call_once(tc, &rc, &out);
        _exit(0);                    /* survived: no abort */
    }
    int st = 0;
    waitpid(pid, &st, 0);
    int aborted = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("    child %s (status 0x%x)\n", aborted ? "ABORTED (ASan/SEGV above)" : "survived", st);
    return aborted;
}

} /* namespace ccs */

void run_all_tests_cmd_channelselect(void)
{
    int pass = 0, fail = 0, crashes = 0;
    for (int i = 0; ccs::suite[i].test_name != NULL; i++) {
        ccs::test_case_t *test = &ccs::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        ccs::construct_input(test);
        int ok;
        if (test->crash) { ok = ccs::test_crash(test); if (ok) crashes++; }
        else             ok = ccs::test_one(test);
        if (ok) { pass++; printf("================== %s: \033[32m%s\033[0m ==============\n", test->test_name, test->crash ? "CRASH CONFIRMED" : "PASS"); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("cmd_channelselect: %d pass, %d fail (%d crash cases confirmed)\n", pass, fail, crashes);
}
