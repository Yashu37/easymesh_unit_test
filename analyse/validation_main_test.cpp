/*
 * TEST RUNNER: validation_main_test
 *
 * Poisoned around the call: VMN_GUARD bytes in front of and behind the scripted stdin values (type, profile, success/failure), so a
 * scanf beyond the three answers is reported; main's buff[1024] is covered by an ASan redzone, and test_validation reads exactly sz
 * bytes of it. PASS for a valid selection = one test_validation call with the right type / profile / size, the right builder and
 * flag; [spec] cases expect no call at all. Nothing in this function aborts, so there are no crash_* cases.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "validation_main.h"

namespace vmn {
static void poison(bool on)
{
    void *r[2] = { (char *)g_script - VMN_GUARD, (char *)g_script + 3 * sizeof(int) };
    for (int i = 0; i < 2; i++) { if (on) __asan_poison_memory_region(r[i], VMN_GUARD); else __asan_unpoison_memory_region(r[i], VMN_GUARD); }
}
static int check_valid(int user_type, int user_profile, int user_i, int build_len)
{
    return g_calls == 1 && g_vtype == g_type_of_case[user_type] && g_vprofile == user_profile && g_vsz == (unsigned)build_len &&
           g_builder == g_builder_of_case[user_type] && g_vi == user_i;
}
static int test_one(const test_case_t *tc)
{
    int ok = 1;
    if (tc->sweep) {
        int n = 0;
        for (int t = 1; t <= 67; t++) {
            if (!g_type_of_case[t]) continue;
            g_script_pos = 0; g_script[0] = t; g_script[1] = tc->user_profile; g_script[2] = tc->user_i;
            g_calls = 0; g_builder = 0;
            poison(true); invoke(); poison(false);
            if (!check_valid(t, tc->user_profile, tc->user_i, tc->build_len)) { ok = 0; printf("    type %d: wrong call (calls=%d type=%d builder=%d)\n", t, g_calls, g_vtype, g_builder); }
            n++;
        }
        printf("    swept %d message types\n", n);
    } else {
        poison(true); invoke(); poison(false);
        if (tc->expect_calls == 1) ok = (tc->n_inputs == 2) ? (g_calls == 1 && g_vsz == (unsigned)tc->build_len) : check_valid(tc->user_type, tc->user_profile, tc->user_i, tc->build_len);
        else ok = g_calls == 0;
        printf("    test_validation calls=%d (expect %d) type=%d profile=%d sz=%u builder=%d\n", g_calls, tc->expect_calls, g_vtype, g_vprofile, g_vsz, g_builder);
    }
    fflush(stdout);
    return ok;
}
} /* namespace vmn */

void run_all_tests_validation_main(void)
{
    int pass = 0, fail = 0;
    for (int i = 0; vmn::suite[i].test_name != NULL; i++) {
        vmn::test_case_t *test = &vmn::suite[i];
        printf("--- Running Test: %s ---\n", test->test_name); fflush(stdout);
        vmn::construct_input(test);
        int ok = vmn::test_one(test);
        vmn::teardown();
        if (ok) { pass++; printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name); }
        else    { fail++; printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name); }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    printf("validation_main: %d pass, %d fail (0 crash cases confirmed)\n", pass, fail);
}
