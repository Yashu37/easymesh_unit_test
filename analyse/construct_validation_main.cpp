/*
 * TEST CASES / CONSTRUCTOR: construct_validation_main
 *
 * The scripted stdin gives main the user's three answers (message type, profile, 0 success / 1 failure case). Every builder of the
 * stand-in writes build_len bytes into main's buff[1024] and test_validation reads that many bytes back. PASS for a valid selection =
 * test_validation is called exactly once with the em_msg_type_t main assigns to that number, the chosen profile, sz == build_len, and
 * the builder of that number ran with the typed success / failure flag. [spec] cases: an invalid message type / profile (or stdin
 * closed before the answers) makes main print "invalid" and then still call test_validation with the never-assigned type / profile / sz
 * variables (uninitialised in the original): expect_calls 0 is what the tool should do. No abort is reproducible: a GCC 13 ASan frame is
 * zero-filled, so the indeterminate values read as 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "validation_main.h"

namespace vmn {
/* {name, n_inputs, user_type, user_profile, user_i, build_len, sweep, expect_calls, crash} */
test_case_t suite[] = {
 {"ok_autoconf_search_profile1_success",     3, 1, 1, 0, 100, 0, 1, false},
 {"ok_topo_disc_profile2_success",           3, 5, 2, 0, 100, 0, 1, false},
 {"ok_combined_infra_metrics_profile3",      3, 38, 3, 0, 300, 0, 1, false},
 {"ok_channel_pref_query_failure_case",      3, 16, 2, 1, 100, 0, 1, false},
 {"ok_last_message_type_67",                 3, 67, 2, 0, 100, 0, 1, false},
 {"ok_message_fills_buff_1024_bytes",        3, 17, 2, 0, 1024, 0, 1, false},
 {"ok_empty_message",                        3, 7, 2, 0, 0, 0, 1, false},
 {"ok_every_message_type_sweep",             3, 0, 2, 0, 200, 1, 1, false},
 {"ok_stdin_closed_before_choice_defaults_to_success", 2, 5, 2, 0, 100, 0, 1, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_message_type_0_must_not_validate [spec]",        3, 0, 2, 0, 100, 0, 0, false},
 {"spec_message_type_3_commented_out_must_not_validate [spec]", 3, 3, 2, 0, 100, 0, 0, false},
 {"spec_message_type_4_commented_out_must_not_validate [spec]", 3, 4, 2, 0, 100, 0, 0, false},
 {"spec_message_type_68_must_not_validate [spec]",       3, 68, 2, 0, 100, 0, 0, false},
 {"spec_message_type_negative_must_not_validate [spec]", 3, -1, 2, 0, 100, 0, 0, false},
 {"spec_profile_0_must_not_validate [spec]",             3, 5, 0, 0, 100, 0, 0, false},
 {"spec_profile_4_must_not_validate [spec]",             3, 5, 4, 0, 100, 0, 0, false},
 {"spec_stdin_closed_before_type_must_not_validate [spec]",   0, 0, 0, 0, 100, 0, 0, false},
 {"spec_stdin_closed_before_profile_must_not_validate [spec]", 1, 5, 0, 0, 100, 0, 0, false},
 {NULL, 0, 0, 0, 0, 0, 0, 0, false}
};

void construct_input(const test_case_t *tc)
{
    g_script_n = tc->n_inputs; g_script_pos = 0;
    int *raw = (int *)calloc(1, (VMN_GUARD + 3 * sizeof(int) + VMN_GUARD));    /* [guard][type, profile, i][guard] */
    g_script = (int *)((char *)raw + VMN_GUARD);
    g_script[0] = tc->user_type; g_script[1] = tc->user_profile; g_script[2] = tc->user_i;
    g_build_len = tc->build_len; g_builder = 0; g_calls = 0; g_vtype = -1; g_vprofile = -1; g_vsz = 0; g_vi = -1;
}
void teardown(void) { free((char *)g_script - VMN_GUARD); g_script = NULL; }
} /* namespace vmn */
