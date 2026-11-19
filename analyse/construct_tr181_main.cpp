/*
 * TEST CASES / CONSTRUCTOR: construct_tr181_main
 *
 * The scripted stdin gives main the menu numbers (0 controller id, 1 colocated agent id, 2 SetSSID, 3 topology subscribe, anything else
 * is invalid); the bus stand-in answers success or the configured error and records every call (O open, G controller get, g colocated
 * get, I invoke, S subscribe). The tool has no exit command: its loop ends when the user presses Ctrl-C, which the stub models by
 * ending the run when the script is used up (mode 0). PASS = the recorded call sequence, a SetSSID object with the five expected
 * properties, the number of tracked heap objects main still owns at the end, and the way main returned. [spec] cases: wrong
 * behaviour, no abort. rej_* cases ABORTED on the original code (get_bus_descriptor() returning NULL was only printed about, then
 * dereferenced): fix 1 returns.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tr181_main.h"

namespace tmo {
/* {name, n_inputs, {inputs}, mode, open_rc, get_rc, invoke_rc, subs_rc, null_desc, expect_seq, expect_returned, expect_live, expect_no_hang, crash} */
test_case_t suite[] = {
 {"ok_controller_id",                   1, {0}, 0, 0, 0, 0, 0, false, "OG", -1, -1, false, false},
 {"ok_colocated_agent_id",              1, {1}, 0, 0, 0, 0, 0, false, "Og", -1, -1, false, false},
 {"ok_controller_id_get_fails",         1, {0}, 0, 0, 1, 0, 0, false, "OG", -1, -1, false, false},
 {"ok_colocated_agent_id_get_fails",    1, {1}, 0, 0, 1, 0, 0, false, "Og", -1, -1, false, false},
 {"ok_set_ssid_builds_five_properties", 1, {2}, 0, 0, 0, 0, 0, false, "OI", -1, -1, false, false},
 {"ok_set_ssid_invoke_fails",           1, {2}, 0, 0, 0, 1, 0, false, "OI", -1, -1, false, false},
 {"ok_topology_subscribe",              1, {3}, 0, 0, 0, 0, 0, false, "OS", -1, -1, false, false},
 {"ok_topology_subscribe_fails",        1, {3}, 0, 0, 0, 0, 1, false, "OS", -1, -1, false, false},
 {"ok_invalid_input_99",                1, {99}, 0, 0, 0, 0, 0, false, "O", -1, -1, false, false},
 {"ok_negative_input",                  1, {-5}, 0, 0, 0, 0, 0, false, "O", -1, -1, false, false},
 {"ok_all_commands_in_a_row",           6, {0, 1, 2, 3, 99, 0}, 0, 0, 0, 0, 0, false, "OGgISG", -1, -1, false, false},
 {"ok_bus_open_fails_main_returns",     1, {0}, 0, 1, 0, 0, 0, false, "O", 0, -1, false, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_bus_open_failure_must_return_nonzero [spec]", 1, {0}, 0, 1, 0, 0, 0, false, "O", 1, -1, false, false},
 {"spec_stdin_closed_must_end_the_loop [spec]",       0, {0}, 1, 0, 0, 0, 0, false, "O", 1, -1, true, false},
 {"spec_set_ssid_must_not_leak [spec]",               1, {2}, 0, 0, 0, 0, 0, false, "OI", -1, 0, false, false},
 /* ---- was a CRASH case on the original code ---- */
 {"rej_bus_descriptor_null",          1, {0}, 0, 0, 0, 0, 0, true, "", 1, -1, false, false},
 {NULL, 0, {0}, 0, 0, 0, 0, 0, false, NULL, 0, 0, false, false}
};

void construct_input(const test_case_t *tc)
{
    g_script_n = tc->n_inputs; g_script_pos = 0; g_eof_calls = 0; g_mode = tc->mode; g_hung = false; g_ended_by_stdin = false;
    int *raw = (int *)calloc(1, TMO_GUARD + 8 * sizeof(int) + TMO_GUARD);          /* [guard][inputs][guard] */
    g_script = (int *)((char *)raw + TMO_GUARD);
    for (int i = 0; i < 8; i++) g_script[i] = tc->in[i];
    g_open_rc = tc->open_rc; g_get_rc = tc->get_rc; g_invoke_rc = tc->invoke_rc; g_subs_rc = tc->subs_rc; g_null_desc = tc->null_desc;
    g_seq.clear(); g_get_names.clear(); g_free_calls = g_invoke_calls = g_subs_calls = g_inv_props = g_inv_ok = g_subs_ok = 0;
    g_live.clear(); g_returned = false; g_ret = 0;
}
void teardown(void) { free((char *)g_script - TMO_GUARD); g_script = NULL; }
} /* namespace tmo */
