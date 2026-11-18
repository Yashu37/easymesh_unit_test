/*
 * TEST CASES / CONSTRUCTOR: construct_dev_test_decode
 *
 * The JSON is copied into dtd::evt_buf = event header + subdoc.buff (the runner poisons everything past
 * the NUL and the event's guard field). decode() fills em_dev_test_info, which starts all zero with haul
 * type fronthaul; the handler only accepts a "DevTest" array of exactly 2 entries (ssid, channel), each
 * entry updating the slot chosen by Test_type ("ssid_change" -> 0, anything else -> 1). The result is
 * summarised (dtd::g_sum) as
 *   "ni=<a>,<b> en=<a>,<b> ip=<a>,<b> done=<a>,<b> st=<a>,<b> haul=<h> em=<s0><s1>.."
 * ni = num_iteration, en = enabled, ip = test_inprogress, done = num_of_iteration_completed, st =
 * test_status (0 inprogress, 1 idle, 2 complete, 3 failed; slots start at 0), em = result of
 * set_devteststatus for each em entry (1 / 0 / - untouched). "" = nothing written (rejected).
 * em_states selects the em entries: bit i set = entry i is configured (state em_state_ctrl_configured),
 * clear = unconfigured; 0 = no entries.
 *
 * Cases marked [spec] are wrong behaviour (no abort): a Test_type that is not "ssid_change" (e.g. a typo or a
 * number) silently selects the channel slot, and a negative No_of_iteration / out of range Haul_type is
 * stored. The case crash_* ABORTS on the original function: "Test_status" that is not a string
 * (tmp->valuestring is NULL and is passed to strncmp). It runs last and UNFORKED so a plain make stops with
 * the ASan report (FORK_CRASH=1 forks it). Not tested (uninitialised stack data, not deterministic): an
 * entry without Test_type (str_type is never initialised).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "dev_test_decode.h"

namespace dtd {

alignas(16) char evt_buf[DTD_EVT_SZ];
em_dev_test_info g_out;
char g_sum[512];

#define H "{\"wfa-dataelements:SetDevTest\":{\"dev_test\":"
#define T "}}"
#define SSID(f) "{\"Test_type\":\"ssid_change\"" f "}"
#define CHAN(f) "{\"Test_type\":\"channel_change\"" f "}"
#define BOTH(a, b) H "[" SSID(a) "," CHAN(b) "]" T
/* {name, json, expect, ems, crash} */
#define OK(n, j, e) {n, j, e, NULL, false}

test_case_t suite[] = {
 /* ---- fields of each slot ---- */
 OK("ok_iterations", BOTH(",\"No_of_iteration\":5", ",\"No_of_iteration\":7"), "ni=5,7 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_enabled", BOTH(",\"Test_enabled\":1", ",\"Test_enabled\":1"), "ni=0,0 en=1,1 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_inprogress", BOTH(",\"Current_iteration_inprogress\":3", ",\"Current_iteration_inprogress\":4"), "ni=0,0 en=0,0 ip=3,4 done=0,0 st=0,0 haul=0 em="),
 OK("ok_completed", BOTH(",\"Num_of_iteration_completed\":2", ",\"Num_of_iteration_completed\":6"), "ni=0,0 en=0,0 ip=0,0 done=2,6 st=0,0 haul=0 em="),
 OK("ok_only_ssid_fields", BOTH(",\"No_of_iteration\":9", ""), "ni=9,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_only_channel_fields", BOTH("", ",\"No_of_iteration\":8"), "ni=0,8 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_empty_entries", BOTH("", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_haul_backhaul", BOTH(",\"Haul_type:[Fronthault:0,Backhaul:1,IOT:2,Configurator:3,Hotspot:4]\":1", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=1 em="),
 OK("ok_haul_hotspot", BOTH("", ",\"Haul_type:[Fronthault:0,Backhaul:1,IOT:2,Configurator:3,Hotspot:4]\":4"), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=4 em="),
 /* ---- Test_type selects the slot ---- */
 OK("ok_ssid_is_slot0", H "[" SSID(",\"No_of_iteration\":3") "," SSID(",\"No_of_iteration\":4") "]" T, "ni=4,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_channel_is_slot1", H "[" CHAN(",\"No_of_iteration\":3") "," CHAN(",\"No_of_iteration\":4") "]" T, "ni=0,4 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_swapped_order", H "[" CHAN(",\"No_of_iteration\":3") "," SSID(",\"No_of_iteration\":4") "]" T, "ni=4,3 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 /* ---- Test_status text (0 inprogress, 1 idle, 2 complete, 3 failed) ---- */
 OK("ok_status_inprogress", BOTH(",\"Test_status\":\"Inprogress\"", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_status_complete", BOTH(",\"Test_status\":\"Complete\"", ",\"Test_status\":\"Complete\""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=2,2 haul=0 em="),
 OK("ok_status_failed", BOTH(",\"Test_status\":\"Failed\"", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=3,0 haul=0 em="),
 OK("ok_status_unknown_ignored", BOTH(",\"Test_status\":\"Bogus\"", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_status_prefix_ignored", BOTH(",\"Test_status\":\"Complet\"", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 OK("ok_status_empty_ignored", BOTH(",\"Test_status\":\"\"", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em="),
 /* ---- Test_enabled = 0 resets status and progress ---- */
 OK("ok_disabled_resets_status", BOTH(",\"Current_iteration_inprogress\":5,\"Test_enabled\":0", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=1,0 haul=0 em="),
 OK("ok_enabled_keeps_status", BOTH(",\"Current_iteration_inprogress\":5,\"Test_enabled\":1", ""), "ni=0,0 en=1,0 ip=5,0 done=0,0 st=0,0 haul=0 em="),
 /* ---- Configure_active_em: 1 marks every em entry by its state and starts the test ---- */
 {"ok_active_em_configured", BOTH(",\"Configure_active_em\":1", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=1", "C", false},
 {"ok_active_em_two_entries", BOTH(",\"Configure_active_em\":1", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=10", "CU", false},
 {"ok_active_em_three_entries", BOTH(",\"Configure_active_em\":1", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=101", "CUC", false},
 {"ok_active_em_zero_ignored", BOTH(",\"Configure_active_em\":0", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=--", "CU", false},
 {"ok_active_em_resets_completed", BOTH(",\"Num_of_iteration_completed\":4,\"Configure_active_em\":1", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=1", "C", false},
 {"ok_active_em_misconfigured_false", BOTH(",\"Configure_active_em\":1", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=0", "M", false},
 {"ok_active_em_unconfigured_false", BOTH(",\"Configure_active_em\":1", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=0", "U", false},
 {"ok_active_em_no_entries", BOTH(",\"Configure_active_em\":1", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=", "", false},
 /* ---- rejected input (nothing written) ---- */
 OK("rej_not_json", "not json", ""),
 OK("rej_empty_text", "", ""),
 OK("rej_missing_setdevtest", "{\"other\":1}", ""),
 OK("rej_missing_dev_test", "{\"wfa-dataelements:SetDevTest\":{}}", ""),
 OK("rej_setdevtest_empty_array", "{\"wfa-dataelements:SetDevTest\":[]}", ""),
 OK("rej_dev_test_empty", H "[]" T, ""),
 OK("rej_dev_test_one_entry", H "[" SSID(",\"No_of_iteration\":3") "]" T, ""),
 OK("rej_dev_test_three_entries", H "[" SSID("") "," CHAN("") "," CHAN("") "]" T, ""),
 OK("rej_dev_test_not_array", H "{\"a\":1,\"b\":2}" T, ""),
 OK("rej_dev_test_number", H "5" T, ""),
 /* ---- [spec]: wrong behaviour, no abort ---- */
 OK("rej_test_type_typo [spec]", H "[{\"Test_type\":\"ssid_chnge\",\"No_of_iteration\":3},{\"Test_type\":\"channel_change\"}]" T, ""),
 OK("rej_negative_iterations [spec]", BOTH(",\"No_of_iteration\":-5", ""), ""),
 OK("rej_haul_out_of_range [spec]", BOTH(",\"Haul_type:[Fronthault:0,Backhaul:1,IOT:2,Configurator:3,Hotspot:4]\":9", ""), ""),
 /* ---- CRASH case on the original function (the status is ignored after the fix) ---- */
 {"crash_status_not_string", BOTH(",\"Test_status\":5", ""), "ni=0,0 en=0,0 ip=0,0 done=0,0 st=0,0 haul=0 em=", NULL, true},

 { NULL, NULL, NULL, 0, false }  /* sentinel */
};

void construct_input(const test_case_t *tc)
{
    memset(evt_buf, 0, sizeof(evt_buf));
    char *buff = ((em_bus_event_t *)evt_buf)->u.subdoc.buff;
    size_t room = DTD_EVT_SZ - offsetof(em_bus_event_t, u.subdoc.buff);
    snprintf(buff, room, "%s", tc->json);
    memset(g_em, 0, sizeof(g_em));
    g_nem = 0;
    for (const char *p = tc->ems; p && *p && g_nem < DTD_MAXEM; p++, g_nem++) {
        g_em[g_nem].devtest = -1;
        g_em[g_nem].state = (*p == 'C') ? em_state_ctrl_configured : (*p == 'M') ? em_state_ctrl_misconfigured : em_state_ctrl_unconfigured;
    }
}

void teardown(void) {}

} /* namespace dtd */
