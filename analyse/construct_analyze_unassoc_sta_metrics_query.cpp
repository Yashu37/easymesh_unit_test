/*
 * TEST CASES / CONSTRUCTOR: construct_analyze_unassoc_sta_metrics_query
 *
 * The JSON is copied into uaq::evt_buf = event header + subdoc.buff (the runner poisons everything past
 * the NUL and the event's guard field). pcmd[] is uaq::pcmd_buf with EM_MAX_CMD (16) usable slots (the
 * runner poisons slot 16 onward). The recorded query is summarised as
 *   "al=<mac> nop=<n> oc<i>=<class>/<channels> c<i>.<j>=<channel>/<stas> s<i>.<j>.<k>=<mac>"
 * (first 3 of each level). gen=1..6 build the over/at-limit cases: 49 / 48 opclasses (capped at 48),
 * 17 / 16 channels (capped at 16), 65 / 64 STA MACs (capped at 64).
 *
 * expect_num: 1 = command built, 0 = rejected. The handler already caps every count, so there is no
 * abort: cases marked [spec] are wrong behaviour (no abort): an entry that is skipped (missing channels /
 * sta_macs, non-string STA) is still counted in num_opclass / num_channels / num_sta and leaves a zeroed
 * entry in the query, and opclass / channel values that do not fit in a byte are silently truncated
 * (300 -> 44, 256 -> 0, -1 -> 255); an AlMac with trailing text is accepted. Not tested (the result is
 * uninitialised stack data, so it is not deterministic): STA / AlMac strings that are not hex MACs
 * (dm_easy_mesh_t::string_to_macbytes leaves mac[] uninitialised when sscanf matches fewer than 6 fields).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "analyze_unassoc_sta_metrics_query.h"

namespace uaq {

alignas(16) char evt_buf[UAQ_EVT_SZ];
alignas(16) void *pcmd_buf[UAQ_MAXCMD + UAQ_PCMD_EXTRA];

#define H "{\"wfa-dataelements:UnassocSTAQuery\":{\"AlMac\":\"02:00:00:00:00:01\",\"UnassocStaQueryList\":"
#define HM(m) "{\"wfa-dataelements:UnassocSTAQuery\":{\"AlMac\":" m ",\"UnassocStaQueryList\":"
#define T "}}"
#define STAS "[\"11:22:33:44:55:66\",\"aa:bb:cc:dd:ee:ff\"]"
#define BASE H "[{\"opclass\":115,\"channels\":[{\"channel\":36,\"sta_macs\":" STAS "}]}]" T
#define ONE(oc, ch, sta) H "[{\"opclass\":" oc ",\"channels\":[{\"channel\":" ch ",\"sta_macs\":" sta "}]}]" T
/* {name, json, gen, expect_num, has, not_has, crash} */
#define OK(n, j, has) {n, j, 0, 1, has, NULL, false}
#define RJ(n, j) {n, j, 0, 0, NULL, NULL, false}

test_case_t suite[] = {
 /* ---- valid query ---- */
 OK("ok_basic_almac", BASE, "al=02:00:00:00:00:01 nop=1"),
 OK("ok_basic_opclass", BASE, "oc0=115/1"),
 OK("ok_basic_channel", BASE, "c0.0=36/2"),
 OK("ok_basic_sta0", BASE, "s0.0.0=11:22:33:44:55:66"),
 OK("ok_basic_sta1", BASE, "s0.0.1=aa:bb:cc:dd:ee:ff"),
 OK("ok_almac_no_colons", HM("\"020000000001\"") "[]" T, "al=02:00:00:00:00:01"),
 OK("ok_sta_no_colons", ONE("115", "36", "[\"112233445566\"]"), "s0.0.0=11:22:33:44:55:66"),
 OK("ok_sta_uppercase", ONE("115", "36", "[\"AA:BB:CC:DD:EE:FF\"]"), "s0.0.0=aa:bb:cc:dd:ee:ff"),
 OK("ok_two_opclasses", H "[{\"opclass\":115,\"channels\":[]},{\"opclass\":81,\"channels\":[]}]" T, "oc0=115/0 oc1=81/0"),
 OK("ok_two_channels", H "[{\"opclass\":115,\"channels\":[{\"channel\":36,\"sta_macs\":[]},{\"channel\":40,\"sta_macs\":[\"11:22:33:44:55:66\"]}]}]" T, "c0.0=36/0 c0.1=40/1"),
 OK("ok_empty_list", H "[]" T, "nop=0"),
 OK("ok_empty_channels", H "[{\"opclass\":115,\"channels\":[]}]" T, "oc0=115/0"),
 OK("ok_empty_stas", ONE("115", "36", "[]"), "c0.0=36/0"),
 OK("ok_extra_fields_ignored", H "[{\"opclass\":115,\"x\":1,\"channels\":[{\"channel\":36,\"y\":2,\"sta_macs\":[]}]}],\"Other\":5" T, "oc0=115/1"),
 OK("ok_opclass_zero", ONE("0", "36", "[]"), "oc0=0/1"),
 OK("ok_opclass_255", ONE("255", "36", "[]"), "oc0=255/1"),
 /* ---- count limits (capped by the handler) ---- */
 {"ok_49_opclasses_capped_to_48", NULL, 1, 1, "nop=48", NULL, false},
 {"ok_48_opclasses", NULL, 2, 1, "nop=48", NULL, false},
 {"ok_17_channels_capped_to_16", NULL, 3, 1, "oc0=100/16", NULL, false},
 {"ok_16_channels", NULL, 4, 1, "oc0=100/16", NULL, false},
 {"ok_65_stas_capped_to_64", NULL, 5, 1, "c0.0=36/64", NULL, false},
 {"ok_64_stas", NULL, 6, 1, "c0.0=36/64", NULL, false},
 /* ---- rejected ---- */
 RJ("rej_empty_string", ""),
 RJ("rej_invalid_json", "{"),
 RJ("rej_json_null", "null"),
 RJ("rej_top_level_array", "[]"),
 RJ("rej_missing_wfa_object", "{\"other\":{}}"),
 RJ("rej_missing_almac", "{\"wfa-dataelements:UnassocSTAQuery\":{\"UnassocStaQueryList\":[]}}"),
 RJ("rej_missing_query_list", "{\"wfa-dataelements:UnassocSTAQuery\":{\"AlMac\":\"02:00:00:00:00:01\"}}"),
 RJ("rej_query_list_not_array", H "{}" T),
 RJ("rej_almac_number", HM("5") "[]" T),
 RJ("rej_almac_null", HM("null") "[]" T),
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_skipped_opclass_still_counted", H "[{\"opclass\":115},{\"opclass\":81,\"channels\":[{\"channel\":1,\"sta_macs\":[\"11:22:33:44:55:66\"]}]}]" T, 0, 1, "nop=1 oc0=81/1", NULL, false},
 {"spec_skipped_channel_still_counted", H "[{\"opclass\":115,\"channels\":[{\"channel\":36},{\"channel\":40,\"sta_macs\":[\"11:22:33:44:55:66\"]}]}]" T, 0, 1, "oc0=115/1 c0.0=40/1", NULL, false},
 {"spec_nonstring_sta_still_counted", ONE("115", "36", "[\"11:22:33:44:55:66\",123]"), 0, 1, "c0.0=36/1", NULL, false},
 RJ("spec_opclass_300_truncated_to_44", ONE("300", "36", "[]")),
 RJ("spec_opclass_negative_truncated", ONE("-1", "36", "[]")),
 RJ("spec_channel_256_truncated_to_0", ONE("115", "256", "[]")),
 RJ("spec_channel_negative_truncated", ONE("115", "-1", "[]")),
 RJ("spec_almac_trailing_text_accepted", HM("\"02:00:00:00:00:01zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"") "[]" T),

 { NULL, NULL, 0, 0, NULL, NULL, false }  /* sentinel */
};

static void gen_json(int gen, char *out, size_t n)
{
    size_t l = (size_t)snprintf(out, n, "%s", H);
    #define APP(...) l += (size_t)snprintf(out + l, n - l, __VA_ARGS__)
    int cnt = 0;
    APP("[");
    if (gen == 1 || gen == 2) {
        cnt = gen == 1 ? 49 : 48;
        for (int i = 0; i < cnt; i++) APP("%s{\"opclass\":%d,\"channels\":[]}", i ? "," : "", 100 + (i ? i : 0));
        /* first entry keeps opclass 100 */
    } else if (gen == 3 || gen == 4) {
        cnt = gen == 3 ? 17 : 16;
        APP("{\"opclass\":100,\"channels\":[");
        for (int j = 0; j < cnt; j++) APP("%s{\"channel\":%d,\"sta_macs\":[]}", j ? "," : "", 36 + j);
        APP("]}");
    } else {
        cnt = gen == 5 ? 65 : 64;
        APP("{\"opclass\":100,\"channels\":[{\"channel\":36,\"sta_macs\":[");
        for (int k = 0; k < cnt; k++) APP("%s\"02:00:00:00:00:%02x\"", k ? "," : "", k);
        APP("]}]}");
    }
    APP("]%s", T);
}

void construct_input(const test_case_t *tc)
{
    memset(evt_buf, 0, sizeof(evt_buf));
    char *buff = ((em_bus_event_t *)evt_buf)->u.subdoc.buff;
    size_t room = UAQ_EVT_SZ - offsetof(em_bus_event_t, u.subdoc.buff);
    if (tc->gen) gen_json(tc->gen, buff, room);
    else snprintf(buff, room, "%s", tc->json);
    g_num = 0;
}

void teardown(void) {}

} /* namespace uaq */
