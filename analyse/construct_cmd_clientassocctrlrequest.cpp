/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_clientassocctrlrequest
 *
 * method_name is copied into method_buf (runner poisons past strlen+1). Each property gets
 * name[128], a value buffer val_buf[i] (runner poisons past raw_data_len) and is linked through
 * next_data. One device 1 / radio 1 / BSS 1 exists (or the MAC aliases 02:00:00:00:00:01,
 * 02:00:00:00:10:01, 02:00:00:00:10:11).
 *
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input, 22 invalid_method,
 * 25 invalid_namespace). Accept cases also check the JSON handed to io_process. Cases marked [spec]
 * are inputs a strict handler should reject (StationsList entries are not validated as MACs). The
 * crash_* cases (method name shorter than the Network prefix, path that stops before the Device /
 * Radio / BSS instance) ABORT on the original handler: they run last and UNFORKED (a plain make
 * stops at the first ASan report); FORK_CRASH=1 runs each in a forked child so all of them show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_clientassocctrlrequest.h"

namespace cca {

alignas(16) char method_buf[256 + CCA_PAD];
ccs::bus_data_prop_t props_buf[CCA_MAXP];
alignas(16) char val_buf[CCA_MAXP][CCA_VAL_SZ + CCA_PAD];
int num_props = 0;

#define N "Device.WiFi.DataElements.Network."
#define P N "Device.1.Radio.1.BSS.1.X_AIRTIES_ClientAssocControl()"
#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define B(n, v)   {n, 6, NULL, v, 0}
#define R(n, c, l) {n, 5, c, 0, l}
#define E0 {NULL, 0, NULL, 0, 0}
#define SL(v) S("StationsList", v)
#define BL(v) B("Block", v)
#define PD(v) I32("Period", v)
#define A1 "11:22:33:44:55:66"
#define OK(n, j, ...) {n, P, false, false, {__VA_ARGS__, E0}, 0, j, false}
#define RJ(n, ...) {n, P, false, false, {__VA_ARGS__, E0}, 2, NULL, false}
#define RP(n, m, rc) {n, m, false, false, {SL(A1), BL(1), PD(30), E0}, rc, NULL, false}
#define CR(n, m) {n, m, false, false, {SL(A1), BL(1), PD(30), E0}, 25, NULL, true}

test_case_t suite[] = {
 /* ---- accepted ---- */
 OK("ok_block", "\"StaMacList\":[\"" A1 "\"],\"AssocControl\":0,\"ValidityPeriod\":30", SL(A1), BL(1), PD(30)),
 OK("ok_unblock", "\"AssocControl\":1", SL(A1), BL(0), PD(30)),
 OK("ok_two_stas", "\"StaMacList\":[\"" A1 "\",\"aa:bb:cc:dd:ee:ff\"]", SL(A1 ",aa:bb:cc:dd:ee:ff"), BL(1), PD(5)),
 OK("ok_period_0", "\"ValidityPeriod\":0", SL(A1), BL(1), PD(0)),
 OK("ok_period_65535", "\"ValidityPeriod\":65535", SL(A1), BL(1), PD(65535)),
 OK("ok_trailing_comma", "\"StaMacList\":[\"" A1 "\"]", SL(A1 ","), BL(1), PD(30)),
 OK("ok_params_any_order", "\"ValidityPeriod\":7", PD(7), BL(1), SL(A1)),
 OK("ok_stalist_128_chars", "\"StaMacList\":[\"", R("StationsList", "1", 128), BL(1), PD(30)),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Radio.[02:00:00:00:10:01].BSS.[02:00:00:00:10:11].X_AIRTIES_ClientAssocControl()", false, false, {SL(A1), BL(1), PD(30), E0}, 0, "\"BSSID\":\"02:00:00:00:10:11\"", false},
 {"ok_output_null", P, false, true, {SL(A1), BL(1), PD(30), E0}, 0, "\"AssocControl\":0", false},
 /* ---- rejected: method / path ---- */
 {"rej_method_null", NULL, false, false, {SL(A1), BL(1), PD(30), E0}, 2, NULL, false},
 RP("rej_method_no_dot", "X_AIRTIES_ClientAssocControl()", 2),
 RP("rej_wrong_method", N "Device.1.Radio.1.BSS.1.Foo()", 22),
 RP("rej_device_not_found", N "Device.9.Radio.1.BSS.1.X_AIRTIES_ClientAssocControl()", 25),
 RP("rej_radio_not_found", N "Device.1.Radio.9.BSS.1.X_AIRTIES_ClientAssocControl()", 25),
 RP("rej_bss_not_found", N "Device.1.Radio.1.BSS.9.X_AIRTIES_ClientAssocControl()", 25),
 /* ---- rejected: parameters ---- */
 {"rej_no_params", P, false, false, {E0}, 2, NULL, false},
 RJ("rej_missing_stalist", BL(1), PD(30)),
 RJ("rej_missing_block", SL(A1), PD(30)),
 RJ("rej_missing_period", SL(A1), BL(1)),
 RJ("rej_empty_stalist", SL(""), BL(1), PD(30)),
 RJ("rej_period_negative", SL(A1), BL(1), PD(-1)),
 RJ("rej_period_65536", SL(A1), BL(1), PD(65536)),
 RJ("rej_period_huge", SL(A1), BL(1), PD(2147483647)),
 RJ("rej_block_int_type", SL(A1), I32("Block", 1), PD(30)),
 RJ("rej_period_string", SL(A1), BL(1), S("Period", "30")),
 RJ("rej_stalist_int_type", I32("StationsList", 5), BL(1), PD(30)),
 RJ("rej_unknown_prop", SL(A1), BL(1), PD(30), S("Foo", "bar")),
 RJ("rej_stalist_129_chars", R("StationsList", "1", 129), BL(1), PD(30)),
 RJ("rej_stalist_300_chars", R("StationsList", "1", 150), BL(1), PD(30)),
 /* ---- [spec]: should be rejected but are accepted ---- */
 RJ("rej_sta_not_mac [spec]", SL("garbage"), BL(1), PD(30)),
 RJ("rej_sta_empty_item [spec]", SL(A1 ",,aa:bb:cc:dd:ee:ff"), BL(1), PD(30)),
 /* ---- CRASH cases (run last, unforked) ---- */
 CR("crash_method_name_short", "X.X_AIRTIES_ClientAssocControl()"),
 CR("crash_path_without_device", N "X_AIRTIES_ClientAssocControl()"),
 CR("crash_path_without_radio", N "Device.1.X_AIRTIES_ClientAssocControl()"),
 CR("crash_path_without_bss", N "Device.1.Radio.1.X_AIRTIES_ClientAssocControl()"),

 { NULL, NULL, false, false, {E0}, 0, NULL, false }  /* sentinel */
};

static void add_prop(const char *name, int kind, const char *s, int i, int len)
{
    ccs::bus_data_prop_t *p = &props_buf[num_props];
    memset(p, 0, sizeof(*p));
    snprintf(p->name, sizeof(p->name), "%s", name);
    p->name_len = (uint32_t)strlen(p->name);
    if (kind == 0 || kind == 5) {
        char *v = val_buf[num_props];
        memset(v, 0, CCA_VAL_SZ + CCA_PAD);
        size_t n;
        if (kind == 5) { memset(v, s[0], (size_t)len); n = (size_t)len + 1; }
        else { n = strlen(s) + 1; memcpy(v, s, n); }
        p->value.data_type = ccs::bus_data_type_string;
        p->value.raw_data.bytes = v;
        p->value.raw_data_len = (unsigned int)n;
    } else if (kind == 6) {
        p->value.data_type = (ccs::bus_data_type_t)100;     /* bus_data_type_boolean stand-in */
        p->value.raw_data.u8 = (uint8_t)i;
    } else {
        p->value.data_type = ccs::bus_data_type_int32;
        p->value.raw_data.i32 = i;
    }
    if (num_props > 0) props_buf[num_props - 1].next_data = p;
    num_props++;
}

void construct_input(const test_case_t *tc)
{
    memset(method_buf, 0, sizeof(method_buf));
    if (tc->method) snprintf(method_buf, 256, "%s", tc->method);
    set_ctrl(true);
    num_props = 0;
    for (int i = 0; tc->props[i].name != NULL; i++)
        add_prop(tc->props[i].name, tc->props[i].kind, tc->props[i].s, tc->props[i].i, tc->props[i].len);
}

} /* namespace cca */
