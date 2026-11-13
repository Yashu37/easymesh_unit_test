/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_disassociate
 *
 * method_name is copied into method_buf (runner poisons past strlen+1). Each property gets
 * name[128], a value buffer val_buf[i] (runner poisons past raw_data_len) and is linked through
 * next_data. One device 1 / radio 1 / BSS 1 / STA 1 exists (or the MAC aliases
 * 02:00:00:00:00:01, :10:01, :10:11, :10:21).
 *
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input, 22 invalid_method,
 * 25 invalid_namespace). Accept cases also check the JSON handed to io_process. Cases marked [spec]
 * are inputs a strict handler should reject (a ReasonCode above 65535 does not fit the 16-bit
 * 802.11 reason code field). The last 6 cases (NULL method_name, method name shorter than the
 * Network prefix, path that stops before the Device / Radio / BSS / STA instance) ABORTED on the
 * original handler; with fixes 1-2 they are rejected (rc 2). A case flagged crash=true would run
 * last and UNFORKED (FORK_CRASH=1 forks it).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_disassociate.h"

namespace cda {

alignas(16) char method_buf[256 + CDA_PAD];
ccs::bus_data_prop_t props_buf[CDA_MAXP];
alignas(16) char val_buf[CDA_MAXP][CDA_VAL_SZ + CDA_PAD];
int num_props = 0;

#define N "Device.WiFi.DataElements.Network."
#define P N "Device.1.Radio.1.BSS.1.STA.1.Disassociate()"
#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define B(n, v)   {n, 6, NULL, v, 0}
#define R(n, c, l) {n, 5, c, 0, l}
#define E0 {NULL, 0, NULL, 0, 0}
#define TM(v) I32("DisassociationTimer", v)
#define RC(v) I32("ReasonCode", v)
#define SL(v) B("Silent", v)
#define BASE TM(10), RC(3)
#define OK(n, j, ...) {n, P, false, false, {__VA_ARGS__, E0}, 0, j, false}
#define RJ(n, ...) {n, P, false, false, {__VA_ARGS__, E0}, 2, NULL, false}
#define RP(n, m, rc) {n, m, false, false, {BASE, E0}, rc, NULL, false}
#define RJC(n, m) {n, m, false, false, {BASE, E0}, 2, NULL, false}

test_case_t suite[] = {
 /* ---- accepted ---- */
 OK("ok_basic", "\"Disassociate\":{\"DisassociationTimer\":10,\"ReasonCode\":3}", BASE),
 OK("ok_silent_true", "\"ReasonCode\":3,\"Silent\":true", BASE, SL(1)),
 OK("ok_silent_false", "\"Silent\":false", BASE, SL(0)),
 OK("ok_timer_0", "\"DisassociationTimer\":0", TM(0), RC(3)),
 OK("ok_reason_0", "\"ReasonCode\":0", TM(10), RC(0)),
 OK("ok_timer_huge", "\"DisassociationTimer\":2147483647", TM(2147483647), RC(3)),
 OK("ok_params_any_order", "\"DisassociationTimer\":10", SL(1), RC(3), TM(10)),
 OK("ok_json_path_ids", "\"MACAddress\":\"02:00:00:00:10:21\",\"Associated\":true", BASE),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Radio.[02:00:00:00:10:01].BSS.[02:00:00:00:10:11].STA.[02:00:00:00:10:21].Disassociate()", false, false, {BASE, E0}, 0, "\"BSSID\":\"02:00:00:00:10:11\"", false},
 {"ok_output_null", P, false, true, {BASE, E0}, 0, "\"ReasonCode\":3", false},
 /* ---- rejected: method / path ---- */
 RP("rej_method_no_dot", "Disassociate()", 2),
 RP("rej_wrong_method", N "Device.1.Radio.1.BSS.1.STA.1.Foo()", 22),
 RP("rej_device_not_found", N "Device.9.Radio.1.BSS.1.STA.1.Disassociate()", 25),
 RP("rej_radio_not_found", N "Device.1.Radio.9.BSS.1.STA.1.Disassociate()", 25),
 RP("rej_bss_not_found", N "Device.1.Radio.1.BSS.9.STA.1.Disassociate()", 25),
 RP("rej_sta_not_found", N "Device.1.Radio.1.BSS.1.STA.9.Disassociate()", 25),
 /* ---- rejected: parameters ---- */
 {"rej_no_params", P, false, false, {E0}, 2, NULL, false},
 RJ("rej_missing_timer", RC(3)),
 RJ("rej_missing_reason", TM(10)),
 RJ("rej_timer_negative", TM(-1), RC(3)),
 RJ("rej_reason_negative", TM(10), RC(-1)),
 RJ("rej_timer_string_type", S("DisassociationTimer", "10"), RC(3)),
 RJ("rej_reason_string_type", TM(10), S("ReasonCode", "3")),
 RJ("rej_silent_int_type", BASE, I32("Silent", 1)),
 RJ("rej_unknown_prop", BASE, S("Foo", "bar")),
 /* ---- [spec]: should be rejected but are accepted ---- */
 RJ("rej_reason_70000 [spec]", TM(10), RC(70000)),
 RJ("rej_reason_huge [spec]", TM(10), RC(2147483647)),
 /* ---- were CRASH cases on the original handler (now rejected, rc 2) ---- */
 {"rej_method_null", NULL, false, false, {BASE, E0}, 2, NULL, false},
 RJC("rej_method_name_short", "X.Disassociate()"),
 RJC("rej_path_without_device", N "Disassociate()"),
 RJC("rej_path_without_radio", N "Device.1.Disassociate()"),
 RJC("rej_path_without_bss", N "Device.1.Radio.1.Disassociate()"),
 RJC("rej_path_without_sta", N "Device.1.Radio.1.BSS.1.Disassociate()"),

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
        memset(v, 0, CDA_VAL_SZ + CDA_PAD);
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

} /* namespace cda */
