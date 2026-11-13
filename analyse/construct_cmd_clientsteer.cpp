/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_clientsteer
 *
 * method_name is copied into method_buf (runner poisons past strlen+1). Each property gets
 * name[128], a value buffer val_buf[i] (runner poisons past raw_data_len) and is linked through
 * next_data. One device 1 / radio 1 / BSS 1 / STA 1 exists (or the MAC aliases
 * 02:00:00:00:00:01, :10:01, :10:11, :10:21).
 *
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input, 22 invalid_method,
 * 25 invalid_namespace). Accept cases also check the JSON handed to io_process. Cases marked [spec]
 * are wrong behaviour without an abort (an unknown RequestMode answers out_of_resources, TargetBSSID
 * is not validated and truncated at 32, RequestMode truncated at 24, the JSON key keeps the caller's
 * case, a window of 0 is dropped). The crash_* cases (NULL method_name, method name shorter than
 * the Network prefix, path that stops before the Device / Radio / BSS / STA instance) ABORT on the
 * original handler: they run last and UNFORKED (a plain make stops at the first ASan report);
 * FORK_CRASH=1 runs each in a forked child so all of them show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_clientsteer.h"

namespace ccl {

alignas(16) char method_buf[256 + CCL_PAD];
ccs::bus_data_prop_t props_buf[CCL_MAXP];
alignas(16) char val_buf[CCL_MAXP][CCL_VAL_SZ + CCL_PAD];
int num_props = 0;

#define N "Device.WiFi.DataElements.Network."
#define P N "Device.1.Radio.1.BSS.1.STA.1.ClientSteer()"
#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define B(n, v)   {n, 6, NULL, v, 0}
#define R(n, c, l) {n, 5, c, 0, l}
#define E0 {NULL, 0, NULL, 0, 0}
#define TB(v) S("TargetBSSID", v)
#define RM(v) S("RequestMode", v)
#define IM(v) B("BTMDisassociationImminent", v)
#define BR(v) B("BTMAbridged", v)
#define LK(v) B("LinkRemovalImminent", v)
#define WN(v) I32("SteeringOpportunityWindow", v)
#define TM(v) I32("BTMDisassociationTimer", v)
#define OC(v) I32("TargetBSSOperatingClass", v)
#define CH(v) I32("TargetBSSChannel", v)
#define T1 "aa:bb:cc:dd:ee:ff"
#define BASE TB(T1), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115), CH(36)
#define OK(n, j, ...) {n, P, false, false, {__VA_ARGS__, E0}, 0, j, false}
#define RJ(n, ...) {n, P, false, false, {__VA_ARGS__, E0}, 2, NULL, false}
#define RP(n, m, rc) {n, m, false, false, {BASE, E0}, rc, NULL, false}
#define CR(n, m) {n, m, false, false, {BASE, E0}, 25, NULL, true}

test_case_t suite[] = {
 /* ---- accepted ---- */
 OK("ok_mandate", "\"TargetBSSID\":\"" T1 "\",\"RequestMode\":{\"Steering_Mandate\":1},\"BTMDisassociationImminent\":false,\"BTMAbridged\":false,\"BTMDisassociationTimer\":10,\"TargetBSSOperatingClass\":115,\"TargetBSSChannel\":36", BASE),
 OK("ok_opportunity_with_window", "\"RequestMode\":{\"Steering_Opportunity\":0},", TB(T1), RM("Steering_Opportunity"), IM(0), BR(0), WN(20), TM(10), OC(115), CH(36)),
 OK("ok_opportunity_window_in_json", "\"SteeringOpportunityWindow\":20", TB(T1), RM("Steering_Opportunity"), IM(0), BR(0), WN(20), TM(10), OC(115), CH(36)),
 OK("ok_imminent_bridged_true", "\"BTMDisassociationImminent\":true,\"BTMAbridged\":true", TB(T1), RM("Steering_Mandate"), IM(1), BR(1), TM(10), OC(115), CH(36)),
 OK("ok_link_removal", "\"LinkRemovalImminent\":true", BASE, LK(1)),
 OK("ok_timer_0", "\"BTMDisassociationTimer\":0", TB(T1), RM("Steering_Mandate"), IM(0), BR(0), TM(0), OC(115), CH(36)),
 OK("ok_mode_uppercase", "\"STEERING_MANDATE\":1", TB(T1), RM("STEERING_MANDATE"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 OK("ok_window_ignored_for_mandate", "\"SteeringOpportunityWindow\":5", BASE, WN(5)),
 OK("ok_params_any_order", "\"TargetBSSChannel\":36", CH(36), OC(115), TM(10), BR(0), IM(0), RM("Steering_Mandate"), TB(T1)),
 OK("ok_target_32_chars", "\"TargetBSSID\":\"", R("TargetBSSID", "T", 32), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Radio.[02:00:00:00:10:01].BSS.[02:00:00:00:10:11].STA.[02:00:00:00:10:21].ClientSteer()", false, false, {BASE, E0}, 0, "\"MACAddress\":\"02:00:00:00:10:21\"", false},
 {"ok_output_null", P, false, true, {BASE, E0}, 0, "\"Associated\":true", false},
 /* ---- rejected: method / path ---- */
 RP("rej_method_no_dot", "ClientSteer()", 2),
 RP("rej_wrong_method", N "Device.1.Radio.1.BSS.1.STA.1.Foo()", 22),
 RP("rej_device_not_found", N "Device.9.Radio.1.BSS.1.STA.1.ClientSteer()", 25),
 RP("rej_radio_not_found", N "Device.1.Radio.9.BSS.1.STA.1.ClientSteer()", 25),
 RP("rej_bss_not_found", N "Device.1.Radio.1.BSS.9.STA.1.ClientSteer()", 25),
 RP("rej_sta_not_found", N "Device.1.Radio.1.BSS.1.STA.9.ClientSteer()", 25),
 /* ---- rejected: parameters ---- */
 {"rej_no_params", P, false, false, {E0}, 2, NULL, false},
 RJ("rej_missing_target", RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_missing_mode", TB(T1), IM(0), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_missing_imminent", TB(T1), RM("Steering_Mandate"), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_missing_bridged", TB(T1), RM("Steering_Mandate"), IM(0), TM(10), OC(115), CH(36)),
 RJ("rej_missing_timer", TB(T1), RM("Steering_Mandate"), IM(0), BR(0), OC(115), CH(36)),
 RJ("rej_missing_opclass", TB(T1), RM("Steering_Mandate"), IM(0), BR(0), TM(10), CH(36)),
 RJ("rej_missing_channel", TB(T1), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115)),
 RJ("rej_opportunity_without_window", TB(T1), RM("Steering_Opportunity"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_timer_negative", TB(T1), RM("Steering_Mandate"), IM(0), BR(0), TM(-1), OC(115), CH(36)),
 RJ("rej_opclass_negative", TB(T1), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(-1), CH(36)),
 RJ("rej_channel_negative", TB(T1), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115), CH(-1)),
 RJ("rej_imminent_int_type", TB(T1), RM("Steering_Mandate"), I32("BTMDisassociationImminent", 1), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_timer_string_type", TB(T1), RM("Steering_Mandate"), IM(0), BR(0), S("BTMDisassociationTimer", "10"), OC(115), CH(36)),
 RJ("rej_target_int_type", I32("TargetBSSID", 5), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_unknown_prop", BASE, S("Foo", "bar")),
 RJ("rej_empty_target", TB(""), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 /* ---- [spec]: wrong behaviour, no abort ---- */
 RJ("rej_request_mode_invalid [spec]", TB(T1), RM("Foo"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_target_not_mac [spec]", TB("garbage"), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_target_33_chars [spec]", R("TargetBSSID", "T", 33), RM("Steering_Mandate"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 RJ("rej_mode_25_chars [spec]", TB(T1), R("RequestMode", "S", 25), IM(0), BR(0), TM(10), OC(115), CH(36)),
 OK("ok_mode_canonical_key [spec]", "\"Steering_Mandate\":1", TB(T1), RM("steering_mandate"), IM(0), BR(0), TM(10), OC(115), CH(36)),
 OK("ok_window_0_in_json [spec]", "\"SteeringOpportunityWindow\":0", TB(T1), RM("Steering_Opportunity"), IM(0), BR(0), WN(0), TM(10), OC(115), CH(36)),
 /* ---- CRASH cases (run last, unforked) ---- */
 {"crash_method_null", NULL, false, false, {BASE, E0}, 2, NULL, true},
 CR("crash_method_name_short", "X.ClientSteer()"),
 CR("crash_path_without_device", N "ClientSteer()"),
 CR("crash_path_without_radio", N "Device.1.ClientSteer()"),
 CR("crash_path_without_bss", N "Device.1.Radio.1.ClientSteer()"),
 CR("crash_path_without_sta", N "Device.1.Radio.1.BSS.1.ClientSteer()"),

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
        memset(v, 0, CCL_VAL_SZ + CCL_PAD);
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

} /* namespace ccl */
