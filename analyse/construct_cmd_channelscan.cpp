/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_channelscan
 *
 * method_name is copied into method_buf (runner poisons past strlen+1). Each property gets
 * name[128], a value buffer val_buf[i] (runner poisons past raw_data_len) and is linked through
 * next_data. One device 1 / radio 1 exists (or the MAC alias 02:00:00:00:00:01 / 02:00:00:00:10:01).
 *
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input, 22 invalid_method,
 * 25 invalid_namespace). Accept cases also check the JSON handed to io_process. Cases marked [spec]
 * are inputs a strict handler should reject (a channel list with OpClass 0 is silently dropped, a
 * 129-character list is silently truncated). The crash_* cases (NULL method_name, method name shorter than the
 * Network prefix, path that stops before the Device / Radio instance) ABORT on the original
 * handler: they run last and UNFORKED (a plain make stops at the first ASan report); FORK_CRASH=1
 * runs each in a forked child so all of them show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_channelscan.h"

namespace ccn {

alignas(16) char method_buf[256 + CCN_PAD];
ccs::bus_data_prop_t props_buf[CCN_MAXP];
alignas(16) char val_buf[CCN_MAXP][CCN_VAL_SZ + CCN_PAD];
int num_props = 0;

#define N "Device.WiFi.DataElements.Network."
#define P N "Device.1.Radio.1.ChannelScanRequest()"
#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define R(n, c, l) {n, 5, c, 0, l}
#define E0 {NULL, 0, NULL, 0, 0}
#define OC(v) I32("OpClass", v)
#define CL(v) S("ChannelList", v)
#define OK(n, j, ...) {n, P, false, false, {__VA_ARGS__, E0}, 0, j, false}
#define RJ(n, ...) {n, P, false, false, {__VA_ARGS__, E0}, 2, NULL, false}
#define RP(n, m, rc) {n, m, false, false, {OC(115), CL("36"), E0}, rc, NULL, false}
#define CR(n, m) {n, m, false, false, {OC(115), CL("36"), E0}, 25, NULL, true}

test_case_t suite[] = {
 /* ---- accepted ---- */
 {"ok_no_params", P, false, false, {E0}, 0, "\"ChannelScanParameters\":[{}]", false},
 {"ok_no_props_null", P, true, false, {E0}, 0, "\"ChannelScanParameters\":[{}]", false},
 OK("ok_class_and_list", "\"Class\":115,\"ChannelList\":[36,40]", OC(115), CL("36,40")),
 OK("ok_single_channel", "\"ChannelList\":[149]", OC(125), CL("149")),
 OK("ok_trailing_comma", "\"ChannelList\":[36]", OC(115), CL("36,")),
 OK("ok_scan_type_ignored", "\"ChannelScanParameters\":[{}]", S("ScanType", "1"), I32("DwellTime", 20), I32("DFSDwellTime", 30), I32("HomeTime", 5)),
 OK("ok_op_class_negative_no_list", "\"ChannelScanParameters\":[{}]", OC(-5)),
 OK("ok_list_127_chars", "\"ChannelList\":[", OC(115), R("ChannelList", "1", 127)),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Radio.[02:00:00:00:10:01].ChannelScanRequest()", false, false, {OC(115), CL("36"), E0}, 0, "\"Class\":115", false},
 {"ok_output_null", P, false, true, {OC(115), CL("36"), E0}, 0, "\"ChannelList\":[36]", false},
 /* ---- rejected: method / path ---- */
 RP("rej_method_no_dot", "ChannelScanRequest()", 2),
 RP("rej_wrong_method", N "Device.1.Radio.1.Foo()", 22),
 RP("rej_device_not_found", N "Device.9.Radio.1.ChannelScanRequest()", 25),
 RP("rej_radio_not_found", N "Device.1.Radio.9.ChannelScanRequest()", 25),
 /* ---- rejected: parameters ---- */
 RJ("rej_class_without_list", OC(115)),
 RJ("rej_list_without_class", CL("36")),
 RJ("rej_list_with_negative_class", OC(-1), CL("36")),
 RJ("rej_op_class_string", S("OpClass", "115"), CL("36")),
 RJ("rej_list_int_type", OC(115), I32("ChannelList", 36)),
 RJ("rej_unknown_prop", OC(115), CL("36"), S("Foo", "bar")),
 RJ("rej_channel_not_number", OC(115), CL("36,abc")),
 RJ("rej_channel_empty_item", OC(115), CL("36,,40")),
 RJ("rej_channel_leading_comma", OC(115), CL(",36")),
 RJ("rej_channel_trailing_text", OC(115), CL("36x")),
 /* ---- [spec]: should be rejected but are accepted ---- */
 RJ("rej_list_with_class_0 [spec]", OC(0), CL("36")),
 RJ("rej_list_129_chars [spec]", OC(115), R("ChannelList", "1", 129)),
 /* ---- CRASH cases (run last, unforked) ---- */
 CR("crash_method_name_short", "X.ChannelScanRequest()"),
 CR("crash_path_without_radio", N "Device.1.ChannelScanRequest()"),
 CR("crash_path_without_device", N "ChannelScanRequest()"),
 {"crash_method_null", NULL, false, false, {OC(115), CL("36"), E0}, 2, NULL, true},

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
        memset(v, 0, CCN_VAL_SZ + CCN_PAD);
        size_t n;
        if (kind == 5) { memset(v, s[0], (size_t)len); n = (size_t)len + 1; }
        else { n = strlen(s) + 1; memcpy(v, s, n); }
        p->value.data_type = ccs::bus_data_type_string;
        p->value.raw_data.bytes = v;
        p->value.raw_data_len = (unsigned int)n;
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

} /* namespace ccn */
