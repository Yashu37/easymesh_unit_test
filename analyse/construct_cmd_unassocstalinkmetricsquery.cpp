/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_unassocstalinkmetricsquery
 *
 * method_name is copied into method_buf (runner poisons past strlen+1). Each property gets
 * name[128], a value buffer val_buf[i] (runner poisons past raw_data_len) and is linked through
 * next_data. One device 1 exists (or the MAC alias 02:00:00:00:00:01). Properties are the
 * OpClass int plus Channel.{i}.Channel (int) and Channel.{i}.STA.{j}.MAC (string); up to 8
 * channels and 16 STAs per channel are valid.
 *
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input, 22 invalid_method,
 * 25 invalid_namespace). Accept cases also check the JSON handed to io_process. Cases marked [spec]
 * are inputs a strict handler should reject (STA entries are not validated as MACs, a MAC longer
 * than 17 characters is cut, an absurd channel number is accepted). The crash_* cases (paths with no
 * Device instance after the Network prefix) ABORT on the original handler. Unlike the other cmd_*
 * handlers there is no short-method-name over-read here: the mandatory suffix
 * X_AIRTIES_UnassociatedStaLinkMetricsQuery() is 42 characters, longer than the 34-byte prefix, so
 * name += sizeof(DATAELEMS_NETWORK) always stays inside the string. The crash cases run last and UNFORKED (a plain make stops at the first ASan report);
 * FORK_CRASH=1 runs each in a forked child so all of them show. A NULL method_name is already
 * rejected by the handler.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_unassocstalinkmetricsquery.h"

namespace cua {

alignas(16) char method_buf[256 + CUA_PAD];
ccs::bus_data_prop_t props_buf[CUA_MAXP];
alignas(16) char val_buf[CUA_MAXP][CUA_VAL_SZ + CUA_PAD];
int num_props = 0;

#define N "Device.WiFi.DataElements.Network."
#define P N "Device.1.X_AIRTIES_UnassociatedStaLinkMetricsQuery()"
#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define R(n, c, l) {n, 5, c, 0, l}
#define E0 {NULL, 0, NULL, 0, 0}
#define OC(v) I32("OpClass", v)
#define CHN(i, v) I32("Channel." #i ".Channel", v)
#define STM(i, j, m) S("Channel." #i ".STA." #j ".MAC", m)
#define M1 "aa:bb:cc:dd:ee:ff"
#define M2 "11:22:33:44:55:66"
#define BASE OC(115), CHN(1, 36), STM(1, 1, M1)
#define OK(n, j, ...) {n, P, false, false, {__VA_ARGS__, E0}, 0, j, false}
#define RJ(n, ...) {n, P, false, false, {__VA_ARGS__, E0}, 2, NULL, false}
#define RP(n, m, rc) {n, m, false, false, {BASE, E0}, rc, NULL, false}
#define CR(n, m) {n, m, false, false, {BASE, E0}, 25, NULL, true}
#define JB "\"UnassocStaQueryList\":[{\"opclass\":115,\"channels\":[{\"channel\":36,\"sta_macs\":[\"" M1 "\"]}]}]"

test_case_t suite[] = {
 /* ---- accepted ---- */
 OK("ok_basic", "\"AlMac\":\"02:00:00:00:00:01\"," JB, BASE),
 OK("ok_two_stas", "\"sta_macs\":[\"" M1 "\",\"" M2 "\"]", BASE, STM(1, 2, M2)),
 OK("ok_two_channels", "\"channels\":[{\"channel\":36,\"sta_macs\":[\"" M1 "\"]},{\"channel\":40,\"sta_macs\":[\"" M2 "\"]}]", BASE, CHN(2, 40), STM(2, 1, M2)),
 OK("ok_params_any_order", JB, STM(1, 1, M1), CHN(1, 36), OC(115)),
 OK("ok_opclass_0", "\"opclass\":0", OC(0), CHN(1, 36), STM(1, 1, M1)),
 OK("ok_sta_16_of_16", "\"sta_macs\":[\"aa:bb:cc:dd:ee:01\"", OC(115), CHN(1, 36), STM(1, 1, "aa:bb:cc:dd:ee:01"), STM(1, 2, "aa:bb:cc:dd:ee:02"), STM(1, 3, "aa:bb:cc:dd:ee:03"), STM(1, 4, "aa:bb:cc:dd:ee:04"), STM(1, 5, "aa:bb:cc:dd:ee:05"), STM(1, 6, "aa:bb:cc:dd:ee:06"), STM(1, 7, "aa:bb:cc:dd:ee:07"), STM(1, 8, "aa:bb:cc:dd:ee:08"), STM(1, 9, "aa:bb:cc:dd:ee:09"), STM(1, 10, "aa:bb:cc:dd:ee:0a"), STM(1, 11, "aa:bb:cc:dd:ee:0b"), STM(1, 12, "aa:bb:cc:dd:ee:0c"), STM(1, 13, "aa:bb:cc:dd:ee:0d"), STM(1, 14, "aa:bb:cc:dd:ee:0e"), STM(1, 15, "aa:bb:cc:dd:ee:0f"), STM(1, 16, "aa:bb:cc:dd:ee:10")),
 OK("ok_channel_8_of_8", "\"channel\":62", OC(115), CHN(1, 34), STM(1, 1, M1), CHN(2, 38), STM(2, 1, M1), CHN(3, 42), STM(3, 1, M1), CHN(4, 46), STM(4, 1, M1), CHN(5, 50), STM(5, 1, M1), CHN(6, 54), STM(6, 1, M1), CHN(7, 58), STM(7, 1, M1), CHN(8, 62), STM(8, 1, M1)),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].X_AIRTIES_UnassociatedStaLinkMetricsQuery()", false, false, {BASE, E0}, 0, "\"AlMac\":\"02:00:00:00:00:01\"", false},
 {"ok_output_null", P, false, true, {BASE, E0}, 0, JB, false},
 /* ---- rejected: method / path ---- */
 {"rej_method_null", NULL, false, false, {BASE, E0}, 2, NULL, false},
 RP("rej_method_no_dot", "X_AIRTIES_UnassociatedStaLinkMetricsQuery()", 2),
 RP("rej_wrong_method", N "Device.1.Foo()", 22),
 RP("rej_device_not_found", N "Device.9.X_AIRTIES_UnassociatedStaLinkMetricsQuery()", 25),
 /* ---- rejected: parameters ---- */
 {"rej_no_params", P, false, false, {E0}, 2, NULL, false},
 RJ("rej_missing_opclass", CHN(1, 36), STM(1, 1, M1)),
 RJ("rej_missing_channels", OC(115)),
 RJ("rej_opclass_negative", OC(-1), CHN(1, 36), STM(1, 1, M1)),
 RJ("rej_channel_without_sta", OC(115), CHN(1, 36)),
 RJ("rej_sta_without_channel", OC(115), STM(1, 1, M1)),
 RJ("rej_channel_0", OC(115), CHN(1, 0), STM(1, 1, M1)),
 RJ("rej_channel_negative", OC(115), CHN(1, -5), STM(1, 1, M1)),
 RJ("rej_channel_gap_index2_only", OC(115), CHN(2, 36), STM(2, 1, M1)),
 RJ("rej_sta_gap_index2_only", OC(115), CHN(1, 36), STM(1, 2, M1)),
 RJ("rej_sta_empty_mac", OC(115), CHN(1, 36), STM(1, 1, "")),
 RJ("rej_channel_index_0", OC(115), CHN(0, 36), STM(0, 1, M1)),
 RJ("rej_channel_index_9", OC(115), CHN(9, 36), STM(9, 1, M1)),
 RJ("rej_sta_index_0", OC(115), CHN(1, 36), STM(1, 0, M1)),
 RJ("rej_sta_index_17", OC(115), CHN(1, 36), STM(1, 17, M1)),
 RJ("rej_channel_index_alpha", OC(115), CHN(a, 36), STM(a, 1, M1)),
 RJ("rej_channel_index_huge", OC(115), I32("Channel.99999999999.Channel", 36)),
 RJ("rej_channel_name_only", OC(115), I32("Channel.", 36)),
 RJ("rej_channel_no_field", OC(115), I32("Channel.1", 36)),
 RJ("rej_channel_unknown_field", OC(115), I32("Channel.1.Foo", 36)),
 RJ("rej_sta_unknown_field", OC(115), CHN(1, 36), S("Channel.1.STA.1.Foo", M1)),
 RJ("rej_sta_no_field", OC(115), CHN(1, 36), S("Channel.1.STA.1", M1)),
 RJ("rej_sta_extra_field", OC(115), CHN(1, 36), S("Channel.1.STA.1.MAC.x", M1)),
 RJ("rej_opclass_string_type", S("OpClass", "115"), CHN(1, 36), STM(1, 1, M1)),
 RJ("rej_channel_string_type", OC(115), S("Channel.1.Channel", "36"), STM(1, 1, M1)),
 RJ("rej_sta_int_type", OC(115), CHN(1, 36), I32("Channel.1.STA.1.MAC", 5)),
 RJ("rej_unknown_prop", BASE, S("Foo", "bar")),
 /* ---- [spec]: should be rejected but are accepted ---- */
 RJ("rej_sta_not_mac [spec]", OC(115), CHN(1, 36), STM(1, 1, "garbage")),
 RJ("rej_sta_mac_20_chars [spec]", OC(115), CHN(1, 36), S("Channel.1.STA.1.MAC", "aa:bb:cc:dd:ee:ff:00:11")),
 RJ("rej_channel_99999 [spec]", OC(115), CHN(1, 99999), STM(1, 1, M1)),
 /* ---- CRASH cases (run last, unforked) ---- */
 CR("crash_dot_prefix_no_instance", "X.X_AIRTIES_UnassociatedStaLinkMetricsQuery()"),
 CR("crash_path_without_device", N "X_AIRTIES_UnassociatedStaLinkMetricsQuery()"),

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
        memset(v, 0, CUA_VAL_SZ + CUA_PAD);
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

} /* namespace cua */
