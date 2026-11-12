/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_channelselect
 *
 * method_name is copied into method_buf (runner poisons past strlen+1). Each
 * property gets name[128], a value buffer val_buf[i] (runner poisons past
 * raw_data_len) and is linked through next_data. Radio is 5 GHz, device 1 /
 * radio 1 exist. Stand-in op-class table: 81=2.4G(1-13), 115=5G(36-48),
 * 118=5G(52-64), 121=5G(100-140), 131=6G.
 *
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input,
 * 22 invalid_method, 25 invalid_namespace). Accept cases also check the
 * JSON handed to io_process. Cases marked [spec] are inputs a strict parser
 * should reject (sign / whitespace in an index or channel). The last 3 cases
 * (short method name, path without a Radio instance, NULL method name) ABORT
 * on the original handler (build with -DCCS_FIX=0); with the fix they are
 * rejected (crash=true re-enables the forked-child runner for them).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

namespace ccs {

alignas(16) char method_buf[256 + CCS_PAD];
bus_data_prop_t props_buf[CCS_MAXP];
alignas(16) char val_buf[CCS_MAXP][CCS_VAL_SZ + CCS_PAD];
int num_props = 0;

#define P "Device.WiFi.DataElements.Network.Device.1.Radio.1.ChannelSelectionRequest()"
#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define U8(n, v)  {n, 2, NULL, v, 0}
#define E0 {NULL, 0, NULL, 0, 0}
#define OK(n, ...) {n, P, 0, 0, false, {__VA_ARGS__, E0}, 0, NULL, false}
#define RJ(n, ...) {n, P, 0, 0, false, {__VA_ARGS__, E0}, 2, NULL, false}
#define C1 S("Class.1.Channel.1.Channel", "36,40"), I32("Class.1.Channel.1.Preference", 7), I32("Class.1.OpClass", 115)

test_case_t suite[] = {
 /* ---- accepted ---- */
 {"ok_single_class", P, 0, 0, false, {C1, E0}, 0, "\"Class\":115,\"ChannelList\":[36,40],\"ChannelPrefList\":[7,7]", false},
 {"ok_two_groups", P, 0, 0, false, {I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", 5),
                                    S("Class.1.Channel.2.Channel", "44,48"), I32("Class.1.Channel.2.Preference", 9), E0}, 0,
  "\"ChannelList\":[36,44,48],\"ChannelPrefList\":[5,9,9]", false},
 {"ok_two_classes", P, 0, 0, false, {C1, I32("Class.2.OpClass", 118), S("Class.2.Channel.1.Channel", "52"), I32("Class.2.Channel.1.Preference", 3), E0}, 0,
  "\"Class\":118,\"ChannelList\":[52],\"ChannelPrefList\":[3]", false},
 {"ok_list_spaces", P, 0, 0, false, {I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36 , 40"), I32("Class.1.Channel.1.Preference", 7), E0}, 0,
  "\"ChannelList\":[36,40]", false},
 {"ok_types_uint8", P, 0, 0, false, {U8("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36"), U8("Class.1.Channel.1.Preference", 1), E0}, 0,
  "\"Class\":115", false},
 {"ok_pref_0", P, 0, 0, false, {I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", 0), E0}, 0,
  "\"ChannelPrefList\":[0]", false},
 {"ok_pref_14_max", P, 0, 0, false, {I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", 14), E0}, 0,
  "\"ChannelPrefList\":[14]", false},
 {"ok_32_classes_max", P, 1, 0, false, {E0}, 0, "\"Class\":115", false},
 /* ---- method / path ---- */
 {"rej_method_no_dot", "ChannelSelectionRequest()", 0, 0, false, {C1, E0}, 2, NULL, false},
 {"rej_wrong_method", "Device.WiFi.DataElements.Network.Device.1.Radio.1.Foo()", 0, 0, false, {C1, E0}, 22, NULL, false},
 {"rej_device_not_found", "Device.WiFi.DataElements.Network.Device.9.Radio.1.ChannelSelectionRequest()", 0, 0, false, {C1, E0}, 25, NULL, false},
 {"rej_radio_not_found", "Device.WiFi.DataElements.Network.Device.1.Radio.9.ChannelSelectionRequest()", 0, 0, false, {C1, E0}, 25, NULL, false},
 {"rej_no_props", P, 0, 0, true, {E0}, 2, NULL, false},
 /* ---- property names / indexes ---- */
 RJ("rej_non_class_prop", S("Foo.1.OpClass", "x")),
 RJ("rej_class_index_0", I32("Class.0.OpClass", 115)),
 RJ("rej_class_index_neg", I32("Class.-1.OpClass", 115)),
 RJ("rej_class_index_alpha", I32("Class.abc.OpClass", 115)),
 RJ("rej_class_index_1x", I32("Class.1x.OpClass", 115)),
 RJ("rej_class_index_33", I32("Class.33.OpClass", 115)),
 RJ("rej_class_index_huge", I32("Class.99999999999999999999.OpClass", 115)),
 RJ("rej_extra_token_opclass", I32("Class.1.OpClass.x", 115)),
 RJ("rej_six_tokens", S("Class.1.Channel.1.Channel.x.y.z", "36")),
 RJ("rej_channel_index_65", I32("Class.1.OpClass", 115), S("Class.1.Channel.65.Channel", "36"), I32("Class.1.Channel.65.Preference", 1)),
 RJ("rej_channel_index_gap", I32("Class.1.OpClass", 115), S("Class.1.Channel.2.Channel", "36"), I32("Class.1.Channel.2.Preference", 1)),
 RJ("rej_class_gap", I32("Class.2.OpClass", 115), S("Class.2.Channel.1.Channel", "36"), I32("Class.2.Channel.1.Preference", 1)),
 /* ---- OpClass ---- */
 RJ("rej_opclass_missing", S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_opclass_0", I32("Class.1.OpClass", 0), S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_opclass_unknown", I32("Class.1.OpClass", 999), S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_opclass_band_mismatch", I32("Class.1.OpClass", 81), S("Class.1.Channel.1.Channel", "1"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_opclass_string", S("Class.1.OpClass", "115"), S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", 1)),
 /* ---- Channel / Preference ---- */
 RJ("rej_channel_no_pref", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36")),
 RJ("rej_pref_no_channel", I32("Class.1.OpClass", 115), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_pref_15", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", 15)),
 RJ("rej_pref_negative", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36"), I32("Class.1.Channel.1.Preference", -1)),
 RJ("rej_pref_string", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36"), S("Class.1.Channel.1.Preference", "1")),
 RJ("rej_channel_int_type", I32("Class.1.OpClass", 115), I32("Class.1.Channel.1.Channel", 36), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_channel_attr_bad", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Foo", "36")),
 RJ("rej_list_empty", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", ""), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_list_trailing_comma", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36,"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_list_leading_comma", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", ",36"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_list_double_comma", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36,,40"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_list_256", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "256"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_list_duplicate", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "36,36"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_list_not_in_opclass", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "1"), I32("Class.1.Channel.1.Preference", 1)),
 {"rej_list_too_long_300", P, 2, 0, false, {E0}, 2, NULL, false},
 {"rej_list_embedded_nul", P, 0, 0, false, {I32("Class.1.OpClass", 115), {"Class.1.Channel.1.Channel", 3, "36\0,40", 0, 7}, I32("Class.1.Channel.1.Preference", 1), E0}, 2, NULL, false},
 /* ---- [spec] ---- */
 RJ("rej_channel_plus_sign [spec]", I32("Class.1.OpClass", 115), S("Class.1.Channel.1.Channel", "+36"), I32("Class.1.Channel.1.Preference", 1)),
 RJ("rej_class_index_plus [spec]", I32("Class.+1.OpClass", 115), S("Class.+1.Channel.1.Channel", "36"), I32("Class.+1.Channel.1.Preference", 1)),
 /* ---- were CRASH cases on the original handler (CCS_FIX 0): now rejected cleanly ---- */
 {"rej_method_name_short", "X.ChannelSelectionRequest()", 0, 0, false, {C1, E0}, 25, NULL, false},
 {"rej_path_without_radio", "Device.WiFi.DataElements.Network.Device.1.ChannelSelectionRequest()", 0, 0, false, {C1, E0}, 25, NULL, false},
 {"rej_method_name_null", NULL, 0, 0, false, {C1, E0}, 2, NULL, false},

 { NULL, NULL, 0, 0, false, {E0}, 0, NULL, false }  /* sentinel */
};

static void add_prop(const char *name, int kind, const char *s, int i, int len)
{
    bus_data_prop_t *p = &props_buf[num_props];
    char *v = val_buf[num_props];
    memset(p, 0, sizeof(*p));
    memset(v, 0, CCS_VAL_SZ + CCS_PAD);
    snprintf(p->name, sizeof(p->name), "%s", name);
    p->name_len = (uint32_t)strlen(p->name);
    p->is_data_set = true;
    if (kind == 0 || kind == 3) {
        size_t n = (kind == 3) ? (size_t)len : strlen(s) + 1;
        if (n > CCS_VAL_SZ) n = CCS_VAL_SZ;
        memcpy(v, s, n);
        p->value.data_type = bus_data_type_string;
        p->value.raw_data.bytes = v;
        p->value.raw_data_len = (unsigned int)n;
    } else if (kind == 1) {
        p->value.data_type = bus_data_type_int32;
        p->value.raw_data.i32 = i;
    } else {
        p->value.data_type = bus_data_type_uint8;
        p->value.raw_data.u8 = (uint8_t)i;
    }
    if (num_props > 0) props_buf[num_props - 1].next_data = p;
    num_props++;
}

void construct_input(const test_case_t *tc)
{
    memset(method_buf, 0, sizeof(method_buf));
    if (tc->method) snprintf(method_buf, 256, "%s", tc->method);
    num_props = 0;
    g_radio_band = tc->radio_band ? tc->radio_band : em_freq_band_5;
    if (tc->gen == 1) {                         /* 32 classes, each 115 / channel 36 */
        for (int c = 1; c <= 32; c++) {
            char n[64];
            snprintf(n, sizeof(n), "Class.%d.OpClass", c);              add_prop(n, 1, NULL, 115, 0);
            snprintf(n, sizeof(n), "Class.%d.Channel.1.Channel", c);    add_prop(n, 0, "36", 0, 0);
            snprintf(n, sizeof(n), "Class.%d.Channel.1.Preference", c); add_prop(n, 1, NULL, 1, 0);
        }
    } else if (tc->gen == 2) {                  /* 300-char channel list: "36,36,36,..." */
        char list[CCS_VAL_SZ];
        int off = 0;
        while (off < 300) off += snprintf(list + off, sizeof(list) - off, "%s36", off ? "," : "");
        add_prop("Class.1.OpClass", 1, NULL, 115, 0);
        add_prop("Class.1.Channel.1.Channel", 0, list, 0, 0);
        add_prop("Class.1.Channel.1.Preference", 1, NULL, 1, 0);
    } else {
        for (int i = 0; tc->props[i].name != NULL; i++)
            add_prop(tc->props[i].name, tc->props[i].kind, tc->props[i].s, tc->props[i].i, tc->props[i].len);
    }
}

} /* namespace ccs */
