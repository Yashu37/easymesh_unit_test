/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_beaconmetricsquery
 *
 * method_name is copied into method_buf (runner poisons past strlen+1). Each
 * property gets name[128], a value buffer val_buf[i] (runner poisons past
 * raw_data_len) and is linked through next_data. One device 1 / radio 1 / BSS 1 /
 * STA 1 exists (or the MAC alias 02:00:00:00:00:01 / :10:01 / :20:01 / :30:01).
 *
 * expect_rc uses the real bus_error_t values (0 success, 2 invalid_input,
 * 22 invalid_method, 25 invalid_namespace). Accept cases also check the JSON
 * handed to io_process. Cases marked [spec] are inputs a strict handler should
 * reject (over-long values silently truncated, BSSID that is not a MAC). The
 * former crash cases (method name shorter than the Network prefix, path that stops
 * before the Radio / BSS / STA instance) ABORTED on the original handler; with
 * the fix they are rejected (rej_*, rc 25).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

namespace cbm {

alignas(16) char method_buf[256 + CBM_PAD];
ccs::bus_data_prop_t props_buf[CBM_MAXP];
alignas(16) char val_buf[CBM_MAXP][CBM_VAL_SZ + CBM_PAD];
int num_props = 0;

#define N "Device.WiFi.DataElements.Network."
#define P N "Device.1.Radio.1.BSS.1.STA.1.X_AIRTIES_BeaconMetricsQuery()"
#define S(n, v)   {n, 0, v, 0, 0}
#define I32(n, v) {n, 1, NULL, v, 0}
#define R(n, c, l) {n, 5, c, 0, l}
#define E0 {NULL, 0, NULL, 0, 0}
#define OC(v) I32("OperatingClass", v)
#define CH(v) I32("Channel", v)
#define SD(v) S("SSID", v)
#define BASE OC(115), CH(36), SD("Net")
#define OK(n, j, ...) {n, P, false, false, {__VA_ARGS__, E0}, 0, j, false}
#define RJ(n, ...) {n, P, false, false, {__VA_ARGS__, E0}, 2, NULL, false}
#define RP(n, m, rc) {n, m, false, false, {BASE, E0}, rc, NULL, false}
#define CR(n, m) {n, m, false, false, {BASE, E0}, 25, NULL, false}

test_case_t suite[] = {
 /* ---- accepted ---- */
 OK("ok_basic", "\"OperatingClass\":115,\"Channel\":36,\"ReportingDetail\":0,\"BSSID\":\"FF:FF:FF:FF:FF:FF\",\"SSID\":\"Net\"", BASE),
 OK("ok_bssid_given", "\"BSSID\":\"02:00:00:00:20:01\"", BASE, S("BSSID", "02:00:00:00:20:01")),
 OK("ok_rep_detail_2", "\"ReportingDetail\":2", BASE, I32("ReportingDetail", 2)),
 OK("ok_rep_detail_1_elements", "\"ReportingDetail\":1", BASE, I32("ReportingDetail", 1), S("ElementIDList", "1,2,3")),
 OK("ok_channel_255_one_report", "\"APChReportList\":[{\"OpClass\":115,\"ChannelList\":[36,40]}]", OC(115), CH(255), SD("Net"),
    I32("APChannelReport.1.OperatingClass", 115), S("APChannelReport.1.ChannelList", "36,40")),
 OK("ok_channel_255_two_reports_same_class", "\"APChReportList\":[{\"OpClass\":115,\"ChannelList\":[36]},{\"OpClass\":115,\"ChannelList\":[44]}]", OC(115), CH(255), SD("Net"),
    I32("APChannelReport.1.OperatingClass", 115), S("APChannelReport.1.ChannelList", "36"),
    I32("APChannelReport.2.OperatingClass", 115), S("APChannelReport.2.ChannelList", "44")),
 {"ok_alias_path", N "Device.[02:00:00:00:00:01].Radio.[02:00:00:00:10:01].BSS.[02:00:00:00:20:01].STA.[02:00:00:00:30:01].X_AIRTIES_BeaconMetricsQuery()", false, false, {BASE, E0}, 0, "\"OperatingClass\":115", false},
 OK("ok_output_null", "\"Channel\":36", BASE),
 OK("ok_ssid_32_chars", "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\"", OC(115), CH(36), R("SSID", "S", 32)),
 OK("ok_elements_127_chars", "\"ElementList\":[", BASE, I32("ReportingDetail", 1), R("ElementIDList", "1", 127)),
 /* ---- rejected: method / path ---- */
 {"rej_method_null", NULL, false, false, {BASE, E0}, 2, NULL, false},
 RP("rej_method_no_dot", "X_AIRTIES_BeaconMetricsQuery()", 2),
 RP("rej_wrong_method", N "Device.1.Radio.1.BSS.1.STA.1.Foo()", 22),
 RP("rej_device_not_found", N "Device.9.Radio.1.BSS.1.STA.1.X_AIRTIES_BeaconMetricsQuery()", 25),
 RP("rej_radio_not_found", N "Device.1.Radio.9.BSS.1.STA.1.X_AIRTIES_BeaconMetricsQuery()", 25),
 RP("rej_bss_not_found", N "Device.1.Radio.1.BSS.9.STA.1.X_AIRTIES_BeaconMetricsQuery()", 25),
 RP("rej_sta_not_found", N "Device.1.Radio.1.BSS.1.STA.9.X_AIRTIES_BeaconMetricsQuery()", 25),
 {"rej_no_props", P, true, false, {E0}, 2, NULL, false},
 /* ---- rejected: parameters ---- */
 RJ("rej_op_class_missing", CH(36), SD("Net")),
 RJ("rej_channel_missing", OC(115), SD("Net")),
 RJ("rej_ssid_missing", OC(115), CH(36)),
 RJ("rej_ssid_empty", OC(115), CH(36), SD("")),
 RJ("rej_op_class_negative", OC(-1), CH(36), SD("Net")),
 RJ("rej_op_class_string", S("OperatingClass", "115"), CH(36), SD("Net")),
 RJ("rej_channel_string", OC(115), S("Channel", "36"), SD("Net")),
 RJ("rej_ssid_int_type", OC(115), CH(36), I32("SSID", 5)),
 RJ("rej_unknown_prop", BASE, S("Foo", "bar")),
 RJ("rej_rep_detail_3", BASE, I32("ReportingDetail", 3)),
 RJ("rej_rep_detail_neg2", BASE, I32("ReportingDetail", -2)),
 RJ("rej_rep_detail_1_no_elements", BASE, I32("ReportingDetail", 1)),
 RJ("rej_elements_not_number", BASE, I32("ReportingDetail", 1), S("ElementIDList", "1,x")),
 RJ("rej_channel_255_no_report", OC(115), CH(255), SD("Net")),
 RJ("rej_report_index_0", OC(115), CH(255), SD("Net"), I32("APChannelReport.0.OperatingClass", 115), S("APChannelReport.0.ChannelList", "36")),
 RJ("rej_report_index_7", OC(115), CH(255), SD("Net"), I32("APChannelReport.7.OperatingClass", 115), S("APChannelReport.7.ChannelList", "36")),
 RJ("rej_report_index_alpha", OC(115), CH(255), SD("Net"), I32("APChannelReport.a.OperatingClass", 115)),
 RJ("rej_report_index_256", OC(115), CH(255), SD("Net"), I32("APChannelReport.256.OperatingClass", 115)),
 RJ("rej_report_no_suffix", OC(115), CH(255), SD("Net"), I32("APChannelReport.1", 115)),
 RJ("rej_report_unknown_field", OC(115), CH(255), SD("Net"), I32("APChannelReport.1.Foo", 115)),
 RJ("rej_report_no_channel_list", OC(115), CH(255), SD("Net"), I32("APChannelReport.1.OperatingClass", 115)),
 RJ("rej_report_op_class_0", OC(115), CH(255), SD("Net"), I32("APChannelReport.1.OperatingClass", 0), S("APChannelReport.1.ChannelList", "36")),
 RJ("rej_reports_differ_in_class", OC(115), CH(255), SD("Net"),
    I32("APChannelReport.1.OperatingClass", 115), S("APChannelReport.1.ChannelList", "36"),
    I32("APChannelReport.2.OperatingClass", 118), S("APChannelReport.2.ChannelList", "52")),
 RJ("rej_report_channel_not_number", OC(115), CH(255), SD("Net"), I32("APChannelReport.1.OperatingClass", 115), S("APChannelReport.1.ChannelList", "36,abc")),
 /* ---- [spec]: should be rejected but are accepted ---- */
 RJ("rej_ssid_33_chars [spec]", OC(115), CH(36), R("SSID", "S", 33)),
 RJ("rej_bssid_not_mac [spec]", BASE, S("BSSID", "garbage")),
 RJ("rej_elements_128_chars [spec]", BASE, I32("ReportingDetail", 1), R("ElementIDList", "1", 128)),
 RJ("rej_report_list_64_chars [spec]", OC(115), CH(255), SD("Net"), I32("APChannelReport.1.OperatingClass", 115), R("APChannelReport.1.ChannelList", "1", 64)),
 /* ---- were CRASH cases on the original handler (now rejected cleanly): name += sizeof(DATAELEMS_NETWORK) / get_table_instance() NULL ---- */
 CR("rej_method_name_short", "X.X_AIRTIES_BeaconMetricsQuery()"),
 CR("rej_path_without_radio", N "Device.1.X_AIRTIES_BeaconMetricsQuery()"),
 CR("rej_path_without_bss", N "Device.1.Radio.1.X_AIRTIES_BeaconMetricsQuery()"),
 CR("rej_path_without_sta", N "Device.1.Radio.1.BSS.1.X_AIRTIES_BeaconMetricsQuery()"),

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
        memset(v, 0, CBM_VAL_SZ + CBM_PAD);
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

} /* namespace cbm */
