/*
 * TEST CASES / CONSTRUCTOR: construct_analyze_beacon_metrics_query
 *
 * The JSON is copied into abq::evt_buf = event header + subdoc.buff (runner
 * poisons everything past the NUL and the event's guard field). pcmd[] is
 * abq::pcmd_buf with EM_MAX_CMD usable slots (runner poisons slot 16 onward).
 *
 * expect_num: 1 = accepted (cmd built; fields below checked), 0 = rejected.
 * Cases marked [spec] are inputs a strict parser should reject (or keep intact)
 * but the source accepts / truncates: invalid STA MAC string, trailing text in
 * BSSID, 32-byte SSID cut to 31, non-numeric / out-of-range OperatingClass and
 * Channel. gen=1..6 build the over/at-limit list cases (17/16 AP channel
 * reports, 65/64 channels, 33/32 element IDs).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

namespace abq {

alignas(16) char evt_buf[ABQ_EVT_SZ];
alignas(16) void *pcmd_buf[EM_MAX_CMD + 8];

#define QHM(m) "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[{\"RadioList\":[{\"BSSList\":[{\"STAList\":[{\"MACAddress\":\"" m "\",\"BeaconMetricsQuery\":{"
#define QH QHM("11:22:33:44:55:66")
#define QT "}}]}]}]}]}}}"
#define OC "\"OperatingClass\":115,"
#define CH "\"Channel\":36,"
#define BS "\"BSSID\":\"aa:bb:cc:dd:ee:ff\","
#define RD "\"ReportingDetail\":0,"
#define SD "\"SSID\":\"test\""
#define STA {0x11,0x22,0x33,0x44,0x55,0x66}
#define BSS {0xaa,0xbb,0xcc,0xdd,0xee,0xff}
#define Z6 {0,0,0,0,0,0}
#define REJ(n,j) {n, j, 0, 0, Z6, 0, 0, Z6, 0, 0, 0, 0}

test_case_t suite[] = {
 /* name                        json                                gen exp sta  opc ch  bssid rd slen apc nel */
 /* ---- accepted ---- */
 {"ok_basic",              QH OC CH BS RD SD QT,                                                0, 1, STA, 115, 36, BSS, 0, 4, 0, 0},
 {"ok_bssid_no_colon",     QH OC CH "\"BSSID\":\"aabbccddeeff\"," RD SD QT,                     0, 1, STA, 115, 36, BSS, 0, 4, 0, 0},
 {"ok_sta_no_colon",       QHM("112233445566") OC CH BS RD SD QT,                               0, 1, STA, 115, 36, BSS, 0, 4, 0, 0},
 {"ok_rd1_elements",       QH OC CH BS "\"ReportingDetail\":1,\"ElementList\":[0,1,2]," SD QT,  0, 1, STA, 115, 36, BSS, 1, 4, 0, 3},
 {"ok_rd2",                QH OC CH BS "\"ReportingDetail\":2," SD QT,                          0, 1, STA, 115, 36, BSS, 2, 4, 0, 0},
 {"ok_ch255_one_report",   QH OC "\"Channel\":255," BS RD SD ",\"APChReportList\":[{\"OpClass\":115,\"ChannelList\":[36,40]}]" QT, 0, 1, STA, 115, 255, BSS, 0, 4, 1, 0},
 {"ok_ap_reports_16_max",  NULL,                                                                2, 1, STA, 115, 255, BSS, 0, 4, 16, 0},
 {"ok_channels_64_max",    NULL,                                                                4, 1, STA, 115, 255, BSS, 0, 4, 1, 0},
 {"ok_elements_32_max",    NULL,                                                                6, 1, STA, 115, 36, BSS, 1, 4, 0, 32},
 {"ok_ssid_empty",         QH OC CH BS RD "\"SSID\":\"\"" QT,                                   0, 1, STA, 115, 36, BSS, 0, 0, 0, 0},
 {"ok_ssid_31_chars",      QH OC CH BS RD "\"SSID\":\"abcdefghijklmnopqrstuvwxyzabcde\"" QT,    0, 1, STA, 115, 36, BSS, 0, 31, 0, 0},
 /* ---- structure ---- */
 REJ("rej_invalid_json",       "{\"wfa-dataelements:BeaconMetricsQuery\":{"),
 REJ("rej_empty_string",       ""),
 REJ("rej_missing_wfa_key",    "{\"foo\":{}}"),
 REJ("rej_missing_network",    "{\"wfa-dataelements:BeaconMetricsQuery\":{}}"),
 REJ("rej_missing_devlist",    "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{}}}"),
 REJ("rej_empty_devlist",      "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[]}}}"),
 REJ("rej_empty_radiolist",    "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[{\"RadioList\":[]}]}}}"),
 REJ("rej_empty_bsslist",      "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[{\"RadioList\":[{\"BSSList\":[]}]}]}}}"),
 REJ("rej_empty_stalist",      "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[{\"RadioList\":[{\"BSSList\":[{\"STAList\":[]}]}]}]}}}"),
 REJ("rej_missing_stalist",    "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[{\"RadioList\":[{\"BSSList\":[{}]}]}]}}}"),
 /* ---- STA / query fields ---- */
 REJ("rej_sta_mac_missing",    "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[{\"RadioList\":[{\"BSSList\":[{\"STAList\":[{}]}]}]}]}}}"),
 REJ("rej_sta_mac_number",     "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[{\"RadioList\":[{\"BSSList\":[{\"STAList\":[{\"MACAddress\":5}]}]}]}]}}}"),
 REJ("rej_bmquery_missing",    "{\"wfa-dataelements:BeaconMetricsQuery\":{\"Network\":{\"DeviceList\":[{\"RadioList\":[{\"BSSList\":[{\"STAList\":[{\"MACAddress\":\"11:22:33:44:55:66\"}]}]}]}]}}}"),
 REJ("rej_opclass_missing",    QH CH BS RD SD QT),
 REJ("rej_channel_missing",    QH OC BS RD SD QT),
 REJ("rej_bssid_missing",      QH OC CH RD SD QT),
 REJ("rej_bssid_number",       QH OC CH "\"BSSID\":7," RD SD QT),
 REJ("rej_bssid_short",        QH OC CH "\"BSSID\":\"aa:bb:cc\"," RD SD QT),
 REJ("rej_bssid_nonhex",       QH OC CH "\"BSSID\":\"zz:bb:cc:dd:ee:ff\"," RD SD QT),
 REJ("rej_rd_missing",         QH OC CH BS SD QT),
 REJ("rej_rd_3",               QH OC CH BS "\"ReportingDetail\":3," SD QT),
 REJ("rej_ssid_missing",       QH OC CH BS "\"ReportingDetail\":0" QT),
 REJ("rej_ssid_number",        QH OC CH BS RD "\"SSID\":9" QT),
 /* ---- AP channel report / channel list / element list ---- */
 REJ("rej_ch255_no_list",      QH OC "\"Channel\":255," BS RD SD QT),
 REJ("rej_ch255_empty_list",   QH OC "\"Channel\":255," BS RD SD ",\"APChReportList\":[]" QT),
 REJ("rej_ap_reports_17",      NULL),
 REJ("rej_report_no_opclass",  QH OC "\"Channel\":255," BS RD SD ",\"APChReportList\":[{\"ChannelList\":[36]}]" QT),
 REJ("rej_report_no_chlist",   QH OC "\"Channel\":255," BS RD SD ",\"APChReportList\":[{\"OpClass\":115}]" QT),
 REJ("rej_chlist_empty",       QH OC "\"Channel\":255," BS RD SD ",\"APChReportList\":[{\"OpClass\":115,\"ChannelList\":[]}]" QT),
 REJ("rej_channels_65",        NULL),
 REJ("rej_rd1_no_elemlist",    QH OC CH BS "\"ReportingDetail\":1," SD QT),
 REJ("rej_rd1_empty_elemlist", QH OC CH BS "\"ReportingDetail\":1,\"ElementList\":[]," SD QT),
 REJ("rej_elements_33",        NULL),
 /* ---- [spec]: accepted / altered by the source ---- */
 REJ("rej_sta_mac_garbage [spec]",   QHM("zz") OC CH BS RD SD QT),
 REJ("rej_bssid_trailing [spec]",    QH OC CH "\"BSSID\":\"aa:bb:cc:dd:ee:ff:11\"," RD SD QT),
 REJ("rej_opclass_string [spec]",    QH "\"OperatingClass\":\"abc\"," CH BS RD SD QT),
 REJ("rej_channel_300 [spec]",       QH OC "\"Channel\":300," BS RD SD QT),
 {"ok_ssid_32_chars [spec]", QH OC CH BS RD "\"SSID\":\"abcdefghijklmnopqrstuvwxyzabcdef\"" QT, 0, 1, STA, 115, 36, BSS, 0, 32, 0, 0},

 { NULL, NULL, 0, 0, Z6, 0, 0, Z6, 0, 0, 0, 0 }  /* sentinel */
};

/* gen: which list case a NULL-json row builds (identified by name) */
static int gen_for(const test_case_t *tc)
{
    if (tc->gen) return tc->gen;
    if (!strcmp(tc->test_name, "rej_ap_reports_17")) return 1;
    if (!strcmp(tc->test_name, "rej_channels_65"))   return 3;
    if (!strcmp(tc->test_name, "rej_elements_33"))   return 5;
    return 0;
}

void construct_input(const test_case_t *tc)
{
    em_bus_event_t *evt = (em_bus_event_t *)evt_buf;
    char *buff = evt->u.subdoc.buff;
    char *tmp = (char *)malloc(ABQ_BUF_MAX);
    int g = gen_for(tc), off = 0;
    memset(evt_buf, 0, ABQ_EVT_SZ);
    memset(pcmd_buf, 0, sizeof(pcmd_buf));

    if (g == 0) {
        snprintf(tmp, ABQ_BUF_MAX, "%s", tc->json);
    } else {
        off += snprintf(tmp + off, ABQ_BUF_MAX - off, QH OC "\"Channel\":%d,\"BSSID\":\"aa:bb:cc:dd:ee:ff\",\"ReportingDetail\":%d,\"SSID\":\"test\"",
                        (g <= 4) ? 255 : 36, (g >= 5) ? 1 : 0);
        if (g == 1 || g == 2) {                       /* 17 / 16 AP channel reports */
            int n = (g == 1) ? 17 : 16;
            off += snprintf(tmp + off, ABQ_BUF_MAX - off, ",\"APChReportList\":[");
            for (int i = 0; i < n; i++)
                off += snprintf(tmp + off, ABQ_BUF_MAX - off, "%s{\"OpClass\":115,\"ChannelList\":[36]}", i ? "," : "");
            off += snprintf(tmp + off, ABQ_BUF_MAX - off, "]");
        } else if (g == 3 || g == 4) {                /* 65 / 64 channels in one report */
            int n = (g == 3) ? 65 : 64;
            off += snprintf(tmp + off, ABQ_BUF_MAX - off, ",\"APChReportList\":[{\"OpClass\":115,\"ChannelList\":[");
            for (int i = 0; i < n; i++)
                off += snprintf(tmp + off, ABQ_BUF_MAX - off, "%s%d", i ? "," : "", i + 1);
            off += snprintf(tmp + off, ABQ_BUF_MAX - off, "]}]");
        } else {                                      /* 33 / 32 element IDs, ReportingDetail=1 */
            int n = (g == 5) ? 33 : 32;
            off += snprintf(tmp + off, ABQ_BUF_MAX - off, ",\"ElementList\":[");
            for (int i = 0; i < n; i++)
                off += snprintf(tmp + off, ABQ_BUF_MAX - off, "%s%d", i ? "," : "", i);
            off += snprintf(tmp + off, ABQ_BUF_MAX - off, "]");
        }
        snprintf(tmp + off, ABQ_BUF_MAX - off, "%s", QT);
    }
    snprintf(buff, ABQ_BUF_MAX, "%s", tmp);
    evt->data_len = (unsigned int)strlen(buff);
    free(tmp);
}

} /* namespace abq */
