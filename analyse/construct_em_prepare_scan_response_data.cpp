/*
 * TEST CASES / CONSTRUCTOR: construct_em_prepare_scan_response_data
 *
 * provider_response lives at epsr_resp_buf; its stat_pointer points at a fresh
 * malloc of scan_count wifi_neighbor_ap2_t entries. scan_response (output) is
 * at epsr_scanresp_buf. The wifi_prop maps radio_index 0 -> "wlan0". The
 * wifi_freq_to_op_class stub treats ap_freq AS the operating class.
 *
 * modes: 0 distinct(3->3 results), 1 aggregate(3 same -> 1 result/3 nbrs),
 * 2 skips(empty ssid + op_class 0 -> 2 results), 3 max_neighbors(20 same ->
 * capped 16), 4 max_results(40 distinct -> capped 32), 5 radio_not_found,
 * 6 null_data, 7 zero_count.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char epsr_mgr_buf[sizeof(wifi_mgr_t) + EPSR_PAD];
alignas(16) char epsr_resp_buf[sizeof(wifi_provider_response_t) + EPSR_PAD];
alignas(16) char epsr_scanresp_buf[sizeof(channel_scan_response_t) + EPSR_PAD];
void *epsr_stat_pointer;

em_epsr_test_case_t em_prepare_scan_response_data_suite[] = {
    /* name            radio scan_count mode want_ret want_num_results */
    { "distinct_3",      0,   3,        0,    0,       3 },
    { "aggregate_3",     0,   3,        1,    0,       1 },
    { "skips",           0,   4,        2,    0,       2 },
    { "max_neighbors",   0,   20,       3,    0,       1 },
    { "max_results",     0,   40,       4,    0,       EM_MAX_RESULTS },
    { "radio_not_found", 9,   3,        0,   -1,       0 },
    { "null_data",       0,   3,        6,   -1,       0 },
    { "zero_count",      0,   0,        7,   -1,       0 },
    { NULL, 0, 0, 0, 0, 0 }  /* sentinel */
};

static void fill_ap(wifi_neighbor_ap2_t *ap, unsigned int op_class, unsigned int channel, const char *ssid)
{
    ap->ap_freq = op_class;              /* stub: freq == op_class (0 -> skipped) */
    ap->ap_Channel = channel;
    snprintf(ap->ap_SSID, sizeof(ap->ap_SSID), "%s", ssid);
    snprintf(ap->ap_BSSID, sizeof(ap->ap_BSSID), "aa:bb:cc:dd:ee:ff");
    snprintf(ap->ap_OperatingChannelBandwidth, sizeof(ap->ap_OperatingChannelBandwidth), "20MHz");
    ap->ap_ChannelUtilization = 30;
    ap->ap_Noise = -90;
    ap->ap_SignalStrength = -55;
    ap->bss_load_element_present = 1;
    ap->ap_StaCount = 5;
}

void construct_em_prepare_scan_response_data_input(const em_epsr_test_case_t *tc)
{
    memset(epsr_mgr_buf, 0, sizeof(epsr_mgr_buf));
    memset(epsr_resp_buf, 0, sizeof(epsr_resp_buf));
    memset(epsr_scanresp_buf, 0, sizeof(epsr_scanresp_buf));

    wifi_mgr_t *m = (wifi_mgr_t *)epsr_mgr_buf;
    wifi_platform_property_t *wp = &m->hal_cap.wifi_prop;
    for (int k = 0; k < 8; k++) wp->radio_interface_map[k].radio_index = -1;
    snprintf(wp->radio_interface_map[0].interface_name, 32, "wlan0"); wp->radio_interface_map[0].radio_index = 0;

    if (epsr_stat_pointer) { free(epsr_stat_pointer); epsr_stat_pointer = NULL; }
    int n = tc->scan_count > 0 ? tc->scan_count : 1;
    wifi_neighbor_ap2_t *arr = (wifi_neighbor_ap2_t *)calloc((size_t)n, sizeof(wifi_neighbor_ap2_t));
    epsr_stat_pointer = arr;

    switch (tc->mode) {
    case 0: /* distinct op_class per entry */
        for (int i = 0; i < tc->scan_count; i++) fill_ap(&arr[i], 100 + i, 36 + i, "Net");
        break;
    case 1: /* all same op_class + channel -> aggregate */
        for (int i = 0; i < tc->scan_count; i++) fill_ap(&arr[i], 115, 36, "Net");
        break;
    case 2: /* [0] valid, [1] empty ssid, [2] op_class 0, [3] valid distinct */
        fill_ap(&arr[0], 115, 36, "Net0");
        fill_ap(&arr[1], 115, 40, "");          /* empty SSID -> skipped */
        fill_ap(&arr[2], 0,   44, "Net2");      /* op_class 0 -> skipped */
        if (tc->scan_count > 3) fill_ap(&arr[3], 116, 48, "Net3");
        break;
    case 3: /* many neighbors, same op_class+channel -> capped at EM_MAX_NEIGHBORS */
        for (int i = 0; i < tc->scan_count; i++) fill_ap(&arr[i], 115, 36, "Net");
        break;
    case 4: /* many distinct results -> capped at EM_MAX_RESULTS */
        for (int i = 0; i < tc->scan_count; i++) fill_ap(&arr[i], 100 + i, 36 + i, "Net");
        break;
    case 6: /* null scan data */
        free(epsr_stat_pointer); epsr_stat_pointer = NULL;
        break;
    default:
        for (int i = 0; i < tc->scan_count; i++) fill_ap(&arr[i], 100 + i, 36 + i, "Net");
        break;
    }

    wifi_provider_response_t *resp = (wifi_provider_response_t *)epsr_resp_buf;
    resp->args.radio_index = tc->radio_index;
    resp->args.dwell_time  = 20;
    resp->stat_array_size  = tc->scan_count;
    resp->stat_pointer     = epsr_stat_pointer;
}
