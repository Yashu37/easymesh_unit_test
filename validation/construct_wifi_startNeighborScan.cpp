/*
 * UNIT TEST (input constructor): construct_wifi_startNeighborScan
 *
 * wifi_startNeighborScan(apIndex, scan_mode, dwell_time, chan_num, chan_list) (platform/banana-pi) forwards to
 * wifi_hal_startNeighborScan (src/wifi_hal.c:3147).  The suite crosses: argument checks (dwell_time < 0, apIndex outside 0..MAX_VAP-1), the
 * lookups (vap interface / radio / private interface missing), the scan state on entry (already STARTED is refused, ERROR / ABORTED / old
 * results are reset), every scan mode (FULL, ONCHAN, OFFCHAN, SELECT_CHANNELS, NONE / SURVEY unsupported), AP vap (channels checked against the
 * hostapd channel table: enabled / disabled / unknown) and STA vap (channels converted with the op class), no channel list (the radio's
 * current channel is used), the dwell_time == 0 ON-CHANNEL special case (results requested immediately), a hostapd interface that does not exist
 * yet (hapd.iface NULL / current_mode NULL) and failing nl80211 calls.  Rows named crash_* crash the unfixed function and run in a child.
 *
 * Row layout: name, ap_index, mode, dwell, chan_num, list_null, {list} | vap_mode(0 ap,1 sta), has_ap_iface, has_radio, has_priv(0 none,1 same as the
 * vap,2 separate), radio_channel, country, op_class, hapd_state(0 iface NULL,1 no current_mode,2 table), pre_state, pre_results, nl_start_rc,
 * nl_results_rc | expected_ret, exp_state, start_calls, results_calls, cleanup_calls, filter_num, {filter}, start_flags, active, forked.
 * ap_index 1000 = MAX_VAP, 1001 = MAX_VAP - 1.  Scan modes: 0 NONE 1 FULL 2 ONCHAN 3 OFFCHAN 4 SURVEY 5 SELECT_CHANNELS.  States: 0 NONE 1 ERROR 2 STARTED.
 * hapd channel table: 1=2412, 6=2437, 11=2462 (disabled), 36=5180, 52=5260 (disabled), 100=5500.  STA op class 81 = 2.4 GHz, 115 = 5 GHz.
 */
#include <initializer_list>
#include "hwr_wsn.h"

/* ---- input constructor: builds the AP / STA / private interfaces, the radio, the hostapd channel table and the caller's channel list for one row ---- */
unsigned int    list_slab[16];
wsn_chan_t      chan_slab[8];
wsn_hw_mode_t   mode_obj;
wsn_hiface_t    hif_obj;
wsn_interface_t ifA, ifP;
wsn_radio_t     radio_obj;


int resolve_index(int idx) { return idx == 1000 ? MAX_VAP : idx == 1001 ? MAX_VAP - 1 : idx; }

wsn_interface_t *construct_wifi_startNeighborScan_input(const hwr_wsn_case_t *t, int idx)
{
	wsn_interface_t *si;
	static const wsn_chan_t table[6] = { {1, 2412, 0}, {6, 2437, 0}, {11, 2462, WSN_CHAN_DISABLED}, {36, 5180, 0}, {52, 5260, WSN_CHAN_DISABLED}, {100, 5500, 0} };

	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(&hwr_wsn_world, 0, sizeof(hwr_wsn_world));
	memset(&ifA, 0, sizeof(ifA)); memset(&ifP, 0, sizeof(ifP)); memset(&radio_obj, 0, sizeof(radio_obj));
	memset(list_slab, 0xA5, sizeof(list_slab));
	memset(chan_slab, 0, sizeof(chan_slab)); memcpy(chan_slab, table, sizeof(table));
	for (int i = 0; i < WSN_MAXL && (unsigned)i < t->chan_num; i++) list_slab[i] = t->list[i];

	mode_obj.num_channels = 6; mode_obj.channels = chan_slab;
	hif_obj.current_mode = (t->hapd_state == 2) ? &mode_obj : NULL;
	for (wsn_interface_t *p : { &ifA, &ifP }) {
		pthread_mutex_init(&p->scan_state_mutex, NULL);
		pthread_mutex_init(&p->scan_info_mutex, NULL);
		pthread_mutex_init(&p->scan_info_ap_mutex, NULL);
		p->vap_info.radio_index = 0;
		p->u.ap.hapd.iface = (t->hapd_state == 0) ? NULL : &hif_obj;
	}
	snprintf(ifA.name, sizeof(ifA.name), "wlan0.1"); snprintf(ifP.name, sizeof(ifP.name), "wlan0");
	ifA.vap_info.vap_mode = (t->vap_mode == 0) ? wifi_vap_mode_ap : wifi_vap_mode_sta;
	ifP.vap_info.vap_mode = wifi_vap_mode_ap;
	snprintf(ifA.vap_info.u.sta_info.ssid, sizeof(ifA.vap_info.u.sta_info.ssid), "BackhaulNet");
	snprintf(ifP.vap_info.u.sta_info.ssid, sizeof(ifP.vap_info.u.sta_info.ssid), "PrivateNet");
	snprintf(radio_obj.name, sizeof(radio_obj.name), "wlan0");
	radio_obj.oper_param.countryCode = t->country; radio_obj.oper_param.operatingClass = t->op_class; radio_obj.oper_param.channel = t->radio_channel;

	si = (t->has_priv == 2) ? &ifP : &ifA;
	si->scan_state = t->pre_state; si->scan_has_results = t->pre_results;
	si->scan_filter.values = (unsigned int *)malloc(3 * sizeof(unsigned int));
	si->scan_filter.values[0] = si->scan_filter.values[1] = si->scan_filter.values[2] = 7; si->scan_filter.num = 3;

	hwr_wsn_world.ap_iface = t->has_ap_iface ? &ifA : NULL; hwr_wsn_world.ap_vap_index = (unsigned)idx;
	hwr_wsn_world.radio = t->has_radio ? &radio_obj : NULL; hwr_wsn_world.radio_index = 0;
	hwr_wsn_world.priv_iface = (t->has_priv == 0) ? NULL : (t->has_priv == 1 ? &ifA : &ifP);
	hwr_wsn_world.nl_start_rc = t->nl_start_rc; hwr_wsn_world.nl_results_rc = t->nl_results_rc;
	return si;
}



#define WAP    0,1,1,1,6,1,81,2,0,0,0,0     /* AP vap, private interface is the vap, radio channel 6, US, op class 81, hapd table */
#define WSTA   1,1,1,2,6,1,81,2,0,0,0,0     /* STA vap, separate private AP interface */
#define NOL    {0,0,0,0,0,0}
#define NOV    {0,0,0,0,0,0}

hwr_wsn_case_t wifi_startNeighborScan_suite[] = {
	/* ---- argument checks / lookups ---- */
	{ "invalid_dwell_negative",          0,    1,  -1, 0, 1, NOL,           WAP,  -4, 0, 0,0,0, 0, NOV, 0,0, 0 },
	{ "ap_index_negative",              -1,    1, 100, 0, 1, NOL,           WAP,  -4, 0, 0,0,0, 0, NOV, 0,0, 0 },
	{ "ap_index_equal_MAX_VAP",       1000,    1, 100, 0, 1, NOL,           WAP,  -4, 0, 0,0,0, 0, NOV, 0,0, 0 },
	{ "ap_index_MAX_VAP_minus_1_valid", 1001,  1, 100, 0, 1, NOL,           WAP,   0, 2, 1,0,1, 4, {2412,2437,5180,5500}, 6,0, 0 },
	{ "no_interface_for_ap_index",       0,    1, 100, 0, 1, NOL,           0,0,1,1,6,1,81,2,0,0,0,0,  -1, 0, 0,0,0, 0, NOV, 0,0, 0 },
	{ "no_radio_for_interface",          0,    1, 100, 0, 1, NOL,           0,1,0,1,6,1,81,2,0,0,0,0,  -1, 0, 0,0,0, 0, NOV, 0,0, 0 },
	{ "no_private_interface",            0,    1, 100, 0, 1, NOL,           0,1,1,0,6,1,81,2,0,0,0,0,  -1, 0, 0,0,0, 0, NOV, 0,0, 0 },
	{ "scan_already_started",            0,    1, 100, 0, 1, NOL,           0,1,1,1,6,1,81,2,2,0,0,0,  -2, 2, 0,0,0, 0, NOV, 0,0, 0 },
	{ "scan_state_error_is_reset",       0,    1, 100, 0, 1, NOL,           0,1,1,1,6,1,81,2,1,0,0,0,   0, 2, 1,0,1, 4, {2412,2437,5180,5500}, 6,0, 0 },
	{ "old_results_not_collected_still_scans", 0, 1, 100, 0, 1, NOL,        0,1,1,1,6,1,81,2,0,1,0,0,   0, 2, 1,0,1, 4, {2412,2437,5180,5500}, 6,0, 0 },
	{ "separate_private_interface",      0,    1, 100, 0, 1, NOL,           0,1,1,2,6,1,81,2,0,0,0,0,   0, 2, 1,0,1, 4, {2412,2437,5180,5500}, 6,0, 0 },
	/* ---- FULL / unsupported modes ---- */
	{ "full_dwell_zero_not_special",     0,    1,   0, 0, 1, NOL,           WAP,   0, 2, 1,0,1, 4, {2412,2437,5180,5500}, 6,0, 0 },
	{ "full_sta_vap_refused",            0,    1, 100, 0, 1, NOL,           WSTA, -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "full_hapd_mode_missing",          0,    1, 100, 0, 1, NOL,           0,1,1,1,6,1,81,1,0,0,0,0,  -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "crash_full_hapd_iface_null",      0,    1, 100, 0, 1, NOL,           0,1,1,1,6,1,81,0,0,0,0,0,  -1, 0, 0,0,1, 0, NOV, 0,0, 1 },
	{ "full_nl_start_fails",             0,    1, 100, 0, 1, NOL,           0,1,1,1,6,1,81,2,0,0,-1,0, -1, 0, 1,0,1, 4, {2412,2437,5180,5500}, 6,0, 0 },
	{ "mode_none_unsupported",           0,    0, 100, 0, 1, NOL,           WAP,  -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "scan_state_error_reset_even_when_refused", 0, 4, 100, 0, 1, NOL,     0,1,1,1,6,1,81,2,1,0,0,0,  -1, 0, 0,0,1, 0, NOV, 0,0, 0 },   /* SURVEY is unsupported; the ERROR state is still reset */
	/* ---- OFFCHAN ---- */
	{ "offchan_ap_two_channels",         0,    3,  50, 2, 0, {1,36,0,0,0,0}, WAP,  0, 2, 1,0,1, 2, {2412,5180}, 6,0, 0 },
	{ "offchan_ap_disabled_channel",     0,    3,  50, 1, 0, {11,0,0,0,0,0}, WAP, -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "offchan_ap_unknown_channel",      0,    3,  50, 1, 0, {7,0,0,0,0,0},  WAP, -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "offchan_second_channel_invalid",  0,    3,  50, 2, 0, {1,7,0,0,0,0},  WAP, -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "offchan_list_null",               0,    3,  50, 2, 1, NOL,           WAP,  -4, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "offchan_chan_num_zero",           0,    3,  50, 0, 0, {1,0,0,0,0,0},  WAP, -4, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "offchan_sta_two_channels",        0,    3,  50, 2, 0, {1,6,0,0,0,0},  WSTA, 0, 2, 1,0,1, 2, {2412,2437}, 0,1, 0 },
	{ "offchan_sta_channel_not_in_opclass", 0, 3,  50, 1, 0, {36,0,0,0,0,0}, WSTA,-1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "crash_offchan_ap_hapd_iface_null", 0,   3,  50, 1, 0, {1,0,0,0,0,0},  0,1,1,1,6,1,81,0,0,0,0,0, -1, 0, 0,0,1, 0, NOV, 0,0, 1 },
	/* ---- SELECT_CHANNELS ---- */
	{ "select_ap_three_channels",        0,    5, 100, 3, 0, {100,6,1,0,0,0}, WAP, 0, 2, 1,0,1, 3, {5500,2437,2412}, 6,0, 0 },
	{ "select_sta_vap_uses_hapd",        0,    5, 100, 1, 0, {100,0,0,0,0,0}, WSTA,0, 2, 1,0,1, 1, {5500}, 0,1, 0 },
	{ "select_list_null",                0,    5, 100, 2, 1, NOL,           WAP,  -4, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "select_disabled_channel",         0,    5, 100, 1, 0, {52,0,0,0,0,0}, WAP, -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "crash_select_hapd_iface_null",    0,    5, 100, 1, 0, {1,0,0,0,0,0},  0,1,1,1,6,1,81,0,0,0,0,0, -1, 0, 0,0,1, 0, NOV, 0,0, 1 },
	/* ---- ONCHAN (dwell_time > 0) ---- */
	{ "onchan_ap_list_one",              0,    2, 100, 1, 0, {36,0,0,0,0,0}, WAP,  0, 2, 1,0,1, 1, {5180}, 6,0, 0 },
	{ "onchan_ap_small_dwell_triggers_scan", 0, 2,   1, 1, 0, {36,0,0,0,0,0}, WAP,  0, 2, 1,0,1, 1, {5180}, 6,0, 0 },
	{ "onchan_ap_no_list_uses_radio_channel", 0, 2, 100, 0, 1, NOL,         WAP,  0, 2, 1,0,1, 1, {2437}, 6,0, 0 },
	{ "onchan_ap_no_list_radio_channel_disabled", 0, 2, 100, 0, 1, NOL,     0,1,1,1,11,1,81,2,0,0,0,0, -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "crash_onchan_ap_no_list_radio_channel_zero", 0, 2, 100, 0, 1, NOL,   0,1,1,1,0,1,81,2,0,0,0,0,  -1, 0, 0,0,1, 0, NOV, 0,0, 1 },
	{ "crash_onchan_ap_chan_num_zero_radio_channel_zero", 0, 2, 100, 0, 0, {1,0,0,0,0,0}, 0,1,1,1,0,1,81,2,0,0,0,0, -1, 0, 0,0,1, 0, NOV, 0,0, 1 },
	{ "onchan_ap_chan_num_zero_list_ignored", 0, 2, 100, 0, 0, {1,0,0,0,0,0}, 0,1,1,1,36,1,81,2,0,0,0,0, 0, 2, 1,0,1, 1, {5180}, 6,0, 0 },
	{ "onchan_sta_no_list_radio_channel", 0,   2, 100, 0, 1, NOL,           WSTA, 0, 2, 1,0,1, 1, {2437}, 0,1, 0 },
	{ "onchan_sta_no_list_opclass_unknown", 0, 2, 100, 0, 1, NOL,           1,1,1,2,6,1,5,2,0,0,0,0,  -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "onchan_sta_list_5g",              0,    2, 100, 1, 0, {36,0,0,0,0,0}, 1,1,1,2,6,1,115,2,0,0,0,0, 0, 2, 1,0,1, 1, {5180}, 0,1, 0 },
	{ "crash_onchan_ap_hapd_iface_null", 0,    2, 100, 1, 0, {1,0,0,0,0,0},  0,1,1,1,6,1,81,0,0,0,0,0, -1, 0, 0,0,1, 0, NOV, 0,0, 1 },
	/* ---- ONCHAN with dwell_time == 0: results requested immediately, no scan is triggered ---- */
	{ "dwell0_ap_list_one",              0,    2,   0, 1, 0, {1,0,0,0,0,0},  WAP,  0, 0, 0,1,1, 1, {2412}, 0,0, 0 },
	{ "dwell0_ap_second_channel_disabled", 0,  2,   0, 2, 0, {1,11,0,0,0,0}, WAP, -1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ "dwell0_sta_list_one",             0,    2,   0, 1, 0, {1,0,0,0,0,0},  WSTA, 0, 0, 0,1,1, 1, {2412}, 0,0, 0 },
	{ "dwell0_results_fail",             0,    2,   0, 1, 0, {1,0,0,0,0,0},  0,1,1,1,6,1,81,2,0,0,0,-1, -1, 0, 0,1,1, 1, {2412}, 0,0, 0 },
	{ "crash_dwell0_ap_no_list_radio_channel_zero", 0, 2, 0, 0, 1, NOL,     0,1,1,1,0,1,81,2,0,0,0,0,  -1, 0, 0,0,1, 0, NOV, 0,0, 1 },
	{ "dwell0_ap_no_list_radio_channel", 0,    2,   0, 0, 1, NOL,           0,1,1,1,36,1,81,2,0,0,0,0,  0, 0, 0,1,1, 1, {5180}, 0,0, 0 },
	{ "dwell0_sta_second_channel_invalid", 0,  2,   0, 2, 0, {1,36,0,0,0,0}, WSTA,-1, 0, 0,0,1, 0, NOV, 0,0, 0 },
	{ NULL }
};
