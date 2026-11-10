/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_startScan
 *
 * wifi_hal_startScan(index, scan_mode, dwell_time, num, chan_list).  Inputs crossed: index 0 / 1 / MAX_NUM_RADIOS / 99 / -1 / no radio; scan_mode ONCHAN / OFFCHAN / invalid; dwell_time 0 / 20 / 1000 /
 * INT_MAX / -1 / INT_MIN; num 0 / 1 / 5 / 50 / 102 / 103 / 128 / 129 / 200 / 300; chan_list NULL or an exact heap block of num entries (all the same valid channel, alternating valid / invalid, ascending
 * 1.., all frequency-0 (255), all invalid (0)); the ONCHAN radio channel valid / 0; radio without interfaces / interface map NULL / only AP interfaces / STA interface at the end; malloc failing; an unknown
 * country code; 6 GHz radios (radio->rnr_enabled); nl80211_start_scan returning 0 / -1; a 0 / 1 / 31 character STA SSID.  Expected (CORRECT behaviour): index outside 0..MAX_NUM_RADIOS-1 or dwell_time < 0 ->
 * WIFI_HAL_INVALID_ARGUMENTS; no radio, no STA interface, a bad mode, OFFCHAN without channels, malloc failure or no usable channel -> RETURN_ERR; otherwise the scan is started once on the STA interface with
 * flags COLOCATED_6GHZ|FLUSH, the frequencies of the usable channels (at most MAX_FREQ_LIST_SIZE = 128, in order), the dwell time and the STA SSID, the interface's scan results are flushed once, rnr_enabled is
 * set when a 6 GHz radio exists, the temporary radio-parameter copy is freed, and the result is 0 only when nl80211_start_scan returned 0.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wss.h"
#include <limits.h>

#define ON 0
#define OFF 1
#define BADM 2
/* name, index, mode, dwell, num, chan_null, chan_kind, chan_val, radio_channel, no_radio, imap_null, n_if, sta_pos, malloc_fail, bad_country, band6_mask, start_ret, ssid_len, last */
hwr_wss_case_t sg_wifi_hal_startScan_suite[] = {
	/* ---- index / dwell / radio / interface ---- */
	{ "index_max_radios",    MAX_NUM_RADIOS, ON, 20, 1, 1,0,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "index_99",            99, ON, 20, 1, 1,0,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "index_minus_1",       -1, ON, 20, 1, 1,0,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "dwell_minus_1",        0, ON, -1, 1, 1,0,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "dwell_int_min",        0, OFF, INT_MIN, 3, 0,0,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "no_radio",             0, ON, 20, 1, 1,0,0, 36, 1,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "interface_map_null",   0, ON, 20, 1, 1,0,0, 36, 0,1, 2,1, 0,0, 0, 0, 8, 0 },
	{ "no_interfaces",        0, ON, 20, 1, 1,0,0, 36, 0,0, 0,-1, 0,0, 0, 0, 8, 0 },
	{ "only_ap_interfaces",   0, ON, 20, 1, 1,0,0, 36, 0,0, 3,-1, 0,0, 0, 0, 8, 0 },
	{ "sta_is_last_interface",1, ON, 20, 1, 1,0,0, 36, 0,0, 3,2, 0,0, 0, 0, 8, 0 },
	/* ---- scan mode / channel arguments ---- */
	{ "mode_invalid",         0, BADM, 20, 3, 0,0,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_num_0",        0, OFF, 20, 0, 0,0,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_list_null",    0, OFF, 20, 3, 1,0,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "onchan_ignores_list",  0, ON, 20, 50, 1,0,0, 149, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "onchan_channel_0",     0, ON, 20, 1, 1,0,0, 0, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_1_channel",    0, OFF, 20, 1, 0,0,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_5_channels",   0, OFF, 100, 5, 0,2,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_alternating_bad", 0, OFF, 20, 6, 0,1,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_all_freq_0",   0, OFF, 20, 4, 0,3,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_all_invalid",  0, OFF, 20, 4, 0,4,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_unknown_country", 0, OFF, 20, 3, 0,0,36, 36, 0,0, 2,1, 0,1, 0, 0, 8, 0 },
	{ "offchan_2g_channels",  0, OFF, 20, 11, 0,2,0, 6, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	/* ---- dwell / result / ssid / rnr / malloc ---- */
	{ "dwell_0",              0, OFF, 0, 2, 0,2,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "dwell_int_max",        0, OFF, INT_MAX, 2, 0,2,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "start_scan_fails",     0, ON, 20, 1, 1,0,0, 36, 0,0, 2,1, 0,0, 0, -1, 8, 0 },
	{ "ssid_empty",           0, ON, 20, 1, 1,0,0, 36, 0,0, 2,1, 0,0, 0, 0, 0, 0 },
	{ "ssid_31_chars",        1, ON, 20, 1, 1,0,0, 100, 0,0, 2,1, 0,0, 0, 0, 31, 0 },
	{ "rnr_enabled_radio_1_6g", 0, ON, 20, 1, 1,0,0, 36, 0,0, 2,1, 0,0, 2, 0, 8, 0 },
	{ "rnr_enabled_own_6g",   0, ON, 20, 1, 1,0,0, 36, 0,0, 2,1, 0,0, 1, 0, 8, 0 },
	{ "malloc_fails",         0, OFF, 20, 3, 0,0,36, 36, 0,0, 2,1, 1,0, 0, 0, 8, 0 },
	/* ---- many channels: 102 usable channels fill chan_list_str to 510 chars (fits), 103 and more do not ---- */
	{ "offchan_50_channels",  0, OFF, 20, 50, 0,0,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_102_channels", 0, OFF, 20, 102, 0,0,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	{ "offchan_300_all_invalid", 0, OFF, 20, 300, 0,4,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 0 },
	/* ---- the original overflows chan_list_str[512] with the log string of 103+ usable channels ---- */
	{ "offchan_103_channels", 0, OFF, 20, 103, 0,0,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 1 },
	{ "offchan_128_channels", 0, OFF, 20, 128, 0,0,36, 36, 0,0, 2,1, 0,0, 0, 0, 8, 1 },
	{ "offchan_200_ascending",0, OFF, 20, 200, 0,2,0, 36, 0,0, 2,1, 0,0, 0, 0, 8, 1 },
	{ "offchan_300_channels", 0, OFF, 20, 300, 0,0,149, 36, 0,0, 2,1, 0,0, 0, 0, 8, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
