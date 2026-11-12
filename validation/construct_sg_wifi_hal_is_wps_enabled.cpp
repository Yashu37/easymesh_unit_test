/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_is_wps_enabled
 *
 * wifi_hal_is_wps_enabled(radio, vap, conf) = vap WPS flag && !conf->ignore_broadcast_ssid && radio band != 6 GHz.  Inputs crossed: the WPS flag (0, 1, 2, 255), ignore_broadcast_ssid (0, 1, 2, -1), the radio band
 * (0, 2.4, 5, 5L, 5H, 6, 60 GHz and a mask containing the 6 GHz bit and another bit) and NULL radio / vap / conf (alone and all together).
 * Expected (CORRECT behaviour): true only when the flag is non-zero, ignore_broadcast_ssid is 0 and the band is not exactly 6 GHz; a NULL radio, vap or conf -> false (nothing can be enabled without them),
 * without reading through the NULL.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wie.h"

/* name, enable, ignore, band, radio_null, vap_null, conf_null, want, last */
hwr_wie_case_t sg_wifi_hal_is_wps_enabled_suite[] = {
	{ "enabled_2_4",                         1, 0, 0x1, 0, 0, 0, 1, 0 },
	{ "enabled_5",                           1, 0, 0x2, 0, 0, 0, 1, 0 },
	{ "enabled_5L",                          1, 0, 0x4, 0, 0, 0, 1, 0 },
	{ "enabled_5H",                          1, 0, 0x8, 0, 0, 0, 1, 0 },
	{ "six_ghz_disabled",                    1, 0, 0x10, 0, 0, 0, 0, 0 },
	{ "enabled_60",                          1, 0, 0x20, 0, 0, 0, 1, 0 },
	{ "enabled_band_0",                      1, 0, 0x0, 0, 0, 0, 1, 0 },
	{ "enable_flag_0",                       0, 0, 0x1, 0, 0, 0, 0, 0 },
	{ "enable_flag_2_nonzero",               2, 0, 0x1, 0, 0, 0, 1, 0 },
	{ "enable_flag_255_nonzero",             255, 0, 0x2, 0, 0, 0, 1, 0 },
	{ "hidden_ssid_1",                       1, 1, 0x1, 0, 0, 0, 0, 0 },
	{ "hidden_ssid_2",                       1, 2, 0x1, 0, 0, 0, 0, 0 },
	{ "hidden_ssid_minus1",                  1, -1, 0x2, 0, 0, 0, 0, 0 },
	{ "not_enabled_and_hidden",              0, 1, 0x1, 0, 0, 0, 0, 0 },
	{ "not_enabled_six_ghz",                 0, 0, 0x10, 0, 0, 0, 0, 0 },
	{ "hidden_and_six_ghz",                  1, 1, 0x10, 0, 0, 0, 0, 0 },
	{ "band_6_with_other_bit",               1, 0, 0x12, 0, 0, 0, 1, 0 },
	{ "conf_null_but_enable_0",              0, 0, 0x1, 0, 0, 1, 0, 0 },
	{ "radio_null_but_enable_0",             0, 0, 0x1, 1, 0, 0, 0, 0 },
	{ "radio_null_but_hidden",               1, 1, 0x1, 1, 0, 0, 0, 0 },
	{ "vap_null",                            1, 0, 0x1, 0, 1, 0, 0, 1 },
	{ "conf_null_enabled",                   1, 0, 0x1, 0, 0, 1, 0, 1 },
	{ "radio_null_enabled",                  1, 0, 0x1, 1, 0, 0, 0, 1 },
	{ "all_null",                            1, 0, 0x1, 1, 1, 1, 0, 1 },
	{ NULL }
};
