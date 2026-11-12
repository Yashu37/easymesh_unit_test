/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_wps_init
 *
 * wifi_hal_wps_init(radio, vap, conf) sets conf->wps_state / wps_rf_bands / uuid / config_methods / ap_pin / wps_cred_processing / pbc_in_m1 from the VAP's WPS settings.  Inputs crossed: radio scenario (0 no radios;
 * 1 one 2.4 GHz radio with a private_ssid_ interface; 2 three radios 2.4 / 5 / 6 GHz each with a private_ssid_ interface; 3 radio0 2.4 GHz with a public_ssid_ interface, radio1 5 GHz private_ssid_, radio2 6 GHz
 * without interface; 4 a 60 GHz radio and a 2.4 GHz radio, both private; 5 radio0 has rdk index 7 (never found) and radio1 5H; 6 a 2.4 GHz radio with an empty interface map), WPS flag, hidden SSID, the VAP radio's
 * band, VAP name shape (normal / no underscore / trailing underscore / only "_" / public / 64 characters unterminated / empty), onboarding methods (PB|PIN, PB, PIN, none, other bit, PB|PIN|label), the PIN (empty,
 * 7 / 8 characters, nine unterminated characters: only its first byte is tested by strlen != 0, so no over-read happens), a pre-set UUID, NULL config_methods / ap_pin buffers and NULL conf / vap / radio.  The conf starts with wps_state = 2 and wps_rf_bands = 3 so the reset is visible.
 * Expected (CORRECT behaviour): wps_state = 0 and wps_rf_bands = 0 on entry.  When WPS is not enabled for the VAP (flag 0, hidden SSID, 6 GHz radio, NULL radio / vap) or the type prefix (the name up to the last
 * '_') cannot be derived (no '_', or a name that is not terminated inside its 64-byte field) nothing else changes.  Otherwise wps_state = 2 (configured); wps_rf_bands = OR of 0x01 / 0x02 for every radio (found
 * by rdk index 0..num_radios-1) that has an interface whose name starts with the type and whose band is 2.4 / 5 / 5L / 5H GHz (6 GHz adds 0, other bands are skipped); the UUID, when nil, = first 16 bytes of
 * SHA1(namespace id || mac) of the first such interface (a set UUID is kept); config_methods = "label display push_button keypad" for PB|PIN, "display virtual_push_button physical_push_button push_button
 * virtual_display" for PB, "keypad label display" for PIN, unchanged otherwise; ap_pin = the first 8 characters of a non-empty PIN (a PIN field is at most 9 characters and need not be terminated); wps_cred_processing
 * = 1 and pbc_in_m1 = 1.  A NULL config_methods / ap_pin buffer is skipped (no write); a NULL conf returns without writing.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wwi.h"

/* name, scen, enable, ignore, rband, vname, methods, pin, uuid_pre, cm_null, pin_null, conf_null, vap_null, radio_null, last */
hwr_wwi_case_t sg_wifi_hal_wps_init_suite[] = {
	{ "success_one_radio",                       1, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "success_three_radios_2g_5g_6g",           2, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "no_radios",                               0, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "only_radio1_has_private_iface",           3, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "band_60ghz_radio_skipped",                4, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "rdk_index_mismatch_radio_skipped",        5, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "empty_interface_map",                     6, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "uuid_already_set_kept",                   2, 1, 0, 0x1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 },
	{ "vap_type_public_ssid",                    3, 1, 0, 0x1, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "vap_name_no_underscore",                  1, 1, 0, 0x1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "vap_name_trailing_underscore",            1, 1, 0, 0x1, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "vap_name_only_underscore",                1, 1, 0, 0x1, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "vap_name_empty",                          1, 1, 0, 0x1, 6, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "disabled_enable_0",                       1, 0, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "disabled_hidden_ssid",                    1, 1, 1, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "disabled_6ghz_radio",                     1, 1, 0, 0x10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "enable_flag_2",                           1, 2, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "radio_5g_enabled",                        1, 1, 0, 0x2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "methods_pushbutton_and_pin",              1, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "methods_pushbutton",                      1, 1, 0, 0x1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "methods_pin",                             1, 1, 0, 0x1, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "methods_none",                            1, 1, 0, 0x1, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "methods_other_bit",                       1, 1, 0, 0x1, 0, 4, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "methods_pb_pin_label",                    1, 1, 0, 0x1, 0, 5, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ "pin_empty",                               1, 1, 0, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "pin_7_chars",                             1, 1, 0, 0x1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0 },
	{ "pin_8_chars",                             1, 1, 0, 0x1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0 },
	{ "vap_null",                                1, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0 },
	{ "radio_null",                              1, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0 },
	{ "cm_null_but_methods_none",                1, 1, 0, 0x1, 0, 3, 1, 0, 1, 0, 0, 0, 0, 0 },
	{ "pin_buf_null_but_pin_empty",              1, 1, 0, 0x1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 },
	{ "cm_null_but_disabled",                    1, 0, 0, 0x1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0 },
	{ "conf_null",                               1, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1 },
	{ "conf_null_vap_null",                      1, 1, 0, 0x1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1 },
	{ "config_methods_null_pb_pin",              1, 1, 0, 0x1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1 },
	{ "config_methods_null_pushbutton",          1, 1, 0, 0x1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1 },
	{ "config_methods_null_pin",                 1, 1, 0, 0x1, 0, 2, 1, 0, 1, 0, 0, 0, 0, 1 },
	{ "ap_pin_null_pin_set",                     1, 1, 0, 0x1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1 },
	{ "pin_nine_chars_unterminated",             1, 1, 0, 0x1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0 },
	{ "vap_name_64_chars_unterminated",          1, 1, 0, 0x1, 5, 0, 1, 0, 0, 0, 0, 0, 0, 1 },
	{ NULL }
};
