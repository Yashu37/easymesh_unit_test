/*
 * UNIT TEST (input constructor): construct_platform_pre_create_vap
 *
 * platform_pre_create_vap(index, map) (platform/banana-pi): for every AP vap of the map whose security mode is a RADIUS (enterprise) mode, or
 * that is a lnf_radius / hotspot_secure vap, a primary and a secondary RADIUS server whose ip is still "0.0.0.0" get the defaults of
 * /nvram/wifi_defaults.txt: ip = "radius_s_ip" (45-byte ip / s_ip field), port = atoi("radius_s_port") (unsigned short), key = "radius_key"
 * (64-byte key / s_key); the value comes from wifi_nvram_defaultRead, which copies strlen+1 bytes (up to 128) into the destination; the port is
 * read into a 32-byte (BPI_LEN_32) stack buffer.  A second loop looks up the interface of every AP vap (the MLO part is compiled out).
 * The runner owns the map (vap_array[MAX_NUM_VAP_PER_RADIO = 8]) in a slab whose tail it POISONS and fills it with a 0x5A canary, then compares
 * the WHOLE map with the result of a safe oracle: a default is applied only when valid (ip 1..44 chars, port 1..65535, key 1..63 chars), otherwise
 * the field keeps its value; num_vaps > 8 or a NULL map -> -1 and the map untouched.  Inputs crossed: enterprise modes (wpa / wpa2 / wpa3 /
 * wpa+wpa2), personal mode, lnf_radius / hotspot_secure vaps, STA vap, primary / secondary / both / none unconfigured, several vaps, interface
 * NULL / STA, num_vaps 0 / 8 / 9 / 100, ip / key lengths around the field sizes, ports 0 / 1812 / 65535 / 65536 / 70000 / -1 / text / empty /
 * missing / 31, 32, 127 characters, nvram keys missing.  The rows that crash the unfixed function run forked.
 */
#include <string.h>
#include "hwr_ppv.h"

hwr_ppv_state_t hwr_ppv_st;
extern "C" int hwr_ppv_nvram(char *in, char *out)
{
	const char *val; int ret;

	if (!strcmp(in, "radius_s_ip")) { hwr_ppv_st.n_ip++; val = hwr_ppv_st.ip_val; ret = hwr_ppv_st.ip_ret; }
	else if (!strcmp(in, "radius_s_port")) { hwr_ppv_st.n_port++; val = hwr_ppv_st.port_val; ret = hwr_ppv_st.port_ret; }
	else if (!strcmp(in, "radius_key")) { hwr_ppv_st.n_key++; val = hwr_ppv_st.key_val; ret = hwr_ppv_st.key_ret; }
	else { hwr_ppv_st.n_other++; return -1; }
	if (ret) return -1;
	strncpy(out, val, strlen(val) + 1);   /* wifi_nvram_defaultRead: strncpy(out,position,strlen(position)+1) */
	return 0;
}
static wifi_interface_info_t hwr_ppv_ifs[16];
extern "C" wifi_interface_info_t *hwr_ppv_get_if(unsigned int vap_index)
{
	hwr_ppv_st.get_if_calls++;
	if (vap_index >= 16 || hwr_ppv_st.if_mode[vap_index] < 0) return NULL;
	hwr_ppv_ifs[vap_index].vap_info.vap_mode = (wifi_vap_mode_t)hwr_ppv_st.if_mode[vap_index];
	return &hwr_ppv_ifs[vap_index];
}
extern "C" BOOL hwr_ppv_is_lnf(UINT ap_index) { return ap_index == HWR_PPV_LNF_IDX; }
extern "C" BOOL hwr_ppv_is_hotspot(UINT ap_index) { return ap_index == HWR_PPV_HOTSPOT_IDX; }

#define L10  "0123456789"
#define L40  L10 L10 L10 L10
#define L127 L40 L40 L40 "0123456"
#define AP   wifi_vap_mode_ap
#define STA  wifi_vap_mode_sta
#define ENT  wifi_security_mode_wpa2_enterprise
#define PER  wifi_security_mode_wpa2_personal
#define NO   "0.0.0.0"
/* a vap: mode, sec, vap_index, ip, s_ip, port, s_port, key, s_key, interface mode (AP) */
#define RADV(idx)           { AP, ENT, idx, NO, NO, 0, 0, "oldkey", "oldskey", AP }
#define NONE_V              { AP, PER, 0, NO, NO, 0, 0, "oldkey", "oldskey", AP }
/* name, null_map, num_vaps, v[3], ip_val, ip_ret, port_val, port_ret, key_val, key_ret, expected_ret, forked */
hwr_ppv_case_t platform_pre_create_vap_suite[] = {
	/* ---- applied ---- */
	{ "wpa2_enterprise_defaults_applied", 0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "wpa3_enterprise",             0, 1, { { AP, wifi_security_mode_wpa3_enterprise, 1, NO, NO, 0, 0, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "wpa_enterprise",              0, 1, { { AP, wifi_security_mode_wpa_enterprise, 1, NO, NO, 0, 0, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "wpa_wpa2_enterprise",         0, 1, { { AP, wifi_security_mode_wpa_wpa2_enterprise, 1, NO, NO, 0, 0, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "lnf_radius_vap_personal_mode", 0, 1, { { AP, PER, HWR_PPV_LNF_IDX, NO, NO, 0, 0, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "hotspot_secure_vap_personal_mode", 0, 1, { { AP, PER, HWR_PPV_HOTSPOT_IDX, NO, NO, 0, 0, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "ipv6_ip",                     0, 1, { RADV(0), NONE_V, NONE_V }, "2001:db8::1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "port_1",                      0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1", 0, "secret", 0, 0, 0 },
	{ "port_65535",                  0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "65535", 0, "secret", 0, 0, 0 },
	{ "port_31_digits_fits_buffer",  0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "0000000000000000000000000001812", 0, "secret", 0, 0, 0 },
	{ "ip_44_chars_fits",            0, 1, { RADV(0), NONE_V, NONE_V }, "1234567890123456789012345678901234567890123.", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "key_63_chars_fits",           0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, L40 L10 L10 "012", 0, 0, 0 },
	{ "key_shorter_than_old_key",    0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "k", 0, 0, 0 },
	/* ---- not applied ---- */
	{ "personal_mode_untouched",     0, 1, { NONE_V, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "sta_vap_enterprise_untouched", 0, 1, { { STA, ENT, 0, NO, NO, 0, 0, "oldkey", "oldskey", STA }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "both_already_configured",     0, 1, { { AP, ENT, 0, "1.2.3.4", "5.6.7.8", 1812, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "only_primary_unconfigured",   0, 1, { { AP, ENT, 0, NO, "5.6.7.8", 0, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "only_secondary_unconfigured", 0, 1, { { AP, ENT, 0, "1.2.3.4", NO, 1812, 0, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "two_radius_vaps",             0, 2, { RADV(0), RADV(1), NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "three_vaps_mixed",            0, 3, { RADV(0), { STA, ENT, 1, NO, NO, 0, 0, "oldkey", "oldskey", STA }, RADV(2) }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "interface_null_for_vap",      0, 1, { { AP, ENT, 3, NO, NO, 0, 0, "oldkey", "oldskey", -1 }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "interface_is_sta",            0, 1, { { AP, ENT, 3, NO, NO, 0, 0, "oldkey", "oldskey", STA }, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "num_vaps_0",                  0, 0, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "num_vaps_8_all_fit",          0, 8, { RADV(0), RADV(1), RADV(2) }, "10.0.0.1", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "map_null",                    1, 0, { NONE_V, NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, -1, 0 },
	/* ---- nvram values that are missing / invalid: the field keeps its value ---- */
	{ "nvram_ip_missing",            0, 1, { RADV(0), NONE_V, NONE_V }, "", -1, "1812", 0, "secret", 0, 0, 0 },
	{ "nvram_ip_empty",              0, 1, { RADV(0), NONE_V, NONE_V }, "", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "nvram_key_missing",           0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "", -1, 0, 0 },
	{ "nvram_key_empty",             0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "", 0, 0, 0 },
	{ "nvram_port_missing",          0, 1, { { AP, ENT, 0, NO, NO, 1812, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "", -1, "secret", 0, 0, 0 },
	{ "nvram_port_empty",            0, 1, { { AP, ENT, 0, NO, NO, 1812, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "", 0, "secret", 0, 0, 0 },
	{ "nvram_port_text",             0, 1, { { AP, ENT, 0, NO, NO, 1812, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "abc", 0, "secret", 0, 0, 0 },
	{ "nvram_port_0",                0, 1, { { AP, ENT, 0, NO, NO, 1812, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "0", 0, "secret", 0, 0, 0 },
	{ "nvram_port_65536",            0, 1, { { AP, ENT, 0, NO, NO, 1812, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "65536", 0, "secret", 0, 0, 0 },
	{ "nvram_port_70000",            0, 1, { { AP, ENT, 0, NO, NO, 1812, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "70000", 0, "secret", 0, 0, 0 },
	{ "nvram_port_minus_1",          0, 1, { { AP, ENT, 0, NO, NO, 1812, 1813, "oldkey", "oldskey", AP }, NONE_V, NONE_V }, "10.0.0.1", 0, "-1", 0, "secret", 0, 0, 0 },
	/* ---- values longer than the destination fields ---- */
	{ "ip_45_chars_overflows_field", 0, 1, { RADV(0), NONE_V, NONE_V }, "1234567890123456789012345678901234567890123.5", 0, "1812", 0, "secret", 0, 0, 0 },
	{ "ip_127_chars_overflows_field", 0, 1, { RADV(0), NONE_V, NONE_V }, L127, 0, "1812", 0, "secret", 0, 0, 0 },
	{ "key_64_chars_overflows_field", 0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, L40 L10 L10 "0123", 0, 0, 0 },
	{ "key_127_chars_overflows_field", 0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, L127, 0, 0, 0 },
	{ "crash_port_32_chars_stack_overflow",  0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "00000000000000000000000000001812", 0, "secret", 0, 0, 1 },
	{ "crash_port_127_chars_stack_overflow", 0, 1, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, L127, 0, "secret", 0, 0, 1 },
	/* ---- num_vaps larger than vap_array ---- */
	{ "crash_num_vaps_9_over_read",  0, 9, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, -1, 1 },
	{ "crash_num_vaps_100_over_read", 0, 100, { RADV(0), NONE_V, NONE_V }, "10.0.0.1", 0, "1812", 0, "secret", 0, -1, 1 },
	{ NULL, 0, 0, { NONE_V, NONE_V, NONE_V }, NULL, 0, NULL, 0, NULL, 0, 0, 0 }
};
