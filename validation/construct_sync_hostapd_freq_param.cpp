/*
 * UNIT TEST (input constructor): construct_sync_hostapd_freq_param
 *
 * sync_hostapd_freq_param(apIndex) looks up the interface for the AP index,
 * its radio, converts (country, operating class, channel) of the radio's
 * operating parameters to a frequency, and writes it into the running hostapd
 * interface (hapd.iface->freq) if it differs.  Returns RETURN_OK / RETURN_ERR.
 *
 * The suite is a table (see hshf_test_case in common.h); the runner
 * (sync_hostapd_freq_param_test.cpp) builds the world in runner-owned,
 * tail-poisoned slabs, poisons, calls the function, unpoisons and verifies.
 * Inputs crossed: apIndex (found / 7 not-found values), interface present /
 * absent, radio present / absent / index mismatch, hapd.iface NULL / set,
 * existing freq equal / different, 2.4 GHz / 5 GHz / 6 GHz channels at the
 * ends and in the middle, invalid channel and operating-class values, country
 * codes (6 known + 2 unknown).  Cases that dereference NULL run forked so the
 * SEGV is visible but does not stop the run.
 * Expected result is the SAFE contract (invalid input -> RETURN_ERR, running
 * hostapd interface untouched), so a FAIL is a finding.
 */
#include <string.h>
#include <stdio.h>
#include "common.h"
#include <limits.h>

/* ap, iface_present, vap_radio, radio_present, hapd, cc, oc, ch, cur, forked, ret, freq, country */
#define OK(n, cc, oc, ch, f)       { n, 3, 1, 0, 1, 1, cc, oc, ch, 1111, 0,  0, f, NULL, 1 }
#define OKC(n, cc, oc, ch, f, cs)  { n, 3, 1, 0, 1, 1, cc, oc, ch, 1111, 0,  0, f, cs, 1 }
#define BAD(n, cc, oc, ch)         { n, 3, 1, 0, 1, 1, cc, oc, ch, 1111, 0, -1, 1111, NULL, 1 }
#define NOAP(n, ap)                { n, ap, 1, 0, 1, 1, 1, 81, 6, 1111, 0, -1, 1111, NULL, 1 }

hshf_test_case_t sync_hostapd_freq_param_suite[] = {
	/* ---- interface lookup ---- */
	OK  ("ap3_found_2g_ch6",                  1, 81, 6, 2437),
	NOAP("ap0_not_found", 0), NOAP("ap1_not_found", 1), NOAP("ap2_not_found", 2), NOAP("ap4_not_found", 4),
	NOAP("ap15_not_found", 15), NOAP("ap16_not_found", 16), NOAP("ap_uint_max_not_found", UINT_MAX),
	{ "interface_absent",                     3, 0, 0, 1, 1, 1, 81, 6, 1111, 0, -1, 1111, NULL, 1 },
	/* ---- existing frequency ---- */
	{ "freq_already_equal_unchanged",         3, 1, 0, 1, 1, 1, 81, 6, 2437, 0,  0, 2437, NULL, 1 },
	{ "freq_different_updated",               3, 1, 0, 1, 1, 1, 81, 11, 2437, 0, 0, 2462, NULL, 1 },
	{ "freq_zero_updated",                    3, 1, 0, 1, 1, 1, 115, 36, 0, 0,   0, 5180, NULL, 1 },
	/* ---- 2.4 GHz ---- */
	OK("2g_ch1", 1, 81, 1, 2412), OK("2g_ch11", 1, 81, 11, 2462), OK("2g_ch13", 1, 81, 13, 2472), OK("2g_ch14_opclass82", 1, 82, 14, 2484),
	/* ---- 5 GHz ---- */
	OK("5g_ch36", 1, 115, 36, 5180), OK("5g_ch48", 1, 115, 48, 5240), OK("5g_ch52_dfs", 1, 118, 52, 5260),
	OK("5g_ch100_dfs", 1, 121, 100, 5500), OK("5g_ch149", 1, 125, 149, 5745), OK("5g_ch165", 1, 125, 165, 5825),
	/* ---- 6 GHz ---- */
	OK("6g_ch1", 1, 131, 1, 5955), OK("6g_ch93", 1, 133, 93, 6415), OK("6g_ch233", 1, 135, 233, 7115),
	/* ---- invalid operating parameters: must be rejected, not written to hostapd ---- */
	BAD("invalid_ch0_2g", 1, 81, 0), BAD("invalid_ch14_in_opclass81", 1, 81, 14), BAD("invalid_ch255_2g", 1, 81, 255),
	BAD("invalid_ch0_5g", 1, 115, 0), BAD("invalid_opclass0", 1, 0, 6), BAD("invalid_opclass200", 1, 200, 36),
	BAD("invalid_opclass255_ch255", 1, 255, 255),
	/* ---- country code mapping ---- */
	OKC("country_US", 1, 81, 6, 2437, "US"), OKC("country_CA", 2, 81, 6, 2437, "CA"), OKC("country_JP", 3, 81, 6, 2437, "JP"),
	OKC("country_CN", 4, 81, 6, 2437, "CN"), OKC("country_DE", 5, 81, 6, 2437, "DE"), OKC("country_GB", 6, 81, 6, 2437, "GB"),
	OKC("country_unknown_0_defaults_US", 0, 81, 6, 2437, "US"), OKC("country_unknown_999_defaults_US", 999, 81, 6, 2437, "US"),
	/* ---- crash group (forked): NULL radio / NULL hapd.iface ---- */
	{ "crash_radio_not_found",                3, 1, 0, 0, 1, 1, 81, 6, 1111, 1, -1, 1111, NULL, 1 },
	{ "crash_radio_index_mismatch",           3, 1, 7, 1, 1, 1, 81, 6, 1111, 1, -1, 1111, NULL, 1 },
	{ "crash_hapd_iface_null",                3, 1, 0, 1, 0, 1, 81, 6, 1111, 1, -1, 0,    NULL, 1 },
	{ "crash_hapd_iface_null_invalid_chan",   3, 1, 0, 1, 0, 1, 81, 0, 1111, 1, -1, 0,    NULL, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0 }
};
