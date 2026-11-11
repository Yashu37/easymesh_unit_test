/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_setBTMRequest
 *
 * wifi_hal_setBTMRequest(apIndex, peerMac, request).  Inputs crossed: peerMac NULL; request NULL; apIndex 0 / 1 / 3 / 4 (no interface) / UINT_MAX; interface in STA mode; station not found; requestMode 0 /
 * candidates (bit0) / termination (bit3) / ESS disassoc (bit4) / combinations / 0x06 and 0xFF (other bits); termDuration.duration 0 / 7; numCandidates 0 / 1 / 5 / 63 / 64 / 255; urlLen 0 / 1 / 100 / 511 / 512 and
 * url[0] = 0; token 0 / 9; malloc failing for the candidate buffer or the URL; wifi_wnm_send_bss_tm_req returning -1 / 0 / 5; a urlLen of 20000 / 65535 on a request whose bytes are all non-NUL.  request is an
 * exact heap block of sizeof(wifi_BTMRequest_t).  Expected (CORRECT behaviour): NULL peerMac or request -> WIFI_HAL_INVALID_ARGUMENTS (nothing dereferenced); no interface / STA mode / no station -> WIFI_HAL_ERROR;
 * the termination flag is dropped when duration is 0, the candidate flag when there are no candidates, the ESS flag when there is no URL; numCandidates >= MAX_CANDIDATES or an allocation failure -> WIFI_HAL_ERROR
 * with nothing sent; otherwise one request is sent for the station with the token, mode, timer, validity, the BSS termination sub-element, the NUL-terminated URL (at most MAX_URL_LEN characters, never read
 * beyond request->url[]) and the neighbour report list (18 bytes per candidate); a returned token > 0 is stored in request->token when it was 0; the mutex is released and nothing leaks.
 * Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wbt.h"
#include <limits.h>

#define PC 0x01
#define TD 0x08
#define ES 0x10
/* name, apIndex, peer_null, req_null, no_iface, vap_sta, no_sta, mode, dur, ncand, urlLen, url_kind, token, malloc_fail_at, send_ret, last */
hwr_wbt_case_t sg_wifi_hal_setBTMRequest_suite[] = {
	/* ---- arguments / interface / station ---- */
	{ "peer_null",               0, 1,0, 0,0,0, 0,     0, 0, 0,   0, 0, 0, 1, 0 },
	{ "apindex_4_no_interface",  4, 0,0, 0,0,0, 0,     0, 0, 0,   0, 0, 0, 1, 0 },
	{ "apindex_uint_max",  UINT_MAX, 0,0, 0,0,0, 0,    0, 0, 0,   0, 0, 0, 1, 0 },
	{ "interface_sta_mode",      1, 0,0, 0,1,0, 0,     0, 0, 0,   0, 0, 0, 1, 0 },
	{ "station_not_found",       0, 0,0, 0,0,1, 0,     0, 0, 0,   0, 0, 0, 1, 0 },
	/* ---- plain request, flags ---- */
	{ "no_flags_token_0",        0, 0,0, 0,0,0, 0,     0, 0, 0,   0, 0, 0, 7, 0 },
	{ "no_flags_token_9",        1, 0,0, 0,0,0, 0,     0, 0, 0,   0, 9, 0, 7, 0 },
	{ "send_returns_0",          0, 0,0, 0,0,0, 0,     0, 0, 0,   0, 0, 0, 0, 0 },
	{ "send_fails",              0, 0,0, 0,0,0, 0,     0, 0, 0,   0, 4, 0,-1, 0 },
	{ "other_mode_bits_0x06",    0, 0,0, 0,0,0, 0x06,  0, 0, 0,   0, 3, 0, 2, 0 },
	{ "other_mode_bits_0xFF",    0, 0,0, 0,0,0, 0xFF,  5, 3, 20,  0, 3, 0, 2, 0 },
	/* ---- termination ---- */
	{ "termination_with_duration", 0, 0,0, 0,0,0, TD,  7, 0, 0,   0, 1, 0, 1, 0 },
	{ "termination_duration_0_dropped", 0, 0,0, 0,0,0, TD, 0, 0, 0, 0, 1, 0, 1, 0 },
	/* ---- candidates ---- */
	{ "candidates_1",            0, 0,0, 0,0,0, PC,    0, 1, 0,   0, 1, 0, 1, 0 },
	{ "candidates_5",            0, 0,0, 0,0,0, PC,    0, 5, 0,   0, 0, 0, 3, 0 },
	{ "candidates_63",           2, 0,0, 0,0,0, PC,    0, 63, 0,  0, 1, 0, 1, 0 },
	{ "candidates_0_flag_dropped", 0, 0,0, 0,0,0, PC,  0, 0, 0,   0, 1, 0, 1, 0 },
	{ "candidates_64_rejected",  0, 0,0, 0,0,0, PC,    0, 64, 0,  0, 1, 0, 1, 0 },
	{ "candidates_255_rejected", 0, 0,0, 0,0,0, PC,    0, 255, 0, 0, 1, 0, 1, 0 },
	{ "candidates_flag_off_ignored", 0, 0,0, 0,0,0, 0, 0, 200, 0, 0, 1, 0, 1, 0 },
	{ "candidates_malloc_fails", 0, 0,0, 0,0,0, PC,    0, 3, 0,   0, 1, 1, 1, 0 },
	/* ---- URL ---- */
	{ "url_100",                 0, 0,0, 0,0,0, ES,    0, 0, 100, 0, 1, 0, 1, 0 },
	{ "url_1",                   0, 0,0, 0,0,0, ES,    0, 0, 1,   0, 1, 0, 1, 0 },
	{ "url_511",                 0, 0,0, 0,0,0, ES,    0, 0, 511, 0, 1, 0, 1, 0 },
	{ "url_512_buffer_filled_to_511", 0, 0,0, 0,0,0, ES, 0, 0, 512, 0, 1, 0, 1, 0 },
	{ "url_len_0_flag_dropped",  0, 0,0, 0,0,0, ES,    0, 0, 0,   0, 1, 0, 1, 0 },
	{ "url_first_char_nul_flag_dropped", 0, 0,0, 0,0,0, ES, 0, 0, 30, 1, 1, 0, 1, 0 },
	{ "url_flag_off_with_url",   0, 0,0, 0,0,0, 0,     0, 0, 100, 0, 1, 0, 1, 0 },
	{ "url_malloc_fails",        0, 0,0, 0,0,0, ES,    0, 0, 50,  0, 1, 1, 1, 0 },
	/* ---- combinations ---- */
	{ "all_three_flags",         0, 0,0, 0,0,0, PC|TD|ES, 9, 4, 40, 0, 0, 0, 6, 0 },
	{ "all_flags_url_malloc_fails_second", 0, 0,0, 0,0,0, PC|TD|ES, 9, 4, 40, 0, 2, 2, 6, 0 },
	{ "all_flags_candidates_malloc_fails", 1, 0,0, 0,0,0, PC|TD|ES, 9, 4, 40, 0, 2, 1, 6, 0 },
	{ "candidates_rejected_url_not_copied", 0, 0,0, 0,0,0, PC|ES, 0, 64, 40, 0, 2, 0, 6, 0 },
	/* ---- the original dereferences request before the NULL check and trusts urlLen ---- */
	{ "request_null",            0, 0,1, 0,0,0, 0,     0, 0, 0,   0, 0, 0, 1, 1 },
	{ "request_null_peer_null",  0, 1,1, 0,0,0, 0,     0, 0, 0,   0, 0, 0, 1, 1 },
	{ "url_len_20000_unterminated", 0, 0,0, 0,0,0, ES, 0, 0, 20000, 2, 1, 0, 1, 1 },
	{ "url_len_65535_unterminated", 0, 0,0, 0,0,0, ES, 0, 0, 65535, 2, 1, 0, 1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
