/* hwr_pgk.h - plumbing for the platform_get_keypassphrase_default harness (platform/banana-pi) */
#ifndef HWR_PGK_H
#define HWR_PGK_H
#include "hwr_defs.h"
extern "C" int hwr_platform_get_keypassphrase_default(char *password, int vap_index);
extern "C" BOOL hwr_pgk_is_mesh_sta(UINT ap_index);
extern "C" int hwr_pgk_json(char *out);
extern "C" int hwr_pgk_nvram(char *in, char *out);
typedef struct {
	int mesh_sta_index;            /* the vap_index for which is_wifi_hal_vap_mesh_sta() is true, -2 = none */
	int json_ret, nvram_ret;       /* results of the stubs (0 = ok) */
	const char *json_val, *nvram_val;
	int json_calls, nvram_calls, mesh_calls;
	int last_vap_index;
} hwr_pgk_rec_t;
extern hwr_pgk_rec_t hwr_pgk_rec;
typedef struct {
	const char *test_name;
	int vap_index;
	int mesh_sta_index;
	int json_ret; const char *json_val;
	int nvram_ret; const char *nvram_val;
	int prefill;                   /* caller's buffer before the call: 0 = zeros, 1 = 0xA5 (no NUL: uninitialised), 2 = "junk" + NUL, 3 = zeros and cap is 64 (OneWifi wifi_dml_cb.c buffer) */
	int null_pw;
	int expected_ret;
	const char *expected_pw;       /* NULL = buffer untouched */
	int expected_json_calls, expected_nvram_calls;
	int expect_fallback_log;       /* the "enforced alternative default password" error line must be in the log */
	int forked;
} hwr_pgk_case_t;
extern hwr_pgk_case_t platform_get_keypassphrase_default_suite[];
extern "C" void run_all_tests_platform_get_keypassphrase_default(void);
#endif
