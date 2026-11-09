/* hwr_nvd.h - plumbing for the raspberry-pi / wifi-emulator wifi_nvram_defaultRead harness (platform/raspberry-pi, platform/wifi-emulator) */
#ifndef HWR_NVD_H
#define HWR_NVD_H
#include "hwr_defs.h"
extern "C" int hwr_rp_wifi_nvram_defaultRead(char *in, char *out);
typedef struct {
	int calls; char cmd[4200]; unsigned long cmd_len;
	const char *reply;             /* what the stubbed _syscmd writes into retBuf (NULL: nothing) */
	int ret;                       /* what the stubbed _syscmd returns */
} hwr_nvd_world_t;
extern hwr_nvd_world_t hwr_nvd_world;
typedef struct {
	const char *test_name;
	int key_len;                   /* >= 0: the key is key_len 'k' characters; -1: use key_text */
	const char *key_text;
	const char *reply;             /* canned _syscmd output (NULL = empty) */
	int syscmd_ret;
	int out_mode;                  /* 0 NULL, 1 exact-size slab (value + NUL): the bytes around it are POISONED during the call */
	int calls;
	int expected_ret;
	const char *expected_out;      /* expected output string when expected_ret == 0 */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_nvd_case_t;
extern hwr_nvd_case_t rp_wifi_nvram_defaultRead_suite[];
extern "C" void run_all_tests_rp_wifi_nvram_defaultRead(void);
#endif
