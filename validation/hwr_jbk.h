/* hwr_jbk.h - plumbing for the json_parse_backhaul_keypassphrase harness (platform/banana-pi) */
#ifndef HWR_JBK_H
#define HWR_JBK_H
#include "hwr_defs.h"
#include <stdio.h>
extern char hwr_jbk_path[256];                                   /* temporary copy of /nvram/EasymeshCfg.json, set by the runner */
extern "C" FILE *hwr_jbk_fopen(const char *path, const char *mode);
extern "C" int hwr_jbk_call(char *out);                          /* trampoline to the static function */

typedef struct {
	const char *test_name;
	const char *file;              /* content of the json file, NULL = file does not exist */
	unsigned file_len;             /* 0 = strlen(file); else exact length (file may be padded, see pad) */
	int null_out;                  /* out passed as NULL */
	int expected_ret;
	const char *expected_out;      /* NULL = out must stay untouched; "%128" etc: see runner (long strings built there) */
	int long_len;                  /* >0: the value of Backhaul_KeyPassphrase is built by the runner with this many chars */
	int forked;
} hwr_jbk_case_t;
extern hwr_jbk_case_t json_parse_backhaul_keypassphrase_suite[];
extern "C" void run_all_tests_json_parse_backhaul_keypassphrase(void);
#endif
