/* hwr_nvr.h - types / plumbing for the wifi_nvram_defaultRead harness (platform/banana-pi) */
#ifndef HWR_NVR_H
#define HWR_NVR_H
#include "hwr_defs.h"
#include <stdio.h>
extern char hwr_nvr_path[256];                                  /* temporary copy of /nvram/wifi_defaults.txt, set by the runner */
extern "C" int hwr_nvr_real_syscmd(char *cmd, char *retBuf, int retBufSize);   /* _syscmd, verbatim */
extern "C" int hwr_nvr_syscmd(char *cmd, char *retBuf, int retBufSize);        /* rewrites the file path, then runs the real one */
extern "C" FILE *hwr_nvr_fopen(const char *path, const char *mode);
extern "C" int hwr_nvr_call(char *in, char *out, size_t out_size);             /* trampoline: 2 or 3 arguments, see the handler */

typedef struct {
	const char *test_name;
	const char *file;              /* content of /nvram/wifi_defaults.txt, NULL = the file does not exist */
	const char *key;               /* the key `in`; "%M" is replaced by the marker file path; NULL = NULL pointer */
	int null_out;                  /* out passed as NULL */
	unsigned cap;                  /* size of the caller's output buffer (the runner poisons everything behind it) */
	int expected_ret;
	const char *expected_out;      /* NULL = out must stay untouched */
	int marker_forbidden;          /* 1: the marker file must not exist afterwards (no injected command ran) */
	int forked;
} hwr_nvr_case_t;
extern hwr_nvr_case_t wifi_nvram_defaultRead_suite[];
extern "C" void run_all_tests_wifi_nvram_defaultRead(void);
#endif
