/* hwr_ncp.h - plumbing for the nvram_get_current_password harness (platform/banana-pi) */
#ifndef HWR_NCP_H
#define HWR_NCP_H
#include "hwr_defs.h"
extern "C" int hwr_nvram_get_current_password(char *l_password, int vap_index);
extern "C" int hwr_ncp_nvram(char *in, char *out);
typedef struct { int ret[2]; const char *val[2]; int calls; char key[32]; } hwr_ncp_rec_t;
extern hwr_ncp_rec_t hwr_ncp_rec;
typedef struct {
	const char *test_name;
	int vap_index;
	int nvram_ret; const char *nvram_val;          /* first call */
	int nvram_ret2; const char *nvram_val2;        /* second call (calls == 2) */
	int prefill;                                   /* 0 zeros, 1 0xA5, 2 "old" + zeros: what the caller's key buffer holds before the call */
	int null_pw;
	int calls;
	int expected_ret;
	const char *expected_pw;                       /* NULL = buffer untouched */
	int forked;
} hwr_ncp_case_t;
extern hwr_ncp_case_t nvram_get_current_password_suite[];
extern "C" void run_all_tests_nvram_get_current_password(void);
#endif
