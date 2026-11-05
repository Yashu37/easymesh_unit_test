/* hwr_ppo.h - plumbing for the platform_post_init harness (platform/banana-pi) */
#ifndef HWR_PPO_H
#define HWR_PPO_H
#include "hwr_defs.h"
extern "C" int hwr_platform_post_init(wifi_vap_info_map_t *vap_map);
extern "C" int hwr_ppo_system(const char *cmd);
typedef struct {
	int n;                         /* system() calls seen */
	char cmd[8][64];               /* the commands, in order */
	unsigned fail_mask;            /* bit i: the i-th system() call (0-based, over all calls) fails */
	int fail_status;               /* value system() returns for a failing call (-1, 256 = exit 1, 32512 = 127) */
} hwr_ppo_rec_t;
extern hwr_ppo_rec_t hwr_ppo_rec;
typedef struct {
	const char *test_name;
	unsigned fail_mask;            /* per system() call, see above */
	int fail_status;
	int map_null;                  /* 1: vap_map == NULL, 0: pointer to a runner slab that is fully poisoned (must not be touched) */
	int calls;
	int expected_ret;              /* of the last call: 0, or -1 when any brctl of that call failed */
	int expect_log_fail;           /* number of "failed" lines expected in the log after all calls */
} hwr_ppo_case_t;
extern hwr_ppo_case_t platform_post_init_suite[];
extern "C" void run_all_tests_platform_post_init(void);
#endif
