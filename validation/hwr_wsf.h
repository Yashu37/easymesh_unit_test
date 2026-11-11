/* hwr_wsf.h - plumbing for the sg_wifi_anqpStartReceivingTestFrame harness (src/wifi_hal_anqp.c).
 * pthread_create is a recording stub (macro in the handler file): it stores the thread-id pointer, attribute, start routine and argument it got and returns the runner-scripted result (writing a thread id on
 * success); wifi_anqpTestFrameHandler is a stand-in start routine with the real signature void *(void *). */
#ifndef HWR_WSF_H
#define HWR_WSF_H
#include "hwr_defs.h"
#include <pthread.h>
#define HWR_WSF_MAXC 6
typedef struct {
	int create_calls;
	pthread_t *tid_ptr[HWR_WSF_MAXC]; const pthread_attr_t *attr[HWR_WSF_MAXC]; void *(*routine[HWR_WSF_MAXC])(void *); void *arg[HWR_WSF_MAXC];
	int script[HWR_WSF_MAXC];                  /* result of the n-th pthread_create call (0 ok, else an errno value) */
	void *unrelated[4];                        /* poisoned: the function must not touch it */
} hwr_wsf_world_t;
extern hwr_wsf_world_t hwr_wsf_world;
extern "C" void *wifi_anqpTestFrameHandler(void *arg);
extern "C" void hwr_sg_wifi_anqpStartReceivingTestFrame(void);
typedef struct {
	const char *test_name;
	int calls;                     /* number of consecutive calls (1-5) */
	int script[5];                 /* pthread_create result for each call */
	int last;                      /* 1: input that crashes the original, run LAST */
} hwr_wsf_case_t;
extern hwr_wsf_case_t sg_wifi_anqpStartReceivingTestFrame_suite[];
extern "C" void run_all_tests_sg_wifi_anqpStartReceivingTestFrame(void);
#endif
