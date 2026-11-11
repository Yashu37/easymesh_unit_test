/*
 * UNIT TEST (input constructor): construct_sg_wifi_anqpStartReceivingTestFrame
 *
 * wifi_anqpStartReceivingTestFrame() takes no argument.  Inputs crossed: 1-5 consecutive calls and the result of each pthread_create (success, EAGAIN, ENOMEM, EPERM).  Expected (CORRECT behaviour): every
 * call issues exactly one pthread_create with a non-NULL thread-id pointer, default attributes (NULL), wifi_anqpTestFrameHandler as the start routine and a NULL argument, whatever the result;
 * nothing else is touched.  No crash case is expected.
 */
#include "hwr_wsf.h"
#include <errno.h>

/* name, calls, {result per call}, last */
hwr_wsf_case_t sg_wifi_anqpStartReceivingTestFrame_suite[] = {
	{ "single_call_succeeds",          1, { 0 }, 0 },
	{ "single_call_eagain",            1, { EAGAIN }, 0 },
	{ "single_call_enomem",            1, { ENOMEM }, 0 },
	{ "single_call_eperm",             1, { EPERM }, 0 },
	{ "two_calls_succeed",             2, { 0, 0 }, 0 },
	{ "two_calls_both_fail",           2, { EAGAIN, EAGAIN }, 0 },
	{ "success_then_failure",          2, { 0, EAGAIN }, 0 },
	{ "failure_then_success",          2, { EAGAIN, 0 }, 0 },
	{ "three_calls_mixed",             3, { 0, ENOMEM, 0 }, 0 },
	{ "five_calls_succeed",            5, { 0, 0, 0, 0, 0 }, 0 },
	{ "five_calls_fail",               5, { EAGAIN, EAGAIN, EAGAIN, EAGAIN, EAGAIN }, 0 },
	{ NULL }
};
