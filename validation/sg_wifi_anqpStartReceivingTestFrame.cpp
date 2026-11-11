/*
 * HANDLER: wifi_anqpStartReceivingTestFrame (src/wifi_hal_anqp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_anqp.c:813-818 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It starts the ANQP test-frame receive thread: one
 * pthread_create(&frame_recv_tid, NULL, wifi_anqpTestFrameHandler, NULL) with a local thread id; the result is not checked and the thread is never joined or detached.
 *
 * Scaffolding only: pthread_create is a recording stub (macro below), wifi_anqpTestFrameHandler a stand-in start routine; renamed hwr_sg_wifi_anqpStartReceivingTestFrame.
 */
#include "hwr_wsf.h"
#include <string.h>

hwr_wsf_world_t hwr_wsf_world;
extern "C" void *wifi_anqpTestFrameHandler(void *arg) { return arg; }
static int hwr_wsf_pthread_create(pthread_t *tid, const pthread_attr_t *attr, void *(*routine)(void *), void *arg)
{
	hwr_wsf_world_t *w = &hwr_wsf_world;
	int n = w->create_calls++, r = n < HWR_WSF_MAXC ? w->script[n] : 0;
	if (n < HWR_WSF_MAXC) { w->tid_ptr[n] = tid; w->attr[n] = attr; w->routine[n] = routine; w->arg[n] = arg; }
	if (r == 0) *tid = (pthread_t)(0x1000 + n);
	return r;
}
#define pthread_create hwr_wsf_pthread_create
#define wifi_anqpStartReceivingTestFrame hwr_sg_wifi_anqpStartReceivingTestFrame

extern "C" {
/* --- wifi_hal_anqp.c:813-818 --- */
void wifi_anqpStartReceivingTestFrame()
{
    pthread_t frame_recv_tid;

    pthread_create(&frame_recv_tid, NULL, wifi_anqpTestFrameHandler, NULL);
}
}
