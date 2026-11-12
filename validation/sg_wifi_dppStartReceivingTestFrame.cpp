/*
 * HANDLER: wifi_dppStartReceivingTestFrame (src/wifi_hal_dpp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_dpp.c:3534-3539 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It starts the DPP test-frame receive thread: one
 * pthread_create(&frame_recv_tid, NULL, wifi_dppTestFrameHandler, NULL) with a local thread id; the result is not checked and the thread is never joined or detached.
 *
 * Scaffolding only: pthread_create is a recording stub (macro below), wifi_dppTestFrameHandler a stand-in start routine; renamed hwr_sg_wifi_dppStartReceivingTestFrame.
 */
#include "hwr_wtq.h"
#include <string.h>

hwr_wtq_world_t hwr_wtq_world;
extern "C" void *wifi_dppTestFrameHandler(void *arg) { return arg; }
static int hwr_wtq_pthread_create(pthread_t *tid, const pthread_attr_t *attr, void *(*routine)(void *), void *arg)
{
	hwr_wtq_world_t *w = &hwr_wtq_world;
	int n = w->create_calls++, r = n < HWR_WTQ_MAXC ? w->script[n] : 0;
	if (n < HWR_WTQ_MAXC) { w->tid_ptr[n] = tid; w->attr[n] = attr; w->routine[n] = routine; w->arg[n] = arg; }
	if (r == 0) *tid = (pthread_t)(0x1000 + n);
	return r;
}
#define pthread_create hwr_wtq_pthread_create
#define wifi_dppStartReceivingTestFrame hwr_sg_wifi_dppStartReceivingTestFrame

extern "C" {
/* --- wifi_hal_dpp.c:3534-3539 --- */
void wifi_dppStartReceivingTestFrame()
{
	pthread_t frame_recv_tid;

	pthread_create(&frame_recv_tid, NULL, wifi_dppTestFrameHandler, NULL);
}
}
