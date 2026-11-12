/*
 * HANDLER: wifi_authenticator_run (src/wifi_hal_hostapd.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_hostapd.c:82-85 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It runs hostapd's event loop: eloop_run() and returns
 * when the loop returns.
 *
 * Scaffolding only: eloop_run is a recording stub (macro below); renamed hwr_sg_wifi_authenticator_run.
 */
#include "hwr_war.h"

hwr_war_world_t hwr_war_world;

static void hwr_war_eloop_run(void)
{
	hwr_war_world_t *w = &hwr_war_world;

	w->eloop_calls++;
	w->in_loop = 1;
	for (int i = 0; i < w->eloop_iterations; i++) { /* the loop body of hostapd: nothing to record */ }
	w->in_loop = 0;
}
#define eloop_run hwr_war_eloop_run
#define wifi_authenticator_run hwr_sg_wifi_authenticator_run

extern "C" {
/* --- wifi_hal_hostapd.c:82-85 --- */
void wifi_authenticator_run()
{
    eloop_run();
}
}
