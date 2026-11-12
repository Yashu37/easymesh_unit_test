/*
 * HANDLER: wifi_dppCancel (src/wifi_hal_dpp.c)
 *
 * Function copied (verbatim apart from the marked fixes) from rdk-wifi-hal: src/wifi_hal_dpp.c:3144-3150 (~/Desktop/G/rdk-wifi-hal).  This file holds the code WITH fixes 1-3 (start fix n / end fix n markers; the unfixed copy is the reproducer).  It cancels the DPP session of a context: it calls
 * delete_dpp_session_instance, which frees the session instance (N, M, responder protocol point, the reconfig responder connector, the initiator protocol key, bn context, prime, n, m, y, x and the instance
 * itself), sets session_data.instance = NULL, and returns RETURN_OK.
 *
 * Scaffolding only: OpenSSL is the real library; the callee delete_dpp_session_instance (wifi_hal_dpp.c:1585-1643) is verbatim support code; wifi_hal_dpp.c redirects printf to wifi_dpp_dbg_print, here that goes
 * to a no-op sink; renamed hwr_sg_wifi_dppCancel.
 */
#include "hwr_wdk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RETURN_OK 0
#define RETURN_ERR -1
static void wifi_dpp_dbg_print(const char *format, ...) { }
#define printf wifi_dpp_dbg_print
#define wifi_dppCancel hwr_sg_wifi_dppCancel
/* the support-code callee is renamed hwr_wdk_<name> so it does not clash with the copies of other harnesses */
#define delete_dpp_session_instance hwr_wdk_delete_dpp_session_instance

extern "C" {
/* --- wifi_hal_dpp.c:1585-1643 (verbatim, support code: delete_dpp_session_instance) --- */
void delete_dpp_session_instance(wifi_device_dpp_context_t *ctx)
{
    wifi_dpp_session_data_t    *data = NULL;
    wifi_dpp_instance_t *instance;

    /* ---------- start fix 1: a NULL context was dereferenced (ctx->session_data). */
    if (ctx == NULL) {
        return;
    }
    /* ---------- end fix 1 */

    wifi_dpp_dbg_print("%s:%d Here\n", __func__, __LINE__);

    data = &ctx->session_data;
	instance = data->instance;

    /* ---------- start fix 2: no session instance (never created, or already cancelled): nothing to free; a second cancel crashed on instance->N. */
    if (instance == NULL) {
        return;
    }
    /* ---------- end fix 2 */

    if (instance->N != NULL) {
        EC_POINT_free(instance->N);
    }

    if (instance->M != NULL) {
        EC_POINT_free(instance->M);
    }
    
    if (instance->responder_proto_pt != NULL) {
        EC_POINT_clear_free(instance->responder_proto_pt);
    }

    if (data->session == wifi_dpp_session_type_reconfig) {
        if (instance->responder_connector != NULL) {
            EC_POINT_free(instance->responder_connector);
        }
    }

    if (instance->initiator_proto_key != NULL) {
        EC_KEY_free(instance->initiator_proto_key);
    }

    if (instance->bnctx != NULL) {
        BN_CTX_free(instance->bnctx);
    }

    if (instance->prime != NULL) {
        BN_free(instance->prime);
    }
    
    if (instance->n != NULL) {
        BN_free(instance->n);
    }
    
    if (instance->m != NULL) {
        BN_free(instance->m);
    }
    
    if (instance->y != NULL) {
        BN_free(instance->y);
    }
    
    if (instance->x != NULL) {
        BN_free(instance->x);
    }

	free(instance);
	data->instance = NULL;
}

/* --- wifi_hal_dpp.c:3144-3150 --- */
int 
wifi_dppCancel(wifi_device_dpp_context_t *ctx)
{
    /* ---------- start fix 3: a NULL context is an error (and is not passed on). */
    if (ctx == NULL) {
        return RETURN_ERR;
    }
    /* ---------- end fix 3 */

	delete_dpp_session_instance(ctx);

    return RETURN_OK;
}
}
