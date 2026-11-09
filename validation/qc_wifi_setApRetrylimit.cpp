/*
 * HANDLER: wifi_setApRetrylimit (platform/qualcomm)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/qualcomm/platform_ext.c:1049-1067 (platform_xer5.c:1328-1346 holds identical code) (~/Desktop/G/rdk-wifi-hal).
 * This file holds the ORIGINAL code: no fix is applied.  The function returns RETURN_ERR for priv == NULL, otherwise it reads interface->vap_info.vap_index,
 * calls wifi_setApRetryLimit(vap_index, RETRY_LIMIT = 7), logs a debug line when that call fails and returns 0 either way.
 *
 * DESIGN NOTES (not counted): (1) a failing wifi_setApRetryLimit is only logged (without a trailing newline) and the function still returns 0, so the caller
 * (src/wifi_hal_nl80211.c:8593, which tests != RETURN_OK) never sees the failure; (2) priv is only checked for NULL (it is the interface pointer hostap passes
 * in, an invalid non-NULL pointer is not a caller contract case).
 *
 * Scaffolding only: wifi_interface_info_t is qrl_iface_t (real wifi_vap_info_t member); wifi_setApRetryLimit (hal-interface function, not in this tree) is a
 * recording stub; RETRY_LIMIT is the file's own define; the print macros map to the log sink hwr_print (runner-poisoned slot).  Renamed
 * hwr_qc_wifi_setApRetrylimit because the other platforms define the same name.
 */
#include "hwr_qrl.h"
#include <string.h>

#define RETRY_LIMIT 7
#define RETURN_OK 0
#define wifi_interface_info_t qrl_iface_t
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_setApRetrylimit hwr_qc_wifi_setApRetrylimit

hwr_qrl_world_t hwr_qrl_world;

static INT wifi_setApRetryLimit(INT apIndex, UINT number)
{
	hwr_qrl_world.calls++; hwr_qrl_world.last_ap = apIndex; hwr_qrl_world.last_limit = number;
	return hwr_qrl_world.ret;
}

/* --- platform_ext.c:1049-1067 --- */
extern "C" {
int wifi_setApRetrylimit(void *priv)
{
    if (priv == NULL) {
        wifi_hal_error_print("%s:%d:error couldn't find primary interface\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_interface_info_t *interface = (wifi_interface_info_t *) priv;
    wifi_vap_index_t retry_vap_index = interface->vap_info.vap_index;
    int res = -1;

    res = wifi_setApRetryLimit(retry_vap_index, RETRY_LIMIT);

    if (res) {
        wifi_hal_dbg_print("%s:%d: AP_RETRY_LIMIT failed:%d", __func__, __LINE__, res);
    }

    return 0;
}
}
