/*
 * HANDLER: wifi_hal_hostApGetErouter0Mac (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:682-689 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * A NULL out is rejected with RETURN_ERR; otherwise the constant string "01:23:12:44:65:ab" (17 characters + NUL = 18 bytes) is strcpy'd into out and RETURN_OK is returned.  The
 * API has no size argument, so out must hold 18 bytes (a mac_addr_str_t).  No caller exists in this tree (wifi_hal_priv.h:919 declares it only).
 *
 * DESIGN NOTE (not counted): the MAC is a hard-coded constant, not the erouter0 interface's address, so the function reports the same fake MAC on every device.
 *
 * Scaffolding only (none needed): the function calls nothing.  Renamed hwr_sg_wifi_hal_hostApGetErouter0Mac.
 */
#include "hwr_wem.h"
#include <string.h>

#define INT int
#define RETURN_OK 0
#define RETURN_ERR -1
#define wifi_hal_hostApGetErouter0Mac hwr_sg_wifi_hal_hostApGetErouter0Mac

extern "C" {
/* --- wifi_hal.c:682-689 --- */
INT wifi_hal_hostApGetErouter0Mac(char *out)
{
    if (out == NULL) {
        return RETURN_ERR;
    }
    strcpy(out, "01:23:12:44:65:ab");
    return RETURN_OK;
}
}
