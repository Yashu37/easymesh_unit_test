/*
 * HANDLER: string_to_macbytes (fix 1 applied, start fix n / end fix n markers)
 *
 * Function copied verbatim from unified-wifi-mesh src/dm/dm_easy_mesh.cpp (develop @ 1ba9529),
 * dm_easy_mesh_t::string_to_macbytes. Local array: mac[6] (never initialised when sscanf matches fewer than 6 fields).
 * The function has no NULL checks and copies mac[] into bmac whatever sscanf returned.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "string_to_macbytes.h"

namespace stm {

/* --- copied verbatim from src/dm/dm_easy_mesh.cpp --- */
void dm_easy_mesh_t::string_to_macbytes(char *key, mac_address_t bmac)
{
    unsigned char mac[6];
/* start fix 1 */
    if (key == NULL || bmac == NULL) {
        return;
    }
/* end fix 1 */
    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
    bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

/* writes 0xAB over the stack below the caller so that an uninitialised mac[] of the handler holds a known garbage value */
__attribute__((noinline)) void dirty_stack(void)
{
    volatile unsigned char junk[2048];
    for (size_t i = 0; i < sizeof(junk); i++) junk[i] = 0xAB;
}

void invoke(const test_case_t *tc)
{
    dirty_stack();
    dm_easy_mesh_t::string_to_macbytes(tc->key_null ? NULL : key_store + STM_LEFT,
                                       tc->bmac_null ? NULL : (unsigned char *)(bmac_store + STM_GUARD));
}

} /* namespace stm */
