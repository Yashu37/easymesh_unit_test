/*
 * HANDLER: dpp_mac_str_tmp
 *
 * Function copied VERBATIM from OneWifi lib/datapipeline/dppline.c, together
 * with its helper dpp_mac_to_str (from the same lib, verbatim). No fixes.
 *
 * dpp_mac_str_tmp returns a static mac_address_str_t (char[18]); dpp_mac_to_str
 * reads mac[0..5] (6 bytes) and writes 17 chars + NUL = 18 bytes into str.
 * The harness watches the 6-byte mac read (caller-owned, poisoned by the
 * runner) and the write into the internal static str (auto-guarded by ASan).
 *
 * Scaffolding: MACADDR_STR_LEN + mac_address_str_t copied from dpp_types.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/datapipeline/dpp_types.h --- */
#define MACADDR_STR_LEN (12 + 5 + 1)
typedef char mac_address_str_t[MACADDR_STR_LEN];

/* --- copied verbatim from lib/datapipeline/dppline.c --- */
void dpp_mac_to_str(uint8_t *mac, char *str)
{
    int i;
    uint8_t nib;
    for (i=0; i<6; i++)
    {
        nib = *mac >> 4;
        *str++ = nib < 10 ? '0' + nib : 'A' + nib - 10;
        nib = *mac & 0xF;
        *str++ = nib < 10 ? '0' + nib : 'A' + nib - 10;
        if (i < 5) *str++ = ':';
        mac++;
    }
    *str = 0;
}

char* dpp_mac_str_tmp(uint8_t *mac)
{
    static mac_address_str_t str;
    dpp_mac_to_str(mac, str);
    return str;
}
