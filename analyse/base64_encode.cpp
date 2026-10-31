/*
 * HANDLER: base64_encode
 *
 * Function copied VERBATIM from OneWifi lib/common/util.c
 * (OneWifi develop @ 3ad202e). No fixes, no edits. The harness only
 * observes whether the function, as shipped, crashes under ASan on an
 * out-of-bounds array access (index below 0 / at or above array size),
 * for the output buffer, the input buffer and the local m[4] array.
 *
 * base64_table is the verbatim declaration. base64_encode only indexes it
 * with (value & 63), i.e. 0..63, and never calls strchr on it.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/common/util.c:269 --- */
static char base64_enc_table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define base64_table base64_enc_table

/* --- copied verbatim from lib/common/util.c:279 --- */
ssize_t base64_encode(char *out, ssize_t out_sz, void *input, ssize_t input_sz)
{
    uint8_t *pin = (uint8_t *)input;
    char *pout = out;
    uint8_t m[4];

    if ((((input_sz + 2) / 3) * 4) >= out_sz) return -1;

    while (input_sz > 0)
    {
        m[0] = m[1] = m[2] = m[3] = 0;
        /* pout[0] and pout[1] are never '=' */
        pout[2] = pout[3] = '=';

        switch (input_sz)
        {
            default:
                m[3] = pin[2];
                m[2] = pin[2] >> 6;

                pout[3] = base64_table[m[3] & 63];
                /* Falls through. */

            case 2:
                m[2] |= (uint8_t)(pin[1] << 2);
                m[1] |= pin[1] >> 4;
                pout[2] = base64_table[m[2] & 63];
                /* Falls through. */

            case 1:
                m[1] |= (uint8_t)(pin[0] << 4);
                m[0] |= pin[0] >> 2;

                pout[1] = base64_table[m[1] & 63];
                pout[0] = base64_table[m[0] & 63];
                /* Falls through. */
        }

        pout += 4;
        pin += 3;
        input_sz -= 3;
    }

    *pout++ = '\0';

    return pout - out;
}

#undef base64_table
