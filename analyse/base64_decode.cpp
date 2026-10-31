/*
 * HANDLER: base64_decode
 *
 * Function copied VERBATIM from OneWifi lib/common/util.c
 * (OneWifi develop @ 3ad202e). No fixes, no edits. The harness only
 * observes whether the function, as shipped, crashes under ASan on an
 * out-of-bounds array access (index below 0 / at or above array size).
 *
 * base64_table is the verbatim declaration: a char[64] initialised with a
 * 64-character string literal, so the array is full and has NO '\0'
 * terminator -- which is the whole point of the test.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/common/util.c:269 --- */
static char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* --- copied verbatim from lib/common/util.c:336 --- */
ssize_t base64_decode(void *out, ssize_t out_sz, char *input)
{
    int ii;
    ssize_t input_sz = (ssize_t)strlen(input);

    if (input_sz == 0) return 0;
    if ((input_sz % 4) != 0) return -1;

    /* Clip ending '=' characters */
    for (ii = 0; ii < 2; ii++) if (input[input_sz - 1] == '=') input_sz -= 1;

    /* Check output length */
    if (((input_sz >> 2) * 3 + (((input_sz & 3) * 3) >> 2)) > out_sz) return -1;

    /* Calculate total output size */
    char *pin = input;
    uint8_t *pout = (uint8_t *)out;

    while (input_sz > 0)
    {
        uint8_t m[4] = {0};

        /* Calculate number of bytes to process this round */
        int isz = (int)((input_sz > 4) ? 4 : input_sz);

        /* Translate a single character to it's base64 value according to base64_table */
        for (ii = 0; ii < isz; ii++)
        {
            char *p = strchr(base64_table, pin[ii]);

            /* Invalid character found -- error*/
            if (p == NULL) return -1;

            m[ii] = (uint8_t)(p - base64_table);
        }

        /* Process a 4-byte (or less) block */
        switch (isz)
        {
            default:
                pout[2] = (uint8_t)((m[2] << 6) | m[3]);
                /* Falls through. */
            case 3:
                pout[1] = (uint8_t)((m[1] << 4) | (m[2] >> 2));
                /* Falls through. */
            case 2:
                pout[0] = (uint8_t)((m[0] << 2) | (m[1] >> 4));
                /* Falls through. */
        }

        pout += isz - 1;
        input_sz -= 4;
        pin += 4;
    }

    return pout - (uint8_t *)out;
}
