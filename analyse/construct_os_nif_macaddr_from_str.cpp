/*
 * TEST CASES / CONSTRUCTOR: construct_os_nif_macaddr_from_str
 *
 * os_nif_macaddr_from_str(&mac, str) splits str on ':'/'-' and stores up to
 * 6 hex bytes in mac->addr[6]. Cases: colon and dash forms, 5 and 7 bytes,
 * 20 bytes (many tokens), a byte of 256, an empty token, an empty string,
 * "-1" (negative), and a 200-char input (truncated to 63 by STRSCPY).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   onm_str[256];
size_t onm_str_len;

os_nif_macaddr_test_case_t os_nif_macaddr_from_str_suite[] = {
    /* name              str                                                     fill ret */
    { "colon_6",         "aa:bb:cc:dd:ee:ff",                                       0,  1 },
    { "dash_6",          "00-11-22-33-44-55",                                       0,  1 },
    { "five_bytes",      "aa:bb:cc:dd:ee",                                          0,  1 },  /* accepted (no min check) */
    { "seven_bytes",     "aa:bb:cc:dd:ee:ff:11",                                    0,  0 },
    { "twenty_bytes",    "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:10:11:12:13:14",            0,  0 },
    { "byte_256",        "aa:bb:cc:dd:ee:100",                                      0,  0 },
    { "empty_token",     "aa::cc:dd:ee:ff",                                         0,  0 },
    { "empty_string",    "",                                                        0,  0 },
    { "negative",        "-1",                                                      0,  0 },
    { "long_200",        NULL,                                                    200,  0 },  /* "a:" repeated */

    { NULL, NULL, 0, 0 }  /* sentinel */
};

void construct_os_nif_macaddr_from_str_input(const os_nif_macaddr_test_case_t *tc)
{
    memset(onm_str, 0, sizeof(onm_str));
    if (tc->fill > 0) {
        for (int i = 0; i < tc->fill && i < (int)sizeof(onm_str) - 1; i++)
            onm_str[i] = (i % 2) ? ':' : 'a';
    } else {
        snprintf(onm_str, sizeof(onm_str), "%s", tc->str);
    }
    onm_str_len = strlen(onm_str);
}
