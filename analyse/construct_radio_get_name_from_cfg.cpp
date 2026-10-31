/*
 * TEST CASES / CONSTRUCTOR: construct_radio_get_name_from_cfg
 *
 * radio_get_name_from_cfg(cfg) formats "<type> <phy_name>". Cases cover
 * each radio type, an unknown type (helper returns NULL -> "(null) ..."),
 * a NULL cfg, and a phy_name that fills its whole field. The radio_entry_t
 * lives in a runner-owned backing buffer so the runner can poison the
 * phy_name tail and the memory past the struct.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* backing buffer so the runner can poison past the struct */
unsigned char rgn_backing[sizeof(radio_entry_t) + 64];
size_t        rgn_phy_len;      /* content length of phy_name (for poisoning) */
int           rgn_null_cfg;     /* pass cfg = NULL */
const char   *rgn_case_name;

radio_name_test_case_t radio_name_suite[] = {
    /* name            type              phy_name       null_cfg  expect_nonnull */
    { "type_2g",       RADIO_TYPE_2G,    "wlan0",        0, 1 },
    { "type_5g",       RADIO_TYPE_5G,    "wlan1",        0, 1 },
    { "type_6g",       RADIO_TYPE_6G,    "wlan2",        0, 1 },
    { "type_none",     RADIO_TYPE_NONE,  "wlan3",        0, 1 },   /* helper returns NULL -> "(null) wlan3" */
    { "phy_full_31",   RADIO_TYPE_5G,    "0123456789012345678901234567890", 0, 1 }, /* 31 chars fills field */
    { "null_cfg",      RADIO_TYPE_2G,    "x",            1, 0 },

    { NULL, RADIO_TYPE_NONE, NULL, 0, 0 }  /* sentinel */
};

void construct_radio_name_input(const radio_name_test_case_t *tc)
{
    rgn_case_name = tc->test_name;
    rgn_null_cfg  = tc->null_cfg;

    memset(rgn_backing, 0, sizeof(rgn_backing));
    radio_entry_t *cfg = (radio_entry_t *)rgn_backing;
    cfg->type = tc->type;

    size_t n = strlen(tc->phy_name);
    if (n >= RADIO_NAME_LEN) n = RADIO_NAME_LEN - 1;
    memcpy(cfg->phy_name, tc->phy_name, n);
    cfg->phy_name[n] = '\0';
    rgn_phy_len = n;
}
