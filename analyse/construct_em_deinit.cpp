/*
 * TEST CASES / CONSTRUCTOR: construct_em_deinit
 *
 * The client-type map is a small local store (built via edi_store_build with N
 * malloc'd entries); the pending-blocks list is kept empty. The wifi_ctrl
 * stand-in is at edi_ctrl_buf.
 *
 * Cases: empty_map (0 entries -> map destroyed, no frees), three_entries
 * (3 entries -> each to_mac_str'd, removed and freed).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char edi_ctrl_buf[sizeof(wifi_ctrl_t) + EDI_PAD];
int edi_destroy_calls;

em_edi_test_case_t em_deinit_suite[] = {
    /* name           num_entries want_ret */
    { "empty_map",      0,         0 },
    { "three_entries",  3,         0 },
    { NULL, 0, 0 }  /* sentinel */
};

void construct_em_deinit_input(const em_edi_test_case_t *tc)
{
    memset(edi_ctrl_buf, 0, sizeof(edi_ctrl_buf));
    edi_destroy_calls = 0;
    edi_store_build(tc->num_entries);
}
