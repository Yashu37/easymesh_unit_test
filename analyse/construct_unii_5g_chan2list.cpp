/*
 * TEST CASES / CONSTRUCTOR: construct_unii_5g_chan2list
 *
 * unii_5g_chan2list(chan, width) looks up a channel within a width's
 * sub-list in the static table. Cases cover valid 20/40/80/160 MHz
 * lookups, a channel not in a width's list, an invalid width, and -- the
 * suspected OOB -- width == 0, which matches the 0 just before the table's
 * terminating -1 and pushes the inner scan past the end of the array.
 *
 * Inputs are two ints; there is no buffer to poison here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int         unii_chan;
int         unii_width;
const char *unii_case_name;

unii_test_case_t unii_suite[] = {
    /* name                 chan   width   expect (1=non-NULL, 0=NULL, -1=suspected crash) */
    { "w20_ch36",           36,    20,      1 },
    { "w40_ch149",          149,   40,      1 },
    { "w80_ch161",          161,   80,      1 },
    { "w160_ch100",         100,   160,     1 },
    { "w20_ch37_notfound",  37,    20,      0 },
    { "invalid_width_999",  36,    999,     0 },
    /* suspected OOB read past the table's -1 terminator (width == 0) LAST */
    { "width_zero_oob",     1,     0,      -1 },

    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_unii_5g_chan2list_input(const unii_test_case_t *tc)
{
    unii_case_name = tc->test_name;
    unii_chan  = tc->chan;
    unii_width = tc->width;
}
