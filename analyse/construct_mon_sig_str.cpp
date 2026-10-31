/*
 * TEST CASES / CONSTRUCTOR: construct_mon_sig_str
 *
 * mon_sig_str(signum, sigstr, sigstr_sz) writes into the CALLER buffer
 * sigstr (bounded by sigstr_sz) and, for signals not in its switch, formats
 * the number into a local sig_default[16]. Cases stress both:
 *   - known signals with ample room
 *   - unknown signals (realtime, and deliberately huge/min int values) to
 *     push the longest possible decimal into sig_default[16]
 *   - tiny output sizes (1/4/8) to exercise snprintf truncation into sigstr
 *
 * signum is just an int parameter, so we can pass values that are not real
 * signals to probe the formatting paths.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int         mss_signum;        /* signum passed to mon_sig_str()         */
size_t      mss_size;          /* sigstr_sz passed to mon_sig_str()      */
const char *mss_case_name;

mon_sig_str_test_case_t mon_sig_str_suite[] = {
    /* name                    signum         sigstr_sz */
    { "known_SIGTERM",         SIGTERM,        64 },
    { "known_SIGKILL",         SIGKILL,        64 },
    { "known_SIGSEGV",         SIGSEGV,        64 },
    { "unknown_realtime_37",   37,             64 },   /* -> sig_default "37"          */
    { "unknown_big_int",       999999999,      64 },   /* -> sig_default "999999999"   */
    { "unknown_int_min",       (-2147483647-1),64 },   /* -> sig_default "-2147483648" (11 chars) */
    { "tiny_out_1",            SIGTERM,        1  },    /* snprintf writes only the NUL */
    { "tiny_out_4",            SIGTERM,        4  },
    { "tiny_out_8",            SIGTERM,        8  },
    { "exact_fit",             SIGINT,         20 },

    { NULL, 0, 0 }  /* sentinel */
};

void construct_mon_sig_str_input(const mon_sig_str_test_case_t *tc)
{
    mss_case_name = tc->test_name;
    mss_signum    = tc->signum;
    mss_size      = tc->sigstr_sz;
}
