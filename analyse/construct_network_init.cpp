/*
 * TEST CASES / CONSTRUCTOR: construct_network_init
 *
 * One dm_network_t per case on the heap between poisoned guards (runner); prefill fills every byte with 'Z' first (id, timestamp,
 * MACs, counts) so a member init() forgets to clear would show. TZ is set per case (UTC, Asia/Kolkata, America/Los_Angeles).
 * check 0: init() returns 0 and the timestamp is "YYYY-MM-DDTHH:MM:SSZ" (20 characters), 1: media is Ethernet (0x01),
 * 2: every member except timestamp / media is zero after a prefilled object, 3: the timestamp equals the current UTC time
 * (the 'Z' suffix means UTC), 4: a second init() gives the same result. [spec] cases: wrong behaviour, no abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network_init.h"

namespace nit {
/* {name, tz, prefill, check, crash} */
test_case_t suite[] = {
 {"ok_returns_zero_and_format_utc",        "UTC", false, 0, false},
 {"ok_format_kolkata",                     "Asia/Kolkata", false, 0, false},
 {"ok_format_los_angeles",                 "America/Los_Angeles", false, 0, false},
 {"ok_media_is_ethernet",                  "UTC", false, 1, false},
 {"ok_prefilled_object_is_cleared",        "UTC", true, 2, false},
 {"ok_prefilled_timestamp_replaced",       "UTC", true, 0, false},
 {"ok_second_call_same_result",            "UTC", false, 4, false},
 {"ok_utc_timestamp_matches_gmtime",       "UTC", false, 3, false},
 /* ---- [spec]: wrong behaviour, no abort ---- */
 {"spec_timestamp_z_suffix_must_be_utc_kolkata [spec]",     "Asia/Kolkata", false, 3, false},
 {"spec_timestamp_z_suffix_must_be_utc_los_angeles [spec]", "America/Los_Angeles", false, 3, false},
 {NULL, NULL, false, 0, false}
};

void construct_input(const test_case_t *tc)
{
    g_box = (box_t *)calloc(1, sizeof(box_t));
    if (tc->prefill) memset(&g_box->obj, 'Z', sizeof(g_box->obj));
    setenv("TZ", tc->tz, 1); tzset();
}
void teardown(void) { free(g_box); g_box = NULL; }
} /* namespace nit */
