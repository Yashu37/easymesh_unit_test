/*
 * HANDLER: unii_5g_chan2list
 *
 * Function copied VERBATIM from OneWifi lib/common/util.c. No fixes.
 * It takes two ints (chan, width) and scans a static const lists[] table
 * for a matching width sub-list, returning a pointer into the table.
 *
 * There is NO caller buffer or input array here (inputs are two ints), so
 * no __asan_poison applies; the only array is the internal static lists[],
 * which ASan guards with a global red-zone. The loop reads every element as
 * a candidate width, including the 0 just before the terminating -1, so a
 * width that matches that 0 can push the inner scan past -1.
 *
 * FIX APPLIED: an "if (width <= 0) return NULL;" guard before the scan, so
 * width==0 (the table terminator value) can no longer match. Only that
 * guard was added; nothing else changed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/common/util.c --- */
const int *unii_5g_chan2list(int chan, int width)
{
    static const int lists[] = {
        /* <width>, <chan1>, <chan2>..., 0, */
        20, 36, 0,
        20, 40, 0,
        20, 44, 0,
        20, 48, 0,
        20, 52, 0,
        20, 56, 0,
        20, 60, 0,
        20, 64, 0,
        20, 100, 0,
        20, 104, 0,
        20, 108, 0,
        20, 112, 0,
        20, 116, 0,
        20, 120, 0,
        20, 124, 0,
        20, 128, 0,
        20, 132, 0,
        20, 136, 0,
        20, 140, 0,
        20, 144, 0,
        20, 149, 0,
        20, 153, 0,
        20, 157, 0,
        20, 161, 0,
        20, 165, 0,
        40, 36, 40, 0,
        40, 44, 48, 0,
        40, 52, 56, 0,
        40, 60, 64, 0,
        40, 100, 104, 0,
        40, 108, 112, 0,
        40, 116, 120, 0,
        40, 124, 128, 0,
        40, 132, 136, 0,
        40, 140, 144, 0,
        40, 149, 153, 0,
        40, 157, 161, 0,
        80, 36, 40, 44, 48, 0,
        80, 52, 56, 60, 64, 0,
        80, 100, 104, 108, 112, 0,
        80, 116, 120, 124, 128, 0,
        80, 132, 136, 140, 144, 0,
        80, 149, 153, 157, 161, 0,
        160, 36, 40, 44, 48, 52, 56, 60, 64, 0,
        160, 100, 104, 108, 112, 116, 120, 124, 128, 0,
        -1, /* keep last */
    };
    const int *start;
    const int *p;

    /* FIX: 0 is the table's terminator, not a real width. Without this
       guard, width==0 matches the final 0 before -1, start=++p lands on
       -1, and the inner loop reads past the end of lists[]. */
    if (width <= 0)
        return NULL;

    for (p = lists; *p != -1; p++)
        if (*p == width)
            for (start = ++p; *p; p++)
                if (*p == chan)
                    return start;

    return NULL;
}
