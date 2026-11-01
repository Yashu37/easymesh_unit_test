/*
 * HANDLER: os_nif_macaddr_from_str
 *
 * Function copied VERBATIM from OneWifi lib/osa/os_nif_linux.c. No fixes.
 * Local pstr[64] is filled by STRSCPY (strscpy with sizeof(pstr)), so a long
 * input is truncated to 63 chars. mac->addr[cmak++] is guarded by
 * "if (cmak >= 6) return false" before the write. Caller input str and
 * output mac are poisoned by the runner; pstr is internal (ASan-guarded).
 *
 * Scaffolding: strscpy/STRSCPY copied verbatim from lib/common/util.c/.h,
 * os_strtoul copied verbatim from lib/common/os_util.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
#define ASSERT_ARRAY(A) A
#define STRSCPY(dest, src)  strscpy(ASSERT_ARRAY(dest), (src), sizeof(dest))
static ssize_t strscpy(char *dest, const char *src, size_t size)
{
    size_t len;
    if (size == 0) return -E2BIG;
    len = strnlen(src, size - 1);
    memcpy(dest, src, len);
    dest[len] = 0;
    if (src[len]) return -E2BIG;
    return (ssize_t)len;
}

static bool os_strtoul(char *str, long *out, int base)
{
    char *pend;

    if (str == NULL) return false;

    errno = 0;

    *out = strtoul(str, &pend, base);

    if (str == pend || *pend != '\0')
    {
        return false;
    }

    if (*out == LONG_MAX && errno != 0)
    {
        return false;
    }

    return true;
}

/* --- copied verbatim from lib/osa/os_nif_linux.c --- */
bool os_nif_macaddr_from_str(os_macaddr_t* mac, const char* str)
{
    char    pstr[64];
    char*   mstr = NULL;
    char*   mtok = NULL;
    long    cnum = 0;
    int     cmak = 0;

    STRSCPY(pstr, str);

    mstr = pstr;
    while ((mtok = strsep(&mstr, ":-")) != NULL)
    {
        if (os_strtoul(mtok, &cnum, 16) != true)
        {
            return false;
        }

        /* Check if the parsed number is between 0 and 255 */
        if (cnum >= 256)
        {
            return false;
        }

        /* Check if we have more than 6 bytes */
        if (cmak >= 6)
        {
            return false;
        }

        mac->addr[cmak++] = cnum;
    }

    return true;
}
