/*
 * HANDLER: parse_uri
 *
 * Function copied VERBATIM from OneWifi lib/common/util.c. No fixes.
 * Local array tmp[UTIL_URI_MAX_LENG] is filled by STRSCPY(tmp, uri) =
 * strscpy(tmp, uri, sizeof(tmp)), which is size-bounded. Output is copied
 * into the caller's proto/host via strscpy(..., *_size) (also bounded).
 *
 * FIX APPLIED: added a "!tproto ||" NULL guard before the strcmp() calls.
 * The original dereferenced tproto unconditionally, so a URI made only of
 * delimiter(s) (e.g. ":") -> strtok_r returns NULL -> strcmp(NULL,...) ->
 * crash. Only that guard was added; nothing else changed.
 *
 * The strscpy() helper is copied verbatim too (from util.c:731).
 * Scaffolding: STRSCPY/ASSERT_ARRAY macros, UTIL_URI_MAX_LENG, LOGE/LOG
 * no-op stubs. No logic changed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
#define LOGE(...)     do { } while (0)
#define UTIL_URI_MAX_LENG 512                /* verbatim from util.c:59 */
#define ASSERT_ARRAY(A) A                    /* verbatim variant from util.h:116 */
#define STRSCPY(dest, src) strscpy(ASSERT_ARRAY(dest), (src), sizeof(dest))

/* --- copied verbatim from lib/common/util.c:731 --- */
ssize_t strscpy(char *dest, const char *src, size_t size)
{
    size_t len;
    if (size == 0) return -E2BIG;
    len = strnlen(src, size - 1);
    memcpy(dest, src, len);
    dest[len] = 0;
    if (src[len]) return -E2BIG;
    return (ssize_t)len;
}

/* --- copied verbatim from lib/common/util.c --- */
bool parse_uri(char *uri, char *proto, size_t proto_size, char *host, size_t host_size, int *port)
{
    // split
    char *sptr, *tproto, *thost, *pstr;
    int tport = 0;
    char tmp[UTIL_URI_MAX_LENG];

    if (!uri || uri[0] == '\0')
    {
        LOGE("URI empty");
        return false;
    }
    STRSCPY(tmp, uri);

    // Split the address up into it's pieces
    tproto = strtok_r(tmp, ":", &sptr);
    thost  = strtok_r(NULL, ":", &sptr);
    pstr  = strtok_r(NULL, ":", &sptr);
    if (pstr) tport = atoi(pstr);

    if (   !tproto
        || (strcmp(tproto, "ssl")
        && strcmp(tproto, "tcp")))
    {
        LOGE("URI %s proto not supported (Only ssl and tcp)", uri);
        return false;
    }

    if (  !thost
        || thost[0] == '\0'
        || tport <= 0
        )
    {
        LOGE("URI %s malformed (Host or port)", uri);
        return false;
    }
    else
    {
        strscpy(proto, tproto, proto_size);
        strscpy(host, thost, host_size);
        *port = tport;
    }

    return true;
}
