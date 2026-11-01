/*
 * HANDLER: onewifi_ovsdb_tran_comment
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_method.c. No fixes.
 * Local comment[128]:
 *   - STRSCPY(comment, ovsdb_comment)   -> strscpy(.., sizeof(comment))
 *   - strscat(comment, " - " / op / ", " / "{uknown}" / "<null>" / each
 *     where string, sizeof(comment))   -> every append bounded by 128.
 * Caller inputs: the global ovsdb_comment string (runner buffer, tail
 * poisoned by the runner) and the where array (jansson-owned strings).
 * comment is internal (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test):
 *   - strscpy / strscat: verbatim from lib/common/util.c.
 *   - STRSCPY: lib/common/util.h (ASSERT_ARRAY is a compile-time check only).
 *   - ovsdb_comment: points at the runner buffer (NULL for one case).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
typedef enum                                    /* lib/ovsdb/ovsdb.h */
{
    OTR_INSERT,
    OTR_SELECT,
    OTR_UPDATE,
    OTR_MUTATE,
    OTR_DELETE,
    OTR_WAIT,
}ovsdb_tro_t;

#define ASSERT_ARRAY(x)     (x)
#define STRSCPY(dest, src)  strscpy(ASSERT_ARRAY(dest), (src), sizeof(dest))   /* lib/common/util.h */

/* verbatim from lib/common/util.c */
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

static ssize_t strscat(char *dest, const char *src, size_t size)
{
    if (size == 0) return -E2BIG;
    size_t dlen = strnlen(dest, size);
    size_t free = size - dlen;
    if (free == 0) return -E2BIG;
    ssize_t slen = strscpy(dest + dlen, src, free);
    if (slen < 0) return slen;
    return (ssize_t)dlen + slen;
}

/* --- copied verbatim from lib/ovsdb/ovsdb_method.c --- */
bool onewifi_ovsdb_tran_comment(json_t *js_array, ovsdb_tro_t oper, json_t *where)
{
    char comment[128];

    char *op = NULL;
    json_t *js = NULL;

    if (ovsdb_comment == NULL) return true;

    STRSCPY(comment, ovsdb_comment);

    switch (oper)
    {
        case OTR_INSERT:
            op = "insert";
            break;

        case OTR_UPDATE:
            op = "update";
            break;

        case OTR_MUTATE:
            op = "mutate";
            break;

        case OTR_DELETE:
            op = "delete";
            break;

        default:
            return true;
    }

    strscat(comment, " - ", sizeof(comment));
    strscat(comment, op, sizeof(comment));

    /* Collapse the where 2-dimensional array to a string */
    if (json_is_array(where))
    {
        size_t ii;

        for (ii = 0; ii < json_array_size(where); ii++)
        {
            json_t *js = json_array_get(where, ii);
            size_t ij;

            strscat(comment, ", ", sizeof(comment));

            if (!json_is_array(js))
            {
                strscat(comment, "{uknown}", sizeof(comment));
                continue;
            }

            for (ij = 0; ij < json_array_size(js); ij++)
            {
                const char *str = json_string_value(json_array_get(js, ij));

                if (str == NULL)
                {
                    strscat(comment, "<null>", sizeof(comment));
                }
                else
                {
                    strscat(comment, str, sizeof(comment));
                }
            }
        }
    }

    js = json_object();
    if (js == NULL) goto error;

    if (json_object_set_new(js, "op", json_string("comment")) != 0)
    {
        goto error;
    }

    if (json_object_set_new(js, "comment", json_string(comment)) != 0)
    {
        goto error;
    }

    if (json_array_append_new(js_array, js) != 0)
    {
        goto error;
    }

    return true;

error:
    if (js != NULL) json_decref(js);

    return false;
}
