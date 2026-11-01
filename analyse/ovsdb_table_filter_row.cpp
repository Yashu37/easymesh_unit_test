/*
 * HANDLER: onewifi_ovsdb_table_filter_row
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_table.c. No fixes.
 * Local str[1024] is filled (only at TRACE log level, which the harness
 * turns ON) by strfmt_nt_array(str, sizeof(str), columns): strscpy "[" then
 * strlcat each column + "]" with size = 1024 -> bounded.
 * Caller input columns[] (NULL-terminated argv) and each column string are
 * poisoned by the runner; str is internal (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test):
 *   - strfmt_nt_array + strscpy: verbatim from lib/common/util.c
 *     (strlcat is glibc's).
 *   - LOG_SEVERITY_ENABLED(...) -> 1 so the str[1024] path always runs.
 *   - onewifi_ovsdb_row_filter_argv / onewifi_ovsdb_row_filtout_argv:
 *     stubs that record which one ran and its argc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
#define LOG_SEVERITY_TRACE 8
#define LOG_SEVERITY_ENABLED(s) (1)      /* force the TRACE branch (str[1024]) */

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

/* verbatim from lib/common/util.c */
static char* strfmt_nt_array(char *str, size_t size, char **array)
{
    *str = 0;
    strscpy(str, "[", size);
    while (array && *array)
    {
        if (str[1]) strlcat(str, ",", size);
        strlcat(str, *array, size);
        array++;
    }
    strlcat(str, "]", size);
    otf_str_len = strlen(str);
    return str;
}

static json_t *onewifi_ovsdb_row_filter_argv(json_t *row, int argc, char **argv)
{
    (void)argv; otf_which = '+'; otf_argc = argc; return row;
}
static json_t *onewifi_ovsdb_row_filtout_argv(json_t *row, int argc, char **argv)
{
    (void)argv; otf_which = '-'; otf_argc = argc; return row;
}

/* --- copied verbatim from lib/ovsdb/ovsdb_table.c --- */
// first column has to be "+" or "-" to select filter in/out
json_t* onewifi_ovsdb_table_filter_row(json_t *row, char *columns[])
{
    int argc = 0;
    char *op;
    if (!row) return row;
    if (!columns) return row; // no filter
    while (columns[argc]) argc++;
    if (!argc) return row; // empty filter
    if (LOG_SEVERITY_ENABLED(LOG_SEVERITY_TRACE)) {
        char str[1024];
        strfmt_nt_array(str, sizeof(str), columns);
        LOG(TRACE, "%s: %s", __FUNCTION__, str);
    }
    op = columns[0]; // + or -
    if (strcmp(op, "+") && strcmp(op, "-")) {
        LOG(ERR, "%s: invalid op: '%s' [%d]", __FUNCTION__, op, argc);
        return row;
    }
    if (argc < 1) {
        LOG(WARNING, "%s: filter op: '%s' no columns [%d]", __FUNCTION__, op, argc);
        return row;
    }
    argc--;
    columns++;
    if (*op == '+')
    {
        return onewifi_ovsdb_row_filter_argv(row, argc, columns);
    }
    else if (*op == '-')
    {
        return onewifi_ovsdb_row_filtout_argv(row, argc, columns);
    }
    return row;
}
