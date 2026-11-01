/*
 * HANDLER: onewifi_ovsdb_table_monitor_columns
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_table.c. No fixes.
 * Local tmp[1024] is filled by strfmt_nt_array(tmp, sizeof(tmp), columns)
 * inside the LOG(NOTICE, ...) arguments: strscpy "[" then strlcat each
 * column + "]" with size = 1024 -> bounded. Caller input columns[] (and the
 * table's own columns[]) plus every column string are poisoned by the
 * runner; tmp is internal (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test):
 *   - LOG / LOGE: really FORMAT their arguments (vsnprintf into a scratch
 *     buffer), so strfmt_nt_array(tmp, ...) inside LOG is executed.
 *   - count_nt_array / is_inarray / is_array_in_array / strfmt_nt_array /
 *     strscpy: verbatim from lib/common/util.c (strlcat is glibc's).
 *   - onewifi_ovsdb_update_monitor / _ex: stubs (record which ran + colc).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
static void otm_log(const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define LOG(sev, ...) otm_log(__VA_ARGS__)
#define LOGE(...)     otm_log(__VA_ARGS__)
#define OMT_ALL  0xF   /* OMT_INITIAL | OMT_INSERT | OMT_DELETE | OMT_MODIFY (lib/ovsdb/ovsdb.h) */
typedef void ovsdb_table_callback_t(ovsdb_update_monitor_t *self, void *old_rec, void *record);

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
static bool is_inarray(const char * key, int argc, char ** argv)
{
    int i;
    bool retval = false;

    for(i = 0; i < argc; i++)
    {
        if (0 == strcmp(key, argv[i]))
        {
            LOG(TRACE, "Found is_inarray()::argc=%d|i=%d|argv[i]=%s", argc, i, argv[i]);
            retval = true;
            break;
        }
    }

    return retval;
}

static int count_nt_array(char **array)
{
    int count = 0;
    if (!array) return 0;
    while (*array)
    {
        array++;
        count++;
    }
    return count;
}

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
    otm_tmp_len = strlen(str);
    return str;
}

static bool is_array_in_array(char **src, char **dest)
{
    int count = count_nt_array(dest);
    if (!src && !dest) return true;
    if (!src || !dest) return false;
    while (*src)
    {
        if (!is_inarray(*src, count, dest)) return false;
        src++;
    }
    return true;
}

static bool onewifi_ovsdb_update_monitor(int fd, ovsdb_update_monitor_t *self, ovsdb_update_cbk_t *cb,
                                         char *table, int flags)
{
    (void)fd; (void)self; (void)cb; (void)table; (void)flags;
    otm_which = 'A'; otm_colc = 0;
    return otm_monitor_ok;
}
static bool onewifi_ovsdb_update_monitor_ex(int fd, ovsdb_update_monitor_t *self, ovsdb_update_cbk_t *cb,
                                            char *table, int flags, int colc, char *colv[])
{
    (void)fd; (void)self; (void)cb; (void)table; (void)flags; (void)colv;
    otm_which = 'C'; otm_colc = colc;
    return otm_monitor_ok;
}

/* --- copied verbatim from lib/ovsdb/ovsdb_table.c --- */
bool onewifi_ovsdb_table_monitor_columns(int ovsdb_fd, ovsdb_table_t *table,
        ovsdb_table_callback_t *callback, char **columns)
{
    bool ret;
    int count = count_nt_array(columns);

    if (!columns || !count)
    {
        LOG(NOTICE, "Monitor: %s: ALL", table->table_name);
        ret = onewifi_ovsdb_update_monitor(ovsdb_fd, 
                &table->monitor,
                table->monitor_callback,
                table->table_name,
                OMT_ALL);
    }
    else
    {
        // are all schema columns present?
        if (!is_array_in_array(table->columns, columns))
        {
            // no, enable partial updates in monitor callback
            table->partial_update = true;
        }
        bool have_version = is_inarray("_version", count, columns);
        char tmp[1024];
        LOG(NOTICE, "Monitor: %s _version: %s partial: %s columns: %d %s", table->table_name,
                have_version ? "true" : "false",
                table->partial_update ? "true" : "false", count,
                strfmt_nt_array(tmp, sizeof(tmp), columns));
        ret = onewifi_ovsdb_update_monitor_ex(ovsdb_fd, 
                &table->monitor,
                table->monitor_callback,
                table->table_name,
                OMT_ALL,
                count,
                columns);
    }
    if (!ret)
    {
        LOGE("Error registering watcher for %s.", table->table_name);
        return false;
    }
    table->monitor.mon_data = table;
    table->table_callback = callback;
    return true;
}
