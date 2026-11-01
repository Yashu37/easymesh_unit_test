/*
 * HANDLER: onewifi_ovsdb_table_monitor_filter
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_table.c, plus one FIX.
 * Local cols[schema_count + 2] (VLA of char *) gets the schema columns
 * (memcpy schema_count), "_version" and NULL, then filter_out_nt_array()
 * compacts it in place -- all within schema_count + 2 slots.
 * The op was read as **filter (first char of filter[0]) with no check that
 * filter[0] exists: an empty filter argv {NULL} dereferenced NULL.
 * FIX APPLIED: the first check is now "if (!filter || !*filter)", so an
 * empty filter is treated like no filter (monitor all columns).
 * Only that condition changed.
 * Caller inputs filter[] and table->columns[] (+ their strings) are
 * poisoned by the runner; cols is internal (ASan stack redzones).
 *
 * Scaffolding (NOT the function under test):
 *   - count_nt_array / is_inarray / filter_out_nt_array: verbatim from
 *     lib/common/util.c.
 *   - onewifi_ovsdb_table_monitor_columns: stub that records the columns
 *     it was given.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
typedef void ovsdb_table_callback_t(ovsdb_update_monitor_t *self, void *old_rec, void *record);

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

static int filter_out_nt_array(char **array, char **filter)
{
    int f_count = count_nt_array(filter);
    int count = 0;
    char **src = array;
    char **dest = array;
    while (src && *src)
    {
        if (!is_inarray(*src, f_count, filter))
        {
            *dest = *src;
            dest++;
            count++;
        }
        src++;
    }
    *dest = NULL;
    return count;
}

static bool onewifi_ovsdb_table_monitor_columns(int fd, ovsdb_table_t *table,
        ovsdb_table_callback_t *callback, char **columns)
{
    (void)fd; (void)table; (void)callback;
    otf2_called = 1;
    otf2_got_null = (columns == NULL);
    otf2_got_count = count_nt_array(columns);
    otf2_has_version = columns ? is_inarray("_version", otf2_got_count, columns) : 0;
    return true;
}

/* --- copied verbatim from lib/ovsdb/ovsdb_table.c --- */
bool onewifi_ovsdb_table_monitor_filter(int ovsdb_fd, ovsdb_table_t *table,
        ovsdb_table_callback_t *callback, char **filter)
{
    int schema_count = count_nt_array(table->columns);
    char *cols[schema_count + 2]; // +2: _version, NULL
    char **columns;
    if (!filter || !*filter)   /* FIX: empty filter argv {NULL} -> same as no filter (was **filter on NULL) */
    {
        columns = NULL;
    }
    else if (**filter == '-')
    {
        // filter out
        // prepare all cols first - schema + _version, NULL
        memcpy(cols, table->columns, schema_count * sizeof(*cols));
        cols[schema_count+0] = "_version";
        cols[schema_count+1] = NULL;
        filter_out_nt_array(cols, filter + 1);
        columns = cols;
    }
    else if (**filter == '+')
    {
        columns = filter + 1;
    }
    else
    {
        columns = filter;
    }
    return onewifi_ovsdb_table_monitor_columns(ovsdb_fd, table, callback, columns);
}
