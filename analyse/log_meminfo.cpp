/*
 * HANDLER: log_meminfo
 *
 * Function copied VERBATIM from OneWifi lib/log/log.c. No fixes.
 *
 * buf[1024] is filled by a bounded read of /proc/self/status. The output is
 * written to the caller's str with snprintf(str, size, ...). The function
 * guards pos >= size but NOT pos < 0: a negative pos does str += pos (moving
 * BEFORE the caller buffer) and then writes there -- the behaviour under
 * test (an index-below-0 write). The runner poisons both sides of str.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- copied verbatim from lib/log/log.c --- */
void log_meminfo(char *str, int size, int pos, const char *str_prefix, const char *str_append)
{
    static int last_size, last_data, last_rss;

    int fd;
    int sz;
    char buf[1024];
    char *s;
    int vmsize = 0, vmdata = 0, vmrss = 0;
    int d_size = 0, d_data = 0, d_rss = 0;

    if (pos >= size) return;
    str += pos;
    size -= pos;

    *str = 0;
    fd = open("/proc/self/status", O_RDONLY);
    if (!fd) return;

    sz = read(fd, buf, sizeof(buf) - 1);
    if (sz > 0) {
        buf[sz] = 0;
        s = strstr(buf, "VmSize:");
        if (s) s = strchr(s, ':') + 1;
        vmsize = atoi(s);
        s = strstr(buf, "VmData:");
        if (s) s = strchr(s, ':') + 1;
        vmdata = atoi(s);
        s = strstr(buf, "VmRSS:");
        if (s) s = strchr(s, ':') + 1;
        vmrss = atoi(s);
        d_size = vmsize - last_size;
        d_data = vmdata - last_data;
        d_rss = vmrss - last_rss;
        last_size = vmsize;
        last_data = vmdata;
        last_rss = vmrss;
    }
    close(fd);

    // %+d = print a + sign for positive numbers
    snprintf(str, size, "%s{%d %d %d %+d %+d %+d}%s",
            str_prefix ? str_prefix : "",
            vmsize, vmdata, vmrss,
            d_size, d_data, d_rss,
            str_append ? str_append : "");
}
