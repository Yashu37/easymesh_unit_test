/*
 * HANDLER: devinfo_get_inet_iface_config
 *
 * Function copied VERBATIM from OneWifi lib/datapipeline/devinfo.c. No fixes.
 * Its local arrays (home_ip_cached[64], etc.) are filled by devinfo_getv()
 * bounded by sizeof, and copied into the caller's config via STRSCPY (also
 * bounded). The harness observes whether any of those writes go OOB.
 *
 * Scaffolding (NOT the function under test):
 *   - devinfo_getv() is STUBBED here: the real one runs /usr/sbin/
 *     deviceinfo.sh (absent on this box). The stub writes a controlled test
 *     value into dest, bounded by destsz exactly like the real function.
 *   - struct / #defines copied from lib/common/devinfo.h; STRSCPY + strscpy
 *     copied verbatim; LOGD/LOGE no-op stubs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding: defines/types from lib/common/devinfo.h --- */
#define LOGD(...) do { } while (0)
#define LOGE(...) do { } while (0)
#define DEVINFO_CACHED_SIZE 64
#define DEVINFO_WAN_MAC   "emac"
#define DEVINFO_WAN_IP    "eip"
#define DEVINFO_HOME_MAC  "lmac"
#define DEVINFO_HOME_IP   "lip"
#define CONFIG_RDK_LAN_BRIDGE_NAME  "brlan0"
#define CONFIG_RDK_WAN_BRIDGE_NAME  "erouter0"
/* devinfo_inet_iface_config_t + IP/MAC_ADDR_STR_LEN come from common.h */

/* strscpy + STRSCPY copied verbatim from util.c/util.h */
#define ASSERT_ARRAY(A) A
#define STRSCPY(dest, src) strscpy(ASSERT_ARRAY(dest), (src), sizeof(dest))
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

/* STUB of devinfo_getv: returns fixed test values, bounded by destsz. */
static bool devinfo_getv(const char *what, char *dest, size_t destsz)
{
    const char *val = "";
    if      (!strcmp(what, DEVINFO_HOME_IP))  val = "192.168.1.1";
    else if (!strcmp(what, DEVINFO_HOME_MAC)) val = "aa:bb:cc:dd:ee:ff";
    else if (!strcmp(what, DEVINFO_WAN_IP))   val = "10.0.0.2";
    else if (!strcmp(what, DEVINFO_WAN_MAC))  val = "11:22:33:44:55:66";
    strscpy(dest, val, destsz);
    return true;
}

/* --- copied verbatim from lib/datapipeline/devinfo.c --- */
bool devinfo_get_inet_iface_config(
        const char *if_name,
        devinfo_inet_iface_config_t *config)
{
    static char home_ip_cached[DEVINFO_CACHED_SIZE];
    static char home_mac_cached[DEVINFO_CACHED_SIZE];
    static char wan_ip_cached[DEVINFO_CACHED_SIZE];
    static char wan_mac_cached[DEVINFO_CACHED_SIZE];

    static bool once = true;

    if (once)
    {
        devinfo_getv(DEVINFO_HOME_IP,  home_ip_cached,  sizeof(home_ip_cached));
        devinfo_getv(DEVINFO_HOME_MAC, home_mac_cached, sizeof(home_mac_cached));
        devinfo_getv(DEVINFO_WAN_IP,   wan_ip_cached,   sizeof(wan_ip_cached));
        devinfo_getv(DEVINFO_WAN_MAC,  wan_mac_cached,  sizeof(wan_mac_cached));

        once = false;
    }

    if (!strcmp(if_name, CONFIG_RDK_LAN_BRIDGE_NAME))
    {
        STRSCPY(config->inet_addr, home_ip_cached);
        STRSCPY(config->mac_str, home_mac_cached);
    }
    else if (!strcmp(if_name, CONFIG_RDK_WAN_BRIDGE_NAME))
    {
        STRSCPY(config->inet_addr, wan_ip_cached);
        STRSCPY(config->mac_str, wan_mac_cached);
    }
    else
    {
        LOGD("Cannot get config for %s. Only %s and %s interfaces available",
             if_name, CONFIG_RDK_LAN_BRIDGE_NAME, CONFIG_RDK_WAN_BRIDGE_NAME);
        return false;
    }

    return true;
}
