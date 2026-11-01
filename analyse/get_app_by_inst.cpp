/*
 * HANDLER: get_app_by_inst
 *
 * Function copied VERBATIM from OneWifi source/apps/wifi_apps_mgr.c. No fixes.
 * Local key_str[32] is filled by
 *   snprintf(key_str, sizeof(key_str), "app_%010d", inst)
 * ("app_" + 10 digits = 14 chars; a negative inst adds a '-' -> 15 at most
 * for INT_MIN) and handed to hash_map_get().
 *
 * Poison route:
 *   - snprintf() -> gai_snprintf(): real vsnprintf on the runner slot
 *     gai_slot with the SAME size (32), then copied into key_str. The runner
 *     poisons gai_slot past 32 around the call -> a write past 32 aborts.
 *   - hash_map_get() -> gai_hash_map_get(): copies the key (strlen) into a
 *     runner buffer and looks it up in a tiny runner table.
 *   - apps_mgr is a runner struct; the bytes past it are poisoned.
 * key_str is also guarded by ASan stack redzones.
 *
 * Scaffolding: wifi_apps_mgr_t subset (ctrl, apps_map), wifi_app_t opaque,
 * wifi_app_inst_t = int (enum of bit values in include/wifi_base.h).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
static void *gai_hash_map_get(void *map, const char *key)
{
    (void)map;
    snprintf(gai_key_seen, sizeof(gai_key_seen), "%s", key);
    gai_key_len = strlen(key);
    for (int i = 0; i < gai_nentries; i++)
        if (!strcmp(gai_keys[i], key)) return gai_vals[i];
    return NULL;
}
static int gai_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > GAI_SLOT_SZ) sz = GAI_SLOT_SZ;
    memset(gai_slot, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(gai_slot, sz, fmt, ap);
    va_end(ap);
    memcpy(out, gai_slot, sz);
    return r;
}
#define hash_map_get(m, k)   gai_hash_map_get((m), (k))
#define snprintf(o, n, ...)  gai_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/wifi_apps_mgr.c --- */
wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *apps_mgr, wifi_app_inst_t inst)
{
    char key_str[32];
    wifi_app_t *node = NULL;

    snprintf(key_str, sizeof(key_str), "app_%010d", inst);
    node = (wifi_app_t *)hash_map_get(apps_mgr->apps_map, key_str);

    return node;
}
