/*
 * HANDLER: app_register
 *
 * Function copied VERBATIM from OneWifi source/apps/wifi_apps_mgr.c. No fixes.
 * Local key_str[32] is filled by
 *   snprintf(key_str, sizeof(key_str), "app_%010d", descriptor->inst)
 * (<= 15 chars) and then strdup'd as the hash-map key.
 * The new app is malloc(sizeof(wifi_app_t)) and memset / memcpy'd with
 * sizeof(wifi_app_t) / sizeof(wifi_app_descriptor_t). Note: malloc's
 * result is NOT checked before memset (checked by the last case).
 *
 * Poison route:
 *   - snprintf() -> apr_snprintf(): real vsnprintf on a runner slot of the
 *     SAME size (32) with a poisoned tail, then copied into key_str.
 *   - malloc() -> apr_malloc(): hands out a runner pool slot whose tail past
 *     sizeof(wifi_app_t) is poisoned -> memset/memcpy past the app aborts.
 *   - descriptor is a runner buffer; bytes past sizeof(wifi_app_descriptor_t)
 *     are poisoned by the runner (memcpy over-read is caught).
 * key_str is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - get_app_by_inst(): stub (has its own harness) -> "already registered"
 *     per case.
 *   - update_rfc_params(): stub (needs the wifi db); returns 0.
 *   - hash_map_put(): stub, records the key; strdup is real.
 *   - wifi_app_t / wifi_app_descriptor_t: subsets in common.h with the
 *     same leading fields; RETURN_OK = 0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
#define RETURN_OK 0
static wifi_app_t *apr_get_app_by_inst(wifi_apps_mgr_t *m, wifi_app_inst_t inst)
{
    (void)m; (void)inst;
    return apr_already ? (wifi_app_t *)apr_pool[APR_POOL_SLOTS - 1] : NULL;
}
static int update_rfc_params(wifi_app_descriptor_t *d) { (void)d; apr_rfc_calls++; return 0; }
static int8_t apr_hash_map_put(void *map, char *key, void *data)
{
    (void)map;
    snprintf(apr_key_seen, sizeof(apr_key_seen), "%s", key);
    apr_key_len = strlen(key);
    apr_put_data = data;
    free(key);
    return 0;
}
static void *apr_malloc(size_t sz)
{
    if (apr_malloc_fail || sz != sizeof(wifi_app_t) || apr_pool_used >= APR_POOL_SLOTS - 1) return NULL;
    return apr_pool[apr_pool_used++];
}
static int apr_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > APR_SLOT_SZ) sz = APR_SLOT_SZ;
    memset(apr_slot, 0, sz);
    __asan_poison_memory_region(apr_slot + sz, sizeof(apr_slot) - sz);
    va_start(ap, fmt);
    r = vsnprintf(apr_slot, sz, fmt, ap);
    va_end(ap);
    __asan_unpoison_memory_region(apr_slot + sz, sizeof(apr_slot) - sz);
    memcpy(out, apr_slot, sz);
    return r;
}
#define get_app_by_inst(m, i)   apr_get_app_by_inst((m), (i))
#define hash_map_put(m, k, d)   apr_hash_map_put((m), (k), (d))
#define malloc(s)               apr_malloc(s)
#define snprintf(o, n, ...)     apr_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/wifi_apps_mgr.c --- */
int app_register(wifi_apps_mgr_t *apps_mgr, wifi_app_descriptor_t *descriptor)
{
    wifi_app_t *app;
    char key_str[32];

    if ((app = get_app_by_inst(apps_mgr, descriptor->inst)) != NULL) {
        return RETURN_OK;
    }
    update_rfc_params(descriptor);
    app = (wifi_app_t *)malloc(sizeof(wifi_app_t));
    memset(app, 0, sizeof(wifi_app_t));
    app->ctrl = apps_mgr->ctrl;
    memcpy(&app->desc, descriptor, sizeof(wifi_app_descriptor_t));
    snprintf(key_str, sizeof(key_str), "app_%010d", descriptor->inst);
    hash_map_put(apps_mgr->apps_map, strdup(key_str), app);
    if (descriptor->rfc == true) {
        app->desc.init_fn(app, app->desc.create_flag);
    }

    return RETURN_OK;

}
