/*
 * TEST CASES / CONSTRUCTOR: construct_app_register
 *
 * The descriptor sits at the start of apr_desc_buf (bytes past
 * sizeof(wifi_app_descriptor_t) poisoned by the runner) with a 255-char
 * desc name. rfc = true -> init_fn(app, create_flag) is called.
 *
 * Cases: new app rfc on, new app rfc off, already registered (returns
 * early), inst INT_MIN (15-char key), inst INT_MAX, and LAST malloc
 * returning NULL (memset(NULL) -- no check in the function).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   apr_slot[APR_SLOT_SZ + APR_SLOT_PAD];
alignas(16) unsigned char apr_pool[APR_POOL_SLOTS][sizeof(wifi_app_t) + APR_POOL_PAD];
int    apr_pool_used, apr_malloc_fail, apr_already, apr_rfc_calls, apr_init_calls;
char   apr_key_seen[64];
size_t apr_key_len;
void  *apr_put_data;
alignas(16) char apr_desc_buf[sizeof(wifi_app_descriptor_t) + 64];
alignas(16) char apr_mgr_buf[sizeof(wifi_apps_mgr_t) + 64];

static int apr_init_fn(wifi_app_t *app, unsigned int create_flag)
{
    (void)create_flag;
    apr_init_calls++;
    return app && app->desc.inst ? 0 : -1;
}

app_register_test_case_t app_register_suite[] = {
    /* name             inst      rfc already malloc_fail key_len put init */
    { "new_rfc_on",       0x1,     1,    0,     0,          14,    1,  1 },
    { "new_rfc_off",      0x2,     0,    0,     0,          14,    1,  0 },
    { "already_reg",      0x8,     1,    1,     0,           0,    0,  0 },
    { "inst_int_min",   INT_MIN,   1,    0,     0,          15,    1,  1 },
    { "inst_int_max",   INT_MAX,   1,    0,     0,          14,    1,  1 },
    { "malloc_fails",     0x4,     1,    0,     1,           0,    0,  0 },   /* NULL deref expected */

    { NULL, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_app_register_input(const app_register_test_case_t *tc)
{
    memset(apr_pool, 0xAB, sizeof(apr_pool));
    apr_pool_used = 0;
    memset(apr_desc_buf, 0, sizeof(apr_desc_buf));
    wifi_app_descriptor_t *d = (wifi_app_descriptor_t *)apr_desc_buf;
    d->inst = tc->inst;
    d->create_flag = 3;
    d->rfc = tc->rfc != 0;
    d->enable = d->rfc;
    memset(d->desc, 'd', sizeof(d->desc) - 1);
    d->init_fn = apr_init_fn;
    memset(apr_mgr_buf, 0, sizeof(apr_mgr_buf));
    ((wifi_apps_mgr_t *)apr_mgr_buf)->ctrl = (void *)0x1234;
    apr_already = tc->already;
    apr_malloc_fail = tc->malloc_fail;
    apr_rfc_calls = apr_init_calls = 0;
    apr_key_seen[0] = 0; apr_key_len = 0; apr_put_data = NULL;
}
