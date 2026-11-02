/*
 * HANDLER: easyconnect_init
 *
 * Copied VERBATIM from OneWifi source/apps/easyconnect/wifi_easyconnect.c
 * (only "static" would be dropped; this one is already non-static). The local
 * array under test is:
 *
 *     bus_data_element_t data_elements[] = { {...}, {...} };   // fixed 2 entries
 *
 * It is a read-only registration table built from an initializer list and
 * passed to bus_reg_data_element_fn(..., ARRAYSIZE(data_elements)). Nothing
 * indexes or writes into it beyond the initializer, so there is no
 * out-of-bounds path here; this is a SAFE-by-construction case. The harness
 * confirms the function registers exactly the two elements and honours the
 * app_init / bus_reg_data_element_fn return codes.
 *
 * Scaffolding (NOT under test): the bus/app plumbing below is stubbed and
 * driven by the ec_* globals the runner/constructor set. NO ASan calls here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"

#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#define WIFI_EC 0
#define WIFI_EASYCONNECT_BSS_INFO  "Device.WiFi.EC.BSSInfo"
#define WIFI_TRIGGER_STA_SCAN_REQ  "Device.WiFi.EC.TriggerStaScan"
#define ZERO_TABLE 0
#define ARRAYSIZE(x) (sizeof(x) / sizeof((x)[0]))
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#define wifi_util_info_print(m, ...)  do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif

/* --- bus types (local to this TU; shapes mirror bus_common.h) --- */
typedef enum { ec_bus_error_success = 0, ec_bus_error_general = 1 } ec_bus_error_t;
#define bus_error_t       ec_bus_error_t
#define bus_error_success ec_bus_error_success
typedef enum { bus_element_type_method = 1 } bus_element_type_t;
typedef enum { slow_speed = 0 } bus_speed_t;
typedef enum { bus_data_type_none = 0, bus_data_type_bytes = 10 } bus_data_type_t;

typedef struct {
    void *get_handler, *set_handler, *table_add_row_handler,
         *table_remove_row_handler, *event_sub_handler, *method_handler;
} bus_callback_table_t;

typedef struct {
    bus_data_type_t data_format;
    bool            data_permission;
    long int        min_data_range;
    long int        max_data_range;
    uint32_t        num_of_str_validation;
    char          **str_validation;
} data_model_properties_t;

typedef struct bus_data_element {
    char                   *full_name;
    bus_element_type_t      type;
    bus_callback_table_t    cb_table;
    bus_speed_t             bus_speed;
    uint32_t                num_of_table_row;
    data_model_properties_t data_model_prop;
} bus_data_element_t;

typedef struct {
    bus_error_t (*bus_reg_data_element_fn)(void *handle, bus_data_element_t *elems, uint32_t num);
} wifi_bus_desc_t;

/* a method callback referenced in the table (real one lives in wifi_easyconnect.c) */
static bus_error_t start_sta_channel_scan_cmd(char *name, void *p_data) { (void)name; (void)p_data; return bus_error_success; }

/* --- stubs driven by ec_* globals --- */
static int app_init(wifi_app_t *app, unsigned int create_flags) { (void)app; (void)create_flags; ec_app_init_calls++; return ec_app_init_ret; }

static bus_error_t ec_reg_elems(void *handle, bus_data_element_t *elems, uint32_t num)
{
    (void)handle;
    ec_bus_reg_calls++;
    ec_bus_reg_n = (int)num;
    if (num >= 1 && elems[0].full_name) snprintf(ec_elem0_name, sizeof(ec_elem0_name), "%s", elems[0].full_name);
    if (num >= 2 && elems[1].full_name) {
        snprintf(ec_elem1_name, sizeof(ec_elem1_name), "%s", elems[1].full_name);
        ec_elem1_set_cb = elems[1].cb_table.set_handler;
    }
    return ec_bus_reg_ret ? ec_bus_error_general : bus_error_success;
}
static wifi_bus_desc_t ec_desc = { ec_reg_elems };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &ec_desc; }

/* ================= VERBATIM from wifi_easyconnect.c ================= */
int easyconnect_init(wifi_app_t *app, unsigned int create_flags)
{
    wifi_util_dbg_print(WIFI_EC, "%s called.", __func__);
    char *app_name = "WifiAppsEasyConnect";
    (void)app_name;

    // clang-format off
    bus_data_element_t data_elements[] = {
        { WIFI_EASYCONNECT_BSS_INFO, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } } ,
        { WIFI_TRIGGER_STA_SCAN_REQ, bus_element_type_method,
            { NULL, (void*)start_sta_channel_scan_cmd, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_none, true, 0, 0, 0, NULL } },
    };
    // clang-format on

    if (app_init(app, create_flags) != 0) {
        wifi_util_error_print(WIFI_EC, "%s:%d: Failed to register app!\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_EC, "%s:%d: EasyConnect app init'd\n", __func__, __LINE__);
    if (get_bus_descriptor()->bus_reg_data_element_fn(&app->ctrl->handle, data_elements,
            ARRAYSIZE(data_elements)) != bus_error_success) {
        wifi_util_error_print(WIFI_EC, "%s:%d: failed to register data elements\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_EC, "%s:%d: EasyConnect app data elems registered\n", __func__,
        __LINE__);
    return RETURN_OK;
}
