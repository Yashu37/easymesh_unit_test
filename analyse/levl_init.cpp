/*
 * HANDLER: levl_init
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes).
 * Local array under test:
 *
 *     bus_data_element_t dataElements[12] = { {...}, ... };  // fixed 12 entries
 *
 * It is a read-only registration table built from an initializer list;
 * num_elements = sizeof(dataElements)/sizeof(bus_data_element_t) = 12 is passed
 * to bus_reg_data_element_fn. Nothing indexes or writes into it, so there is no
 * out-of-bounds path (SAFE-by-construction). The other array,
 * temperature_event_subscribed[MAX_NUM_RADIOS], is written for
 * radio < MAX_NUM_RADIOS -> in bounds. The harness checks the table has exactly
 * 12 entries, all with names, plus the init state written into the app.
 *
 * Scaffolding (NOT under test): app_init, get_wifictrl_obj, get_app_by_inst,
 * hash_map_create, scheduler_add_timer_task, mkfifo, pthread_mutex_init, the
 * bus descriptor and the callback functions are stubs driven by the lli_*
 * globals the runner/constructor set; the bus types are local models.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include "common.h"

#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#define WIFI_APPS 0
#define ZERO_TABLE 0
#define wifi_app_inst_csi 4096
#define MAX_LEVL_CSI_CLIENTS 5
#define DEFAULT_SOUNDING_DURATION_MS 2000
#define APPS_FRAME_EXEC_TIMEOUT_PERIOD (30 * 60)
#define CSI_LEVL_PIPE "/tmp/csi_levl_pipe"
#define WIFI_EVENTS_VAP_TABLE               "Device.WiFi.Events.VAP.{i}."
#define WIFI_ANALYTICS_FRAME_EVENTS         "Device.WiFi.Events.VAP.{i}.Frames.Mgmt"
#define WIFI_ANALYTICS_DATA_EVENTS          "Device.WiFi.Events.VAP.{i}.Frames.Data"
#define WIFI_LEVL_CLIENTMAC                 "Device.WiFi.X_RDK_CSI_LEVL.clientMac"
#define WIFI_LEVL_NUMBEROFENTRIES           "Device.WiFi.X_RDK_CSI_LEVL.maxNumberCSIClients"
#define WIFI_LEVL_CSI_DATA                  "Device.WiFi.X_RDK_CSI_LEVL.data"
#define WIFI_LEVL_CSI_DATAFIFO              "Device.WiFi.X_RDK_CSI_LEVL.datafifo"
#define WIFI_LEVL_SOUNDING_DURATION         "Device.WiFi.X_RDK_CSI_LEVL.Duration"
#define WIFI_LEVL_CSI_STATUS                "Device.WiFi.X_RDK_CSI_LEVL.soundingStatus"
#define WIFI_LEVL_CSI_MAC_DATA              "Device.WiFi.X_RDK_CSI_LEVL.clientMacData"
#define RADIO_LEVL_TEMPERATURE_TABLE        "Device.WiFi.Events.Radio.{i}."
#define RADIO_LEVL_TEMPERATURE_EVENT        "Device.WiFi.Events.Radio.{i}.Temperature"
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#endif
#define wifi_util_info_print(m, ...)  do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)

/* --- bus types (local to this TU; shapes mirror bus_common.h) --- */
typedef enum { bus_error_success = 0, bus_error_general = 1 } bus_error_t;
typedef enum { bus_element_type_table = 1, bus_element_type_method = 2, bus_element_type_event = 3, bus_element_type_property = 4 } bus_element_type_t;
typedef enum { slow_speed = 0 } bus_speed_t;
typedef enum { bus_data_type_none = 0, bus_data_type_string = 3, bus_data_type_uint32 = 7, bus_data_type_bytes = 10, bus_data_type_object = 11 } bus_data_type_t;
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
    bus_error_t (*bus_open_fn)(void *handle, const char *component);
    bus_error_t (*bus_reg_data_element_fn)(void *handle, bus_data_element_t *elems, uint32_t num);
} wifi_bus_desc_t;

/* --- stubs --- */
static int getNumberRadios(void) { return lli_radios; }
static int getTotalNumberVAPs(void) { return lli_vaps; }
static int app_init(wifi_app_t *app, unsigned int create_flag) { (void)app; (void)create_flag; lli_app_init_calls++; return lli_app_init_ret; }
static wifi_ctrl_t *get_wifictrl_obj(void) { return lli_null_ctrl ? NULL : (wifi_ctrl_t *)lli_ctrl_buf; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return lli_null_csi ? NULL : (wifi_app_t *)lli_csi_buf; }
static void *lli_hash_map_create(void)
{
    lli_map_calls++;
    return (lli_map_fail_at == lli_map_calls) ? NULL : (void *)&lli_map_tokens[lli_map_calls];
}
static int lli_sched_add(void *s, int a, int *id, int (*fn)(void *), void *arg, unsigned int period_ms, unsigned int b, int c)
{
    (void)s; (void)a; (void)fn; (void)arg; (void)b; (void)c;
    lli_sched_calls++; lli_sched_period = (int)period_ms; *id = 77; return 0;
}
static int lli_mkfifo(const char *path, int mode) { (void)path; (void)mode; lli_mkfifo_calls++; if (lli_mkfifo_err) { errno = lli_mkfifo_err; return -1; } return 0; }
static int lli_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) { lli_mutex_init_calls++; return pthread_mutex_init(m, a); }
static bus_error_t lli_open(void *handle, const char *component) { (void)handle; (void)component; lli_open_calls++; return lli_bus_open_ret ? bus_error_general : bus_error_success; }
static bus_error_t lli_reg(void *handle, bus_data_element_t *elems, uint32_t num)
{
    (void)handle;
    lli_reg_calls++; lli_reg_n = (int)num;
    lli_reg_names_ok = 1;
    for (uint32_t i = 0; i < num; i++) if (!elems[i].full_name || !elems[i].full_name[0]) lli_reg_names_ok = 0;
    if (num >= 1) { snprintf(lli_reg_first, sizeof(lli_reg_first), "%s", elems[0].full_name); lli_reg_rows0 = (int)elems[0].num_of_table_row; }
    if (num >= 12) { snprintf(lli_reg_last, sizeof(lli_reg_last), "%s", elems[11].full_name); lli_reg_rows10 = (int)elems[10].num_of_table_row; }
    return lli_bus_reg_ret ? bus_error_general : bus_error_success;
}
static wifi_bus_desc_t lli_desc = { lli_open, lli_reg };
static wifi_bus_desc_t *get_bus_descriptor(void) { return &lli_desc; }
/* callbacks referenced by the table / assigned into the app (real ones live in wifi_levl.c) */
static bus_error_t levl_vap_addrowhandler(char const *t, char const *a, uint32_t *i) { (void)t; (void)a; (void)i; return bus_error_success; }
static bus_error_t levl_vap_removerowhandler(char const *r) { (void)r; return bus_error_success; }
static bus_error_t levl_radio_addrowhandler(char const *t, char const *a, uint32_t *i) { (void)t; (void)a; (void)i; return bus_error_success; }
static bus_error_t levl_radio_removerowhandler(char const *r) { (void)r; return bus_error_success; }
static bus_error_t levl_event_handler(char *e, int act, int32_t iv, bool *ap) { (void)e; (void)act; (void)iv; (void)ap; return bus_error_success; }
static bus_error_t levl_get_handler(char *e, void *p, void *u) { (void)e; (void)p; (void)u; return bus_error_success; }
static bus_error_t levl_set_handler(char *e, void *p, void *u) { (void)e; (void)p; (void)u; return bus_error_success; }
static int levl_start_fn(void *a, unsigned int ap, unsigned char *m, int s) { (void)a; (void)ap; (void)m; (void)s; return 0; }
static int levl_stop_fn(void *a, unsigned int ap, unsigned char *m, int s) { (void)a; (void)ap; (void)m; (void)s; return 0; }
static int levl_event_exec_timeout(void *arg) { (void)arg; return 0; }
#define hash_map_create()                 lli_hash_map_create()
#define scheduler_add_timer_task(s, a, id, fn, arg, p, b, c)   lli_sched_add((s), (a), (id), (fn), (arg), (p), (b), (c))
#define mkfifo(p, m)                      lli_mkfifo((p), (m))
#define pthread_mutex_init(m, a)          lli_mutex_init((m), (a))

/* ================= VERBATIM from wifi_levl.c ================= */
int levl_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = bus_error_success;
    char *component_name = "WifiAppsLevl";

    int num_of_radio = getNumberRadios();
    int num_of_vaps = getTotalNumberVAPs();
    int num_elements;

    bus_data_element_t dataElements[] = {
        { WIFI_EVENTS_VAP_TABLE, bus_element_type_table,
            { NULL, NULL, levl_vap_addrowhandler, levl_vap_removerowhandler, NULL, NULL }, slow_speed, num_of_vaps,
            { bus_data_type_object, false, 0, 0, 0, NULL } },
        { WIFI_ANALYTICS_DATA_EVENTS, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } },
        { WIFI_ANALYTICS_FRAME_EVENTS, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } },
        { WIFI_LEVL_CSI_DATA, bus_element_type_event,
            { NULL, NULL, NULL, NULL, levl_event_handler, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } },
        { WIFI_LEVL_CSI_DATAFIFO, bus_element_type_event,
            { NULL, NULL, NULL, NULL, levl_event_handler, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } },
        { WIFI_LEVL_CLIENTMAC, bus_element_type_property,
            { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_string, true, 0, 0, 0, NULL } },
        { WIFI_LEVL_NUMBEROFENTRIES, bus_element_type_property,
            { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_uint32, true, 0, 0, 0, NULL } },
        { WIFI_LEVL_SOUNDING_DURATION, bus_element_type_property,
            { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_uint32, true, 0, 0, 0, NULL } },
        { WIFI_LEVL_CSI_MAC_DATA, bus_element_type_property,
            { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_string, true, 0, 0, 0, NULL } },
        { WIFI_LEVL_CSI_STATUS, bus_element_type_event,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { RADIO_LEVL_TEMPERATURE_TABLE, bus_element_type_table,
            { NULL, NULL, levl_radio_addrowhandler, levl_radio_removerowhandler, NULL, NULL}, slow_speed, num_of_radio,
            { bus_data_type_object, false, 0, 0, 0, NULL } },
        { RADIO_LEVL_TEMPERATURE_EVENT, bus_element_type_event,
            { NULL, NULL, NULL, NULL, levl_event_handler, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_uint32, false, 0, 0, 0, NULL } }
    };

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_dbg_print(WIFI_APPS, "%s:%d: Init Levl\n", __func__, __LINE__);

    wifi_app_t *csi_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_apps_mgr_t *apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    csi_app = get_app_by_inst(apps_mgr, wifi_app_inst_csi);
    if (csi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL CSI app instance\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.levl.csi_app = csi_app;
    app->data.u.levl.csi_fns.csi_start_fn = levl_start_fn;
    app->data.u.levl.csi_fns.csi_stop_fn = levl_stop_fn;
    app->data.u.levl.probe_req_map = hash_map_create();
    app->data.u.levl.curr_sounding_mac_map = hash_map_create();
    app->data.u.levl.pending_mac_map = hash_map_create();
    app->data.u.levl.postpone_sched_handler_id = 0;
    if ((app->data.u.levl.curr_sounding_mac_map == NULL) || (app->data.u.levl.pending_mac_map == NULL)) {
        wifi_util_error_print(WIFI_APPS,"%s:%d Unable to create hash map\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.levl.max_num_csi_clients = MAX_LEVL_CSI_CLIENTS;
    app->data.u.levl.sounding_duration = DEFAULT_SOUNDING_DURATION_MS;
    app->data.u.levl.num_current_sounding = 0;
    app->data.u.levl.csi_event_subscribed = FALSE;
    for (unsigned int radio = 0; radio < MAX_NUM_RADIOS; radio++) {
        app->data.u.levl.temperature_event_subscribed[radio] = FALSE;
    }
    if (!app->data.u.levl.lock_initialized) {
        pthread_mutex_init(&app->data.u.levl.lock, NULL);
        app->data.u.levl.lock_initialized = TRUE;
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &(app->data.u.levl.probe_collector_sched_handler_id),
                               levl_event_exec_timeout, app, (APPS_FRAME_EXEC_TIMEOUT_PERIOD * 1000), 0, FALSE);

    //Create FIFO for the csi.
    if (mkfifo(CSI_LEVL_PIPE, 0777) != 0 && errno != EEXIST) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Failed to create FIFO %s, errno:%d\n",
            __func__, __LINE__, CSI_LEVL_PIPE, errno);
        return RETURN_ERR;
    }
    app->data.u.levl.csi_fd = -1;
 
    rc = get_bus_descriptor()->bus_open_fn(&app->handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n",
            __func__, __LINE__, component_name, rc);
        return RETURN_ERR;
    }

    num_elements = (sizeof(dataElements)/sizeof(bus_data_element_t));

    rc = get_bus_descriptor()->bus_reg_data_element_fn(&app->handle, dataElements, num_elements);
    if (rc != bus_error_success) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d bus_reg_data_element_fn failed, rc:%d\n", __func__, __LINE__, rc);
    } else {
        wifi_util_info_print(WIFI_APPS,"%s:%d Apps bus_regDataElement success\n", __func__, __LINE__);
    }

    return RETURN_OK;
}
