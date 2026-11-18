/* cmd_setssid scaffolding (namespace css): usings, macros, typedefs and stand-in classes for the handler. Own header, kept out of common.h. */
#ifndef CMD_SETSSID_H
#define CMD_SETSSID_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include "common.h"

namespace css {

/* ---- scaffolding classes, usings, macros moved from cmd_setssid.cpp ---- */
/* bus types come from the ccs section of common.h (the global ones differ in other harnesses) */
using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_general; using ccs::bus_error_invalid_input; using ccs::bus_error_out_of_resources;
using ccs::bus_data_type_t; using ccs::bus_data_type_string;
using ccs::raw_data_t; using ccs::bus_data_prop_t;

#define TR181_SSID_MAX_LEN         32
#define TR181_PASSPHRASE_MAX_LEN   63
#define TR181_BAND_MAX_LEN         16
#define TR181_ADDREMOVE_MAX_LEN    16
#define TR181_HAULTYPE_MAX_LEN     32
#define TR181_AKMS_MAX_LEN         32
#define EM_IO_BUFF_SZ 4096
#undef GLOBAL_NET_ID
#define GLOBAL_NET_ID "OneWifiMesh"

typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef enum { em_bus_event_type_set_ssid = 1 } em_bus_event_type_t;

/* --- scaffolding: controller / data-model stand-ins --- */
const char *cfg_json = NULL;     /* what get_config() returns */

extern int io_calls;
extern char io_json[EM_IO_BUFF_SZ + 64];
extern unsigned int io_len;
extern char last_status[16];
class dm_easy_mesh_ctrl_t {
public:
    void get_config(char *net_id, em_subdoc_info_t *subdoc)
    {   (void)net_id;
        if (cfg_json) { size_t n = strlen(cfg_json); if (n > EM_IO_BUFF_SZ - 1) n = EM_IO_BUFF_SZ - 1; memcpy(subdoc->buff, cfg_json, n); subdoc->buff[n] = '\0'; }
        else subdoc->buff[0] = '\0';
    }
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
    void io_process(em_bus_event_type_t type, char *data, unsigned int len)
    {   (void)type; io_calls++; io_len = len;
        memset(io_json, 0, sizeof(io_json));
        memcpy(io_json, data, len < sizeof(io_json) ? len : sizeof(io_json) - 1);
    }
    static bus_error_t cmd_setssid(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle);
};

class tr_181_t {
public:
    static void tr181_trim_whitespace(char *str);
    static bool tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len);
    static cJSON *create_haultype_array(const char *haul_val);
    static bool item_matches_haultype(const cJSON *item, const char *haul_val);
    static cJSON *create_akms_array(const char *akms_val);
    static const char *akms_to_auth_type(const char *akms_val);
    static const char *akms_array_to_auth_type(const cJSON *akms_arr);
    static bus_data_prop_t *tr181_set_status_output_prop(const char *status)
    {   /* stand-in for tr181_alloc_string_prop("Status", status) */
        bus_data_prop_t *p = (bus_data_prop_t *)calloc(1, sizeof(*p));
        snprintf(last_status, sizeof(last_status), "%s", status);
        p->value.data_type = bus_data_type_string;
        p->value.raw_data.bytes = strdup(status);
        return p;
    }
};

extern em_ctrl_t *ctrl_instance_ptr;
}
#endif
