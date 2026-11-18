/* cmd_steerwifibh harness types (namespace cwb). Kept out of common.h so `make` stays incremental. */
#ifndef CMD_CHANNELSCAN_H
#define CMD_CHANNELSCAN_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "common.h"

namespace cwb {
#define CWB_MAXP 10
#define CWB_VAL_SZ 192
#define CWB_PAD 64

typedef struct {
    const char *name;     /* property name */
    int kind;             /* 0 string, 1 int32, 5 string of len copies, 6 bool (u8) */
    const char *s;
    int i;
    int len;
} prop_spec_t;
typedef struct {
    const char *test_name;
    const char *method;   /* NULL passes a NULL method_name */
    bool no_props;        /* input_params == NULL */
    bool no_out;          /* output_params == NULL */
    prop_spec_t props[CWB_MAXP];
    int expect_rc;
    const char *json_has; /* substring expected in the JSON sent to io_process (accept cases) */
    bool crash;           /* expected to abort: runs last, unforked unless FORK_CRASH=1 */
} test_case_t;
extern test_case_t suite[];
extern char method_buf[256 + CWB_PAD];
extern ccs::bus_data_prop_t props_buf[];
extern char val_buf[][CWB_VAL_SZ + CWB_PAD];
extern int num_props;
extern int io_calls;
extern char io_json[];
extern char last_status[];
void set_ctrl(bool present);
void construct_input(const test_case_t *tc);
ccs::bus_error_t invoke(const char *method, const ccs::bus_data_prop_t *in, ccs::bus_data_prop_t **out);

/* ---- scaffolding classes, usings, macros moved from cmd_steerwifibh.cpp ---- */
using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_general; using ccs::bus_error_invalid_input;
using ccs::bus_error_out_of_resources; using ccs::bus_error_invalid_method; using ccs::bus_error_invalid_namespace;
using ccs::bus_data_type_t; using ccs::bus_data_type_string;
using ccs::bus_data_type_int8; using ccs::bus_data_type_uint8; using ccs::bus_data_type_int16;
using ccs::bus_data_type_uint16; using ccs::bus_data_type_int32; using ccs::bus_data_type_uint32;
using ccs::raw_data_t; using ccs::bus_data_prop_t;

#define TR181_BSSID_MAX_LEN        32
#define TR181_REQMODE_MAX_LEN      24
#include <strings.h>
#include <limits.h>
#ifndef MAX_INSTANCE_LEN
#define MAX_INSTANCE_LEN 32
#endif
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
#define EM_IO_BUFF_SZ 4096
#undef GLOBAL_NET_ID
#define GLOBAL_NET_ID "OneWifiMesh"
typedef char mac_addr_str_t[18];
typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef enum { em_bus_event_type_steer_sta = 1 } em_bus_event_type_t;
typedef enum { em_steering_req_mode_opportunity = 0, em_steering_req_mode_mandate = 1 } em_steering_req_mode_t;

/* --- scaffolding: dm / controller stand-ins --- */
extern int io_calls;
extern char io_json[EM_IO_BUFF_SZ + 64];
extern unsigned int io_len;
extern char last_status[16];
typedef struct { struct { unsigned char mac[6]; } intf; } em_device_info_t;
typedef struct { struct { unsigned char ruid[6]; } id; } em_radio_info_t;
typedef struct { struct { unsigned char mac[6]; } bssid; } em_bss_info_t;
typedef struct { unsigned char id[6]; bool associated; } em_sta_info_t;
class dm_sta_t { public: em_sta_info_t info; em_sta_info_t *get_sta_info() { return &info; } };
class dm_bss_t { public: em_bss_info_t info; em_bss_info_t *get_bss_info() { return &info; } };
class dm_device_t { public: em_device_info_t info; em_device_info_t *get_device_info() { return &info; } };
class dm_radio_t  { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };
class dm_easy_mesh_t {
public:
    dm_device_t device; dm_radio_t radio; dm_bss_t bss; dm_sta_t sta;
    dm_device_t *get_device() { return &device; }
    static void macbytes_to_string(unsigned char *mac, char *string)
    { snprintf(string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); }
};
class dm_easy_mesh_ctrl_t {
public:
    dm_easy_mesh_t dm;
    dm_easy_mesh_ctrl_t() {
        unsigned char d[6] = {2,0,0,0,0,1}, r[6] = {2,0,0,0,0x10,1};
        memcpy(dm.device.info.intf.mac, d, 6); memcpy(dm.radio.info.id.ruid, r, 6);
        unsigned char b[6] = {2,0,0,0,0x10,0x11}; memcpy(dm.bss.info.bssid.mac, b, 6);
        unsigned char s[6] = {2,0,0,0,0x10,0x21}; memcpy(dm.sta.info.id, s, 6); dm.sta.info.associated = true;
    }
    static bool match(unsigned char *mac, char *instance, bool is_num)
    {   char str[18];
        if (is_num) return atoi(instance) == 1;
        dm_easy_mesh_t::macbytes_to_string(mac, str);
        return strcmp(instance, str) == 0;
    }
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num) { return match(dm.device.info.intf.mac, instance, is_num) ? &dm : NULL; }
    dm_bss_t *get_dm_bss(dm_easy_mesh_t *d, em_radio_info_t *r, char *instance, bool is_num) { (void)r; return match(d->bss.info.bssid.mac, instance, is_num) ? &d->bss : NULL; }
    dm_sta_t *get_dm_sta(dm_easy_mesh_t *d, em_bss_info_t *b, char *instance, bool is_num) { (void)b; return match(d->sta.info.id, instance, is_num) ? &d->sta : NULL; }
    dm_radio_t *get_dm_radio(dm_easy_mesh_t *d, char *instance, bool is_num) { return match(d->radio.info.id.ruid, instance, is_num) ? &d->radio : NULL; }
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
    static bus_error_t cmd_steerwifibh(const char *method_name, const bus_data_prop_t *input_params, bus_data_prop_t **output_params, void *async_handle);
};

class tr_181_t {
public:
    static bool tr181_copy_prop_string(const bus_data_prop_t *prop, char *dst, size_t dst_len);
    static bool tr181_get_prop_int(const bus_data_prop_t *prop, int *value);
    static bool tr181_get_prop_bool(const bus_data_prop_t *prop, bool *value);
    static bus_data_prop_t *tr181_set_status_output_prop(const char *status)
    {   /* stand-in for tr181_alloc_string_prop("Status", status) */
        bus_data_prop_t *p = (bus_data_prop_t *)calloc(1, sizeof(*p));
        snprintf(last_status, sizeof(last_status), "%s", status);
        p->value.data_type = bus_data_type_string;
        p->value.raw_data.bytes = strdup(status);
        return p;
    }
};
struct util { static std::vector<std::string> split_by_delim(const std::string& s, char delimiter); };

extern em_ctrl_t *ctrl_instance_ptr;
}
void run_all_tests_cmd_steerwifibh(void);
#endif
