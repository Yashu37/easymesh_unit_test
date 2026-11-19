/* main of src/network_optimiser/test_tr181.cpp harness types (namespace tmo). Own header, kept out of common.h so `make` stays incremental. */
#ifndef TR181_MAIN_H
#define TR181_MAIN_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <vector>
#include <string>
#include "common.h"

namespace tmo {
#define TMO_GUARD 128
/* bus types exactly as in OneWifi source/platform/common/bus_common.h (only the parts test_tr181.cpp uses) */
#define BUS_MAX_NAME_LENGTH 128
#define BUS_METHOD_SET 1
typedef char bus_name_string_t[BUS_MAX_NAME_LENGTH];
typedef volatile int atomic_int;
typedef enum { bus_data_type_string = 12, bus_data_type_none = 20 } bus_data_type_t;
typedef enum bus_error { bus_error_success = 0, bus_error_general = 1, bus_error_invalid_input } bus_error_t;
typedef enum { bus_msg_none = 0 } bus_msg_sub_type_t;
typedef union raw_data_format { bool b; char c; unsigned char u; int8_t i8; uint8_t u8; int16_t i16; uint16_t u16; int32_t i32; uint32_t u32; int64_t i64; uint64_t u64; float f32; double f64; void *bytes; } raw_data_format_t;
typedef struct raw_data { bus_data_type_t data_type; raw_data_format_t raw_data; unsigned int raw_data_len; } raw_data_t;
typedef struct bus_data_prop {
    atomic_int ref_count; uint32_t name_len; bus_name_string_t name; bus_msg_sub_type_t msg_sub_type; bool is_data_set; bus_error_t status;
    raw_data_t value; struct bus_data_prop *next_data;
} bus_data_prop_t;
typedef struct bus_data_obj { uint32_t num_prop; bus_data_prop_t data_prop; } bus_data_obj_t;
typedef struct bus_handle { int opened; } bus_handle_t;
typedef void (*wifi_bus_method_async_resp_handler_t)(char const *method_name, bus_error_t error, bus_data_prop_t *params, void *user_data);
/* wifi_bus_desc_t cut down to the five entries main calls (signatures as in bus_common.h) */
typedef struct {
    bus_error_t (*bus_open_fn)(bus_handle_t *handle, char *component_name);
    bus_error_t (*bus_data_get_fn)(bus_handle_t *handle, char const *name, raw_data_t *data);
    void        (*bus_data_free_fn)(raw_data_t *data);
    bus_error_t (*bus_event_subs_fn)(bus_handle_t *handle, char const *event_name, void *cb, void *userData, int timeout);
    bus_error_t (*bus_method_async_invoke_fn)(bus_handle_t *handle, char const *param_name, char const *event_name, bus_data_obj_t *input_data,
                                              wifi_bus_method_async_resp_handler_t cb, uint32_t timeout);
} wifi_bus_desc_t;
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID   "Device.WiFi.DataElements.Network.ColocatedAgentID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID       "Device.WiFi.DataElements.Network.ControllerID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD        "Device.WiFi.DataElements.Network.SetSSID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY           "Device.WiFi.DataElements.Network.Topology"

void bus_init(bus_handle_t *handle);
wifi_bus_desc_t *get_bus_descriptor(void);

/* scripted stdin, bus stand-ins, tracked allocations (main's calloc / strdup / free go through them) */
extern int *g_script; extern int g_script_n; extern int g_script_pos; extern int g_eof_calls; extern int g_mode; extern bool g_hung; extern bool g_ended_by_stdin;
extern jmp_buf g_env;
extern int g_open_rc, g_get_rc, g_invoke_rc, g_subs_rc; extern bool g_null_desc;
extern std::string g_seq; extern std::string g_get_names; extern int g_free_calls, g_invoke_calls, g_subs_calls, g_inv_props, g_inv_ok, g_subs_ok;
extern std::vector<void *> g_live;
int tmo_scanf(const char *fmt, ...);
char *tmo_strdup(const char *s);
void *tmo_calloc(size_t n, size_t sz);
void tmo_free(void *p);

typedef struct {
    const char *test_name;
    int n_inputs; int in[8];
    int mode;                /* 0: the script ends like the user pressing Ctrl-C (the tool has no exit command), 1: stdin is closed (EOF) and stays closed */
    int open_rc, get_rc, invoke_rc, subs_rc;
    bool null_desc;
    const char *expect_seq;  /* calls made: O open, G controller get, g colocated get, I invoke, S subscribe */
    int expect_returned;     /* -1: main never returns (the script ends it), else main must return and the return value must be nonzero (1) / zero (0) */
    int expect_live;         /* tracked heap objects still allocated when the run ends, -1 unchecked */
    bool expect_no_hang;     /* stdin closed: main must stop within a few loop iterations */
    bool crash;
} test_case_t;
extern test_case_t suite[];
extern bool g_returned; extern int g_ret;
void construct_input(const test_case_t *tc);
void invoke(void);
void teardown(void);
}
void run_all_tests_tr181_main(void);
#endif
