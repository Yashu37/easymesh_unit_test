/* radio_get_inner harness types (namespace rgi). Own header, kept out of common.h so `make` stays incremental. */
#ifndef RADIO_GET_INNER_H
#define RADIO_GET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <type_traits>
#include "common.h"

namespace rgi {
#define RGI_LEFT 16          /* poisoned bytes in front of event_name */
#define RGI_NAME_SZ 300
#define RGI_PAD 64
#define RGI_GUARD 256        /* bytes before / after dm->m_radio[] and after dm->m_op_class[] (neighbouring members), poisoned by the runner */
#define RGI_VAL_SZ 256

using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input; using ccs::bus_error_invalid_namespace;
using ccs::raw_data_t;

#ifndef MAX_INSTANCE_LEN
#define MAX_INSTANCE_LEN 32
#endif
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
typedef struct { int unused; } bus_user_data_t;

typedef enum { em_op_class_type_none = 0, em_op_class_type_current = 1, em_op_class_type_capability = 2 } em_op_class_type_t;
typedef struct { struct { unsigned char ruid[6]; em_op_class_type_t type; } id; int op_class; int channel; int tx_power; } em_op_class_info_t;
class dm_op_class_t { public: em_op_class_info_t info; em_op_class_info_t *get_op_class_info() { return &info; } };

/* em_radio_info_t cut down to the members radio_get_inner reads. chip_vendor is em_long_string_t (128);
 * after_chip stands for the members that follow it in the real struct (ap_metrics_wifi6, ...) and is poisoned by the runner. */
typedef struct {
    struct { unsigned char ruid[6]; } id;
    bool enabled;
    unsigned int number_of_bss;
    int noise;
    unsigned char transmit;
    unsigned char receive_self;
    unsigned char receive_other;
    unsigned short utilization;
    char chip_vendor[128];
    unsigned char after_chip[RGI_GUARD];
    unsigned char radio_temp;
} em_radio_info_t;
class dm_radio_t { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };

class dm_easy_mesh_t {
public:
    unsigned char before[RGI_GUARD];              /* stands for the members in front of m_radio[] */
    dm_radio_t m_radio[EM_MAX_BANDS];
    unsigned char between[RGI_GUARD];             /* stands for the members between m_radio[] and m_num_opclass */
    unsigned int m_num_opclass;                   /* raw value, get_num_op_class() does not clamp it (develop @ 1ba9529) */
    dm_op_class_t m_op_class[EM_MAX_OPCLASS];
    unsigned char after[RGI_GUARD];               /* stands for the members after m_op_class[] */
    unsigned int get_num_op_class() { return m_num_opclass; }
    dm_op_class_t *get_op_class(unsigned int index) { return &m_op_class[index]; }
};
extern dm_easy_mesh_t *g_dm;

extern char g_val[RGI_VAL_SZ];
extern int g_nset;

class em_crypto_t {
public:
    static std::string base64_encode(const uint8_t *in, size_t len)
    {   static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string o; size_t i = 0;
        for (; i + 2 < len; i += 3) { uint32_t v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
            o += t[v >> 18]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += t[v & 63]; }
        if (len - i == 1) { uint32_t v = in[i] << 16; o += t[v >> 18]; o += t[(v >> 12) & 63]; o += "=="; }
        else if (len - i == 2) { uint32_t v = (in[i] << 16) | (in[i+1] << 8); o += t[v >> 18]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += '='; }
        return o; }
};

/* stand-ins for the controller classes (handler body is in radio_get_inner.cpp) */
class dm_easy_mesh_ctrl_t {
public:
    const char* get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num);
    dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
    {   if (!g_dm) return NULL;
        if (is_num) return atoi(instance) == 1 ? g_dm : NULL;
        return strcmp(instance, "02:00:00:00:00:01") == 0 ? g_dm : NULL; }
    bus_error_t raw_data_set(raw_data_t *p, const char *v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%s", v); return bus_error_success; }
    template <typename T>
    typename std::enable_if<std::is_arithmetic<T>::value, bus_error_t>::type
    raw_data_set(raw_data_t *p, T v) { (void)p; g_nset++; snprintf(g_val, sizeof(g_val), "%lld", (long long)v); return bus_error_success; }
    bus_error_t radio_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
};
class em_ctrl_t {
public:
    dm_easy_mesh_ctrl_t m_data_model;
    static em_ctrl_t *get_em_ctrl_instance();
    dm_easy_mesh_ctrl_t *get_dm_ctrl() { return &m_data_model; }
};

typedef struct {
    const char *test_name;
    const char *event;      /* NULL passes a NULL event_name */
    bool no_pdata;
    bool no_dm;             /* no device is registered */
    int expect_rc;          /* 0 success, 2 invalid_input, 25 invalid_namespace */
    const char *expect_val; /* recorded raw_data_set value, NULL = unchecked */
    int variant;            /* 0 normal model, 1 chip_vendor not NUL terminated (128 'A'), 2 m_num_opclass = 100 (> 64) */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[RGI_LEFT + RGI_NAME_SZ + RGI_PAD];
extern int g_rc;
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_radio_get_inner(void);
#endif
