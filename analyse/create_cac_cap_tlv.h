/* create_cac_cap_tlv harness types (namespace ccc). Own header, kept out of common.h so `make` stays incremental. */
#ifndef CREATE_CAC_CAP_TLV_H
#define CREATE_CAC_CAP_TLV_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

namespace ccc {
#define CCC_GUARD 256
#define CCC_OUT_SZ 11000        /* above the largest valid output: 3 + 3 radios * 3483 = 10452 */
#define CCC_OUT_LEFT 64
#define EM_MAX_CAC_METHODS 4
#define EM_MAX_CAC_CHANS_PER_CLASS 16
#ifndef EM_MAX_OP_CLASS
#define EM_MAX_OP_CLASS 48
#endif
typedef unsigned char mac_address_t[6];
enum { em_freq_band_24 = 0, em_freq_band_5 = 1 };
typedef char em_tiny_string_t[4];

/* structures copied from inc/em_base.h */
typedef struct { unsigned char op_class; unsigned char num; unsigned char channels[EM_MAX_CAC_CHANS_PER_CLASS]; } __attribute__((__packed__)) em_cac_op_class_t;
typedef struct {
    unsigned char   cac_method;
    unsigned int    cac_duration : 24;
    unsigned char   op_classes_num;
    em_cac_op_class_t   op_classes[EM_MAX_OP_CLASS];
} __attribute__((__packed__)) em_cac_cap_method_t;
typedef struct {
    mac_address_t   ruid;
    unsigned char   cac_methods_num;
    em_cac_cap_method_t  cac_methods[EM_MAX_CAC_METHODS];
} __attribute__((__packed__)) em_cac_cap_radio_t;

/* em_radio_cap_info_t cut down: before_cac / after_cac stand for the members in front of and behind cac_cap (poisoned by the runner) */
typedef struct {
    unsigned char before_cac[CCC_GUARD];
    em_cac_cap_radio_t cac_cap;
    unsigned char after_cac[CCC_GUARD];
} em_radio_cap_info_t;
class dm_radio_cap_t { public: em_radio_cap_info_t info; em_radio_cap_info_t *get_radio_cap_info() { return &info; } };
typedef struct { int band; } em_radio_info_t_band;
class dm_radio_t { public: struct { int band; } m_radio_info; };
typedef struct { em_tiny_string_t country_code; } em_device_info_t;

class dm_easy_mesh_t {
public:
    unsigned int m_num_radios;
    dm_radio_t m_radio[EM_MAX_BANDS];
    dm_radio_cap_t m_radio_cap[EM_MAX_BANDS];
    em_device_info_t dev_info; bool has_dev_info;
    em_device_info_t *get_device_info() { return has_dev_info ? &dev_info : NULL; }
    unsigned int get_num_radios() { return (m_num_radios > EM_MAX_BANDS) ? EM_MAX_BANDS : m_num_radios; }
    dm_radio_t& get_radio_by_ref(unsigned int index) { return m_radio[index]; }
    dm_radio_cap_t *get_radio_cap(unsigned int index) { if (index >= EM_MAX_BANDS) return NULL; return &m_radio_cap[index]; }
};

class em_t {
public:
    dm_easy_mesh_t *m_dm;
    dm_easy_mesh_t *get_data_model() { return m_dm; }
    short create_cac_cap_tlv(unsigned char *buff);
};

typedef struct {
    const char *test_name;
    const char *country;    /* NULL = no device info, "" = empty country (both use the iw fallback) */
    unsigned int n_radios;
    int variant;
    int expect_len;         /* -1 = unchecked */
    const char *expect_hex; /* hex of the first bytes of the output, NULL = unchecked */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern unsigned char out_store[CCC_OUT_LEFT + CCC_OUT_SZ + CCC_GUARD];
extern dm_easy_mesh_t *g_dm;
extern short g_len;
void construct_input(const test_case_t *tc);
void invoke(void);
void teardown(void);
}
void run_all_tests_create_cac_cap_tlv(void);
#endif
