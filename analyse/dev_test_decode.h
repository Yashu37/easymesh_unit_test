/* dev_test_decode harness types (namespace dtd). Own header, kept out of common.h so `make` stays incremental. */
#ifndef DEV_TEST_DECODE_H
#define DEV_TEST_DECODE_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace dtd {
#define DTD_EVT_SZ 8192
#define DTD_MAXEM 4

/* verbatim from inc/em_base.h */
typedef enum { em_dev_test_type_ssid, em_dev_test_type_channel, em_dev_test_type_max } em_dev_test_type;
typedef enum { em_dev_test_status_inprogess, em_dev_test_status_idle, em_dev_test_status_complete, em_dev_test_status_failed, em_dev_test_status_max } em_dev_test_status;
typedef struct {
    int num_iteration[em_dev_test_type_max];
    em_dev_test_type test_type[em_dev_test_type_max];
    int enabled[em_dev_test_type_max];
    int num_of_iteration_completed[em_dev_test_type_max];
    int test_inprogress[em_dev_test_type_max];
    em_dev_test_status test_status[em_dev_test_type_max];
    em_haul_type_t haul_type;
    em_freq_band_t freq_band;
} em_dev_test_info;

typedef struct { char name[64]; char buff[0]; } __attribute__((__packed__)) em_subdoc_info_t;
typedef struct { int unused; } em_cmd_params_t;
typedef struct {
    em_cmd_params_t params;
    unsigned char guard[32];           /* members after params (runner poisons it) */
    union { em_subdoc_info_t subdoc; } u;
} em_bus_event_t;
typedef struct { int unused; } hash_map_t;

/* stand-ins for em_t (handler body is in dev_test_decode.cpp) */
class em_t {
public:
    em_state_t state;
    int devtest;                       /* -1 untouched, 0 / 1 = set_devteststatus(false / true) */
    em_state_t get_state() { return state; }
    void set_devteststatus(bool enable) { devtest = enable ? 1 : 0; }
};
class em_dev_test_t {
public:
    em_dev_test_info dev_test_info;
    void decode(em_subdoc_info_t *subdoc, hash_map_t *m_em_map, const char *str);
};
void *hash_map_get_first(hash_map_t *m);
void *hash_map_get_next(hash_map_t *m, void *cur);

typedef struct {
    const char *test_name;
    const char *json;      /* the subdoc text */
    const char *expect;    /* summary of dev_test_info that must be produced ("" = unchanged / rejected) */
    const char *ems;       /* em entries: one letter each, C configured, U unconfigured, M misconfigured; NULL / "" = none */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char evt_buf[DTD_EVT_SZ];
extern em_t g_em[DTD_MAXEM];
extern int g_nem;
extern hash_map_t g_map;
extern em_dev_test_info g_out;
extern char g_sum[512];
extern const char *g_default;
void construct_input(const test_case_t *tc);
void invoke(void);
void summarise(void);
void teardown(void);
}
void run_all_tests_dev_test_decode(void);
#endif
