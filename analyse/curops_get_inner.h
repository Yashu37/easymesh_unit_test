/* curops_get_inner harness types (namespace cog). Kept out of common.h so `make` stays incremental. */
#ifndef CUROPS_GET_INNER_H
#define CUROPS_GET_INNER_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "common.h"

namespace cog {
#define COG_LEFT 16          /* poisoned bytes in front of event_name */
#define COG_NAME_SZ 300
#define COG_PAD 64
#define COG_GUARD 256        /* bytes before / after dm->m_radio[] (stand for the neighbouring members), poisoned by the runner */
#define COG_MAXOC 8

using ccs::bus_error_t;
using ccs::bus_error_success; using ccs::bus_error_invalid_input; using ccs::bus_error_invalid_namespace;
using ccs::raw_data_t;

#define MAX_INSTANCE_LEN 32
#define MAX_TIME_STRLEN 24
#define MAX_ZONE_STRLEN 8
#define MAX_TIMESTAMP_STRLEN 64
#define DATAELEMS_NETWORK "Device.WiFi.DataElements.Network."
#define EM_MAX_BANDS 3
typedef struct { int unused; } bus_user_data_t;
typedef enum { em_op_class_type_none = 0, em_op_class_type_current = 1, em_op_class_type_capability = 2 } em_op_class_type_t;
typedef struct { struct { unsigned char ruid[6]; em_op_class_type_t type; } id; int op_class; int channel; int tx_power; } em_op_class_info_t;
class dm_op_class_t { public: em_op_class_info_t info; em_op_class_info_t *get_op_class_info() { return &info; } };
typedef struct { struct { unsigned char ruid[6]; } id; } em_radio_info_t;
class dm_radio_t { public: em_radio_info_t info; em_radio_info_t *get_radio_info() { return &info; } };
class dm_easy_mesh_t {
public:
    unsigned char before[COG_GUARD];    /* stands for the members in front of m_radio[] */
    dm_radio_t m_radio[EM_MAX_BANDS];
    unsigned char after[COG_GUARD];     /* stands for the members after m_radio[] */
    dm_op_class_t *ocs[COG_MAXOC];
    unsigned int noc;
    unsigned int get_num_op_class() { return noc; }
    dm_op_class_t *get_op_class(unsigned int i) { return i < noc ? ocs[i] : NULL; }
};
extern dm_easy_mesh_t *g_dm;

typedef struct {
    unsigned char radio;  /* 1..3: radio whose RUID is used (02:00:00:00:00:radio) */
    int type;             /* 1 current, 2 capability (not current), 0 = NULL entry in the list */
    int op_class, channel, tx_power;
} oc_spec_t;

typedef struct {
    const char *test_name;
    const char *event;     /* NULL passes a NULL event_name */
    bool no_pdata;
    bool no_dm;            /* no device is registered */
    int expect_rc;         /* 0 success, 2 invalid_input, 25 invalid_namespace */
    const char *expect_val;/* recorded raw_data_set value, "TIMESTAMP" = format check, NULL = unchecked */
    bool crash;
} test_case_t;

extern test_case_t suite[];
extern char name_store[COG_LEFT + COG_NAME_SZ + COG_PAD];
extern int g_rc;
extern int g_nset;
extern char g_val[64];
void construct_input(const test_case_t *tc);
int invoke(const char *event, bool no_pdata);
void teardown(void);
}
void run_all_tests_curops_get_inner(void);
#endif
