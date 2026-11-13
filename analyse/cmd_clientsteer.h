/* cmd_clientsteer harness types (namespace ccl). Kept out of common.h so `make` stays incremental. */
#ifndef CMD_CHANNELSCAN_H
#define CMD_CHANNELSCAN_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "common.h"

namespace ccl {
#define CCL_MAXP 10
#define CCL_VAL_SZ 192
#define CCL_PAD 64

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
    prop_spec_t props[CCL_MAXP];
    int expect_rc;
    const char *json_has; /* substring expected in the JSON sent to io_process (accept cases) */
    bool crash;           /* expected to abort: runs last, unforked unless FORK_CRASH=1 */
} test_case_t;
extern test_case_t suite[];
extern char method_buf[256 + CCL_PAD];
extern ccs::bus_data_prop_t props_buf[];
extern char val_buf[][CCL_VAL_SZ + CCL_PAD];
extern int num_props;
extern int io_calls;
extern char io_json[];
extern char last_status[];
void set_ctrl(bool present);
void construct_input(const test_case_t *tc);
ccs::bus_error_t invoke(const char *method, const ccs::bus_data_prop_t *in, ccs::bus_data_prop_t **out);
}
void run_all_tests_cmd_clientsteer(void);
#endif
