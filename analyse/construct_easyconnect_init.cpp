/*
 * TEST CASES / CONSTRUCTOR: construct_easyconnect_init
 *
 * app is a wifi_app_t at eci_app_buf (runner poisons past the struct); its
 * ->ctrl points at eci_ctrl_buf (runner poisons past the ctrl stub). The
 * ec_* globals steer the stubbed app_init / bus_reg_data_element_fn return
 * codes.
 *
 * Cases: both_ok (app_init + reg succeed -> RETURN_OK, 2 elems registered),
 * app_init_fail (-> RETURN_ERR, reg never called),
 * bus_reg_fail (app_init ok, reg fails -> RETURN_ERR, reg called once).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int  ec_app_init_ret, ec_app_init_calls;
int  ec_bus_reg_ret,  ec_bus_reg_calls, ec_bus_reg_n;
char ec_elem0_name[128], ec_elem1_name[128];
void *ec_elem1_set_cb;

alignas(16) char eci_app_buf[sizeof(wifi_app_t) + EC_PAD];
alignas(16) char eci_ctrl_buf[256 + EC_PAD];

easyconnect_init_test_case_t easyconnect_init_suite[] = {
    /* name            app_init_ret bus_reg_ret want_ret want_bus_calls */
    { "both_ok",         0,          0,          0,       1 },
    { "app_init_fail",  -1,          0,         -1,       0 },
    { "bus_reg_fail",    0,          1,         -1,       1 },
    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_easyconnect_init_input(const easyconnect_init_test_case_t *tc)
{
    memset(eci_app_buf, 0, sizeof(eci_app_buf));
    memset(eci_ctrl_buf, 0, sizeof(eci_ctrl_buf));
    wifi_app_t *app = (wifi_app_t *)eci_app_buf;
    app->ctrl = (decltype(app->ctrl))eci_ctrl_buf;   /* so &app->ctrl->handle is valid */

    ec_app_init_ret  = tc->app_init_ret;
    ec_bus_reg_ret   = tc->bus_reg_ret;
    ec_app_init_calls = 0;
    ec_bus_reg_calls  = 0;
    ec_bus_reg_n      = 0;
    ec_elem0_name[0]  = 0;
    ec_elem1_name[0]  = 0;
    ec_elem1_set_cb   = NULL;
}
