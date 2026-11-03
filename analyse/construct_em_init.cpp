/*
 * TEST CASES / CONSTRUCTOR: construct_em_init
 *
 * app is a wifi_app_t at emi_app_buf; its ->ctrl points at emi_appctrl_buf so
 * &app->ctrl->handle is valid (&app->handle is inline). The emi_* globals steer
 * the stubbed app_init / bus_open_fn / bus_reg_data_element_fn.
 *
 * Cases: success (all OK -> RETURN_OK, 12 elements registered, cache init'd),
 * app_init_fail (-> RETURN_ERR, bus not opened), bus_open_fail (-> RETURN_ERR),
 * bus_reg_fail (-> bus_error_general, reg attempted).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char emi_app_buf[sizeof(wifi_app_t) + EMI_PAD];
alignas(16) char emi_appctrl_buf[512];
int  emi_app_init_ret, emi_bus_open_fail, emi_bus_reg_fail;
int  emi_reg_calls, emi_reg_num, emi_cache_init_calls;
char emi_elem0_name[128];

em_emi_test_case_t em_init_suite[] = {
    /* name           app_init_ret bus_open_fail bus_reg_fail want_ret */
    { "success",         0,         0,            0,          0 },
    { "app_init_fail",  -1,         0,            0,         -1 },
    { "bus_open_fail",   0,         1,            0,         -1 },
    { "bus_reg_fail",    0,         0,            1,          1 },  /* returns bus_error_general */
    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_init_input(const em_emi_test_case_t *tc)
{
    memset(emi_app_buf, 0, sizeof(emi_app_buf));
    memset(emi_appctrl_buf, 0, sizeof(emi_appctrl_buf));
    wifi_app_t *app = (wifi_app_t *)emi_app_buf;
    app->ctrl = (decltype(app->ctrl))emi_appctrl_buf;

    emi_app_init_ret   = tc->app_init_ret;
    emi_bus_open_fail  = tc->bus_open_fail;
    emi_bus_reg_fail   = tc->bus_reg_fail;
    emi_reg_calls = 0;
    emi_reg_num = 0;
    emi_cache_init_calls = 0;
    emi_elem0_name[0] = 0;
}
