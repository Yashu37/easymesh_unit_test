/*
 * TEST CASES / CONSTRUCTOR: construct_levl_csi_status_publish
 * The mac lives in lcsp_mac_buf (runner poisons past its 6 bytes).
 * Cases: status_one, status_max (0xFFFFFFFF -> printed as %d), publish_fail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

unsigned char lcsp_mac_buf[6 + LCSP_PAD];
char lcsp_pub_name[256], lcsp_pub_value[256];
int lcsp_publish_calls, lcsp_publish_fail;

lv_lcsp_test_case_t levl_csi_status_publish_suite[] = {
    /* name           mac                                  status      fail ret want_value */
    { "status_one",   {0xaa,0xbb,0xcc,0xdd,0xee,0xff},     1,          0,   0, "aa:bb:cc:dd:ee:ff;1" },
    { "status_max",   {0xff,0xff,0xff,0xff,0xff,0xff},     0xFFFFFFFFu, 0,  0, "ff:ff:ff:ff:ff:ff;-1" },
    { "publish_fail", {0x01,0x02,0x03,0x04,0x05,0x06},     2,          1,  -1, "01:02:03:04:05:06;2" },
    { NULL, {0}, 0, 0, 0, NULL }  /* sentinel */
};

void construct_levl_csi_status_publish_input(const lv_lcsp_test_case_t *tc)
{
    memset(lcsp_mac_buf, 0, sizeof(lcsp_mac_buf));
    memcpy(lcsp_mac_buf, tc->mac, 6);
    memset(lcsp_pub_name, 0, sizeof(lcsp_pub_name));
    memset(lcsp_pub_value, 0, sizeof(lcsp_pub_value));
    lcsp_publish_calls = 0;
    lcsp_publish_fail = tc->publish_fail;
}
