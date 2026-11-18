/*
 * cmd_channelscan() regression tests for PR #877 (RDKBDEV-3645), to be added to upstream
 * tests/test_l1_em_ctrl.cpp. Copilot asked for: a NULL method name, "X.ChannelScanRequest()",
 * missing Device / Radio instances (with #871 applied), a valid path, the error codes and the
 * "Failure" status, a NULL output_params on the rejection paths, all under AddressSanitizer.
 *
 * Built with the harness copy of em_ctrl_t::cmd_channelscan() (cmd_channelscan.cpp, fix markers) -
 * see the gtest_em_ctrl_channelscan Makefile target. The harness controller holds one device 1 /
 * radio 1; the harness io_process stub records the JSON the handler sends, so the valid-path test
 * can check that exactly one request went out. Upstream the valid path needs a device and a radio
 * in the fixture's data model.
 *
 * The method name sits in a buffer whose bytes past the NUL are poisoned for the call, so a read
 * past the end of a short name is an ASan report (on the original handler the NULL / short-name /
 * missing-instance tests abort).
 */
#include <gtest/gtest.h>
#include <sanitizer/asan_interface.h>
#include <cstring>
#include <cstdlib>
#include "cmd_channelscan.h"

namespace {

const char *kNet = "Device.WiFi.DataElements.Network.";

/* runs cmd_channelscan with OpClass 115 + ChannelList "36"; method == NULL passes a NULL method_name */
ccs::bus_error_t run(const char *method, bool with_out, char *status_out = NULL)
{
    ccn::test_case_t tc;
    memset(&tc, 0, sizeof(tc));
    tc.method = method;
    tc.props[0] = {"OpClass", 1, NULL, 115, 0};
    tc.props[1] = {"ChannelList", 0, "36", 0, 0};
    ccn::construct_input(&tc);
    ccn::io_calls = 0;
    ccn::last_status[0] = '\0';
    size_t mlen = method ? strlen(ccn::method_buf) + 1 : 0;
    if (method) __asan_poison_memory_region(&ccn::method_buf[mlen], sizeof(ccn::method_buf) - mlen);
    ccs::bus_data_prop_t *out = NULL;
    ccs::bus_error_t rc = ccn::invoke(method ? ccn::method_buf : NULL, ccn::props_buf,
                                      with_out ? &out : NULL);
    if (method) __asan_unpoison_memory_region(&ccn::method_buf[mlen], sizeof(ccn::method_buf) - mlen);
    if (status_out) snprintf(status_out, 16, "%s", ccn::last_status);
    if (out) { free(out->value.raw_data.bytes); free(out); }
    return rc;
}

std::string path(const char *tail) { return std::string(kNet) + tail; }

} // namespace

/* NULL method name is rejected with invalid_input and the "Failure" status */
TEST(em_ctrl_t, cmd_channelscan_null_method_name)
{
    char status[16];
    EXPECT_EQ(run(NULL, true, status), ccs::bus_error_invalid_input);
    EXPECT_STREQ(status, "Failure");
    EXPECT_EQ(ccn::io_calls, 0);
}

/* method name shorter than the Network prefix must not be read past its terminator */
TEST(em_ctrl_t, cmd_channelscan_short_method_name)
{
    char status[16];
    EXPECT_EQ(run("X.ChannelScanRequest()", true, status), ccs::bus_error_invalid_input);
    EXPECT_STREQ(status, "Failure");
    EXPECT_EQ(ccn::io_calls, 0);
}

/* unknown method name is rejected with invalid_method */
TEST(em_ctrl_t, cmd_channelscan_wrong_method)
{
    char status[16];
    EXPECT_EQ(run(path("Device.1.Radio.1.Foo()").c_str(), true, status), ccs::bus_error_invalid_method);
    EXPECT_STREQ(status, "Failure");
}

/* path that stops before the Device instance (needs get_table_instance() hardening, #871) */
TEST(em_ctrl_t, cmd_channelscan_missing_device_instance)
{
    char status[16];
    EXPECT_EQ(run(path("ChannelScanRequest()").c_str(), true, status), ccs::bus_error_invalid_input);
    EXPECT_STREQ(status, "Failure");
    EXPECT_EQ(ccn::io_calls, 0);
}

/* path that stops before the Radio instance, device exists (needs #871) */
TEST(em_ctrl_t, cmd_channelscan_missing_radio_instance)
{
    char status[16];
    EXPECT_EQ(run(path("Device.1.ChannelScanRequest()").c_str(), true, status), ccs::bus_error_invalid_input);
    EXPECT_STREQ(status, "Failure");
    EXPECT_EQ(ccn::io_calls, 0);
}

/* well-formed path, but no such device / radio */
TEST(em_ctrl_t, cmd_channelscan_device_and_radio_not_found)
{
    char status[16];
    EXPECT_EQ(run(path("Device.9.Radio.1.ChannelScanRequest()").c_str(), true, status), ccs::bus_error_invalid_namespace);
    EXPECT_STREQ(status, "Failure");
    EXPECT_EQ(run(path("Device.1.Radio.9.ChannelScanRequest()").c_str(), true, status), ccs::bus_error_invalid_namespace);
    EXPECT_STREQ(status, "Failure");
}

/* a NULL output_params must not be written on any rejection path */
TEST(em_ctrl_t, cmd_channelscan_null_output_params_on_rejection)
{
    EXPECT_EQ(run(NULL, false), ccs::bus_error_invalid_input);
    EXPECT_EQ(run("X.ChannelScanRequest()", false), ccs::bus_error_invalid_input);
    EXPECT_EQ(run(path("Device.1.Radio.1.Foo()").c_str(), false), ccs::bus_error_invalid_method);
    EXPECT_EQ(run(path("ChannelScanRequest()").c_str(), false), ccs::bus_error_invalid_input);
    EXPECT_EQ(run(path("Device.1.ChannelScanRequest()").c_str(), false), ccs::bus_error_invalid_input);
    EXPECT_EQ(run(path("Device.9.Radio.1.ChannelScanRequest()").c_str(), false), ccs::bus_error_invalid_namespace);
}

/* valid path: accepted, one request sent, status Success */
TEST(em_ctrl_t, cmd_channelscan_valid_path)
{
    char status[16];
    EXPECT_EQ(run(path("Device.1.Radio.1.ChannelScanRequest()").c_str(), true, status), ccs::bus_error_success);
    EXPECT_STREQ(status, "Success");
    EXPECT_EQ(ccn::io_calls, 1);
    EXPECT_NE(strstr(ccn::io_json, "\"Class\":115"), nullptr);
}
