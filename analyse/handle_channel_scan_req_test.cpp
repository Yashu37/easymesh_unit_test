#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

class test_em_channel_t : public em_channel_t {
public:
    dm_easy_mesh_t *get_data_model() override {
        return nullptr;
    }

    em_mgr_t *get_mgr() override {
        return nullptr;
    }

    int send_frame(unsigned char *buff, unsigned int len,
                   bool multicast = false) override {
        return 0;
    }
};

int test_handle_channel_scan_req(void)
{
        int ret;

        printf("packet_len = %d\n", packet_len);
        printf("pcap file 'output.pcap' created successfully\n");

        __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);

        test_em_channel_t obj;

        ret = obj.handle_channel_scan_req(packet, packet_len);

        __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);

        return ret;
}

void run_all_tests_handle_channel_scan_req()
{
        for (int i = 0; handle_channel_scan_req_suite[i].test_name != NULL; i++) {

                pkt_test_case_t *test = &handle_channel_scan_req_suite[i];

                printf("\n--- Running Test: %s ---\n", test->test_name);

                // 1. Setup the common headers using the pcap filename from your struct
                construct_common_headers(test->pcap_file);

                // 2. Call the constructor function
                if (test->tlv_func != NULL) {
                        test->tlv_func();
                }

                // 3. Run the test and get the actual return value
                int ret = construct_pcap_and_test(test_handle_channel_scan_req);

                // 4. Compare against expected result
                if (ret == test->expected_result) {
                        printf("===== %s: \033[32mPASS\033[0m =====\n",
                               test->test_name);
                } else {
                        printf("===== %s: \033[31mFAIL\033[0m ===== (expected=%d, got=%d) =====\n",
                               test->test_name,
                               test->expected_result,
                               ret);
                }

                printf("--------------------------------------------------------------------------------\n");
        }
}

/* em_agent routes a Channel Scan Request with get_radio_id() before
 * handle_channel_scan_req() runs, so it must not read past the TLV. */
int test_get_radio_id_channel_scan_req(void)
{
        mac_address_t ruid;
        unsigned int header_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
        bool found;

        __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);

        found = em_msg_t(em_msg_type_channel_scan_req, em_profile_type_3, packet + header_len,
                         packet_len - header_len).get_radio_id(&ruid);

        __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);

        return (found == true) ? 0 : -1;
}

void run_all_tests_get_radio_id_channel_scan_req()
{
        for (int i = 0; get_radio_id_channel_scan_req_suite[i].test_name != NULL; i++) {

                pkt_test_case_t *test = &get_radio_id_channel_scan_req_suite[i];

                printf("\n--- Running Test: %s ---\n", test->test_name);

                construct_common_headers(test->pcap_file);

                if (test->tlv_func != NULL) {
                        test->tlv_func();
                }

                int ret = construct_pcap_and_test(test_get_radio_id_channel_scan_req);

                if (ret == test->expected_result) {
                        printf("===== %s: \033[32mPASS\033[0m =====\n",
                               test->test_name);
                } else {
                        printf("===== %s: \033[31mFAIL\033[0m ===== (expected=%d, got=%d) =====\n",
                               test->test_name,
                               test->expected_result,
                               ret);
                }

                printf("--------------------------------------------------------------------------------\n");
        }
}
