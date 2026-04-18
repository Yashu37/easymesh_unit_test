#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

class test_em_channel_t : public em_channel_t {
public:
    dm_easy_mesh_t dm;   // 🔥 local data model

    dm_easy_mesh_t *get_data_model() override {
        return &dm;      // ✔ return valid object
    }
};

int test_handle_channel_scan_rprt(void)
{
        int ret;

        printf("packet_len = %d\n", packet_len);
        printf("PCAP file 'output.pcap' created successfully\n");

        __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);

        test_em_channel_t obj;
        ret = obj.handle_channel_scan_rprt(packet, packet_len);

	// 🔥 ADD THIS LINE
	obj.get_data_model()->clear_scan_results();

        __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);

        return ret;
}


void run_all_tests_handle_channel_scan_rprt()
{
        for (int i = 0; handle_channel_scan_rprt_suite[i].test_name != NULL; i++) {

                pkt_test_case_t* test = &handle_channel_scan_rprt_suite[i];

                printf("--- Running Test: %s ---\n", test->test_name);

                // 1. Setup headers using pcap file
                construct_common_headers(test->pcap_file);

                // 2. Call TLV constructor
                if (test->tlv_func != NULL) {
                        test->tlv_func();
                }

                // 3. Execute test
                int ret = construct_pcap_and_test(test_handle_channel_scan_rprt);

                // 4. Validate result
                if (ret == test->expected_result) {
                        printf("================== %s: \033[32mPASS\033[0m ==============\n",
                                        test->test_name);
                } else {
                        printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                                        test->test_name, test->expected_result, ret);
                }

                printf("------------------------------------------------------------------------------------------------------------------------------\n");
        }
}


