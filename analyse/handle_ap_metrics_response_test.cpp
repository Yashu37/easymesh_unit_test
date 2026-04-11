#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>


class test_em_metrics_t : public em_metrics_t {
public:
    dm_easy_mesh_t *get_data_model() override {
        static dm_easy_mesh_t dm;
        return &dm;
    }

    em_profile_type_t get_profile_type() override {
        return em_profile_type_1;
    }
};

int test_handle_ap_metrics_response(void)
{
    int ret;

    printf("packet_len = %d\n", packet_len);
    printf("PCAP file 'output.pcap' created successfully\n");

    __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);

    test_em_metrics_t obj;
    ret = obj.handle_ap_metrics_response(packet, packet_len);

    __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);

    return ret;
}

void run_all_tests_handle_ap_metrics_response()
{
    for (int i = 0; handle_ap_metrics_response_suite[i].test_name != NULL; i++) {

        pkt_test_case_t* test = &handle_ap_metrics_response_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        // 1. Setup headers using pcap file
        construct_common_headers(test->pcap_file);

        // 2. Call TLV constructor
        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        // 3. Execute test
        int ret = construct_pcap_and_test(test_handle_ap_metrics_response);

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
