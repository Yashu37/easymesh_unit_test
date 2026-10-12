#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

class BeaconMetricsQueryTest : public em_metrics_t
{
public:
    dm_easy_mesh_t *get_data_model() override
    {
        return nullptr;
    }

    em_profile_type_t get_profile_type() override
    {
        return em_profile_type_2;
    }

    int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) override
    {
        return 0;
    }

    em_mgr_t *get_mgr() override
    {
        return nullptr;
    }
};

int test_handle_beacon_metrics_query(void)
{
    printf("packet_len = %d\n", packet_len);
    printf("PCAP file 'output.pcap' created successfully\n");

    __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);

    BeaconMetricsQueryTest obj;

    int ret = obj.handle_beacon_metrics_query(packet + 22, packet_len - 22);

    __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);

    return ret;
}

void run_all_tests_handle_beacon_metrics_query()
{
    for (int i = 0; handle_beacon_metrics_query_suite[i].test_name != NULL; i++) {
        pkt_test_case_t* test = &handle_beacon_metrics_query_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_common_headers(test->pcap_file);

        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        int ret = construct_pcap_and_test(test_handle_beacon_metrics_query);

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

