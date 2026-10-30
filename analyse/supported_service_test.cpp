#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>
int test_get_supported_service(void)
{
    bool ret = false;
    em_supported_service_t svc{};

    printf("packet_len = %d\n", packet_len);

    __asan_poison_memory_region(&packet[packet_len],
                                4096 - packet_len);

    em_msg_t obj;

    obj.set_m1(packet + 22, packet_len - 22);

    ret = obj.get_supported_service(&svc);

    __asan_unpoison_memory_region(&packet[packet_len],
                                  4096 - packet_len);

    return ret ? 0 : -1;
}

void run_all_tests_get_supported_service()
{
    for (int i = 0; get_supported_service_suite[i].test_name != NULL; i++) {
        pkt_test_case_t* test = &get_supported_service_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_common_headers(test->pcap_file);

        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        int ret = construct_pcap_and_test(test_get_supported_service);

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
