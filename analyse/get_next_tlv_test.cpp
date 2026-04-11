#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int test_get_next_tlv(void)
{
    em_tlv_t* ret = NULL;

    printf("packet_len = %d\n", packet_len);
    printf("PCAP file 'output.pcap' created successfully\n");

    __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);

    em_msg_t obj;

    // Step 1: directly point to first TLV (skip 22 bytes)
    em_tlv_t *current_tlv = reinterpret_cast<em_tlv_t*>(packet + 22);

    // Step 2: get next TLV
    ret = obj.get_next_tlv(
            current_tlv,
            reinterpret_cast<em_tlv_t*>(packet + 22),
            packet_len - 22
    );

    __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);

    return (ret != NULL) ? 0 : -1;
}


void run_all_tests_get_next_tlv() {
    for (int i = 0; get_next_tlv_suite[i].test_name != NULL; i++) {
        pkt_test_case_t* test = &get_next_tlv_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        // 1. Setup the common headers using the pcap filename from your struct
        construct_common_headers(test->pcap_file);

        // 2. Call the constructor function using your member name 'tlv_func'
        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        // 3. Run the test and get the actual return value
        int ret = construct_pcap_and_test(test_get_next_tlv);

        // 4. Compare against your member name 'expected_result'
        if (ret == test->expected_result) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
                printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                                test->test_name, test->expected_result, ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}

