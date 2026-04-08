#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>
/*
int test_get_first_tlv(void)//change the name
{
        //int ret;
	em_tlv_t* ret = NULL;

        printf("packet_len = %d\n", packet_len);
        printf("PCAP file 'output.pcap' created successfully\n");
        __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);
        em_msg_t obj;
       // ret = obj.get_first_tlv(packet, packet_len);
	ret = obj.get_first_tlv(reinterpret_cast<em_tlv_t*>(packet), packet_len);
        __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);
       // return ret;
       // If ret is NOT NULL, the test passed (return 0 or 1 based on your framework)
       // If ret IS NULL, the test failed (return -1)
	return (ret != NULL) ? 0 : -1;
}
*/

int test_get_first_tlv(void)
{
    em_tlv_t* ret = NULL;

    printf("packet_len = %d\n", packet_len);
    printf("PCAP file 'output.pcap' created successfully\n");

    __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);

    em_msg_t obj;

    ret = obj.get_first_tlv(
            reinterpret_cast<em_tlv_t*>(packet + 22),
            packet_len - 22
    );

    __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);

    return (ret != NULL) ? 0 : -1;
}


void run_all_tests_get_first_tlv() {
    for (int i = 0; get_first_tlv_suite[i].test_name != NULL; i++) {
        pkt_test_case_t* test = &get_first_tlv_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        // 1. Setup the common headers using the pcap filename from your struct
        construct_common_headers(test->pcap_file);

        // 2. Call the constructor function using your member name 'tlv_func'
        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        // 3. Run the test and get the actual return value
        int ret = construct_pcap_and_test(test_get_first_tlv);

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

