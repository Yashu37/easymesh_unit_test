#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

class test_em_configuration_t : public em_configuration_t {
public:
        dm_easy_mesh_t dm;

        dm_easy_mesh_t *get_data_model() override {
                return &dm;
        }

        int test_handle_ap_operational_bss(unsigned char *buff, unsigned int len)
        {
                return handle_ap_operational_bss(buff, len);
        }
};

int test_handle_ap_operational_bss(void)
{
    int ret;

    printf("packet_len = %d\n", packet_len);
    printf("PCAP file 'output.pcap' created successfully\n");

    __asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);

    test_em_configuration_t obj;

    // Read AP Operational BSS TLV length
    uint16_t tlv_len;
    memcpy(&tlv_len, packet + 23, sizeof(tlv_len));
    tlv_len = ntohs(tlv_len);

    // Pass TLV payload and its declared length
    ret = obj.test_handle_ap_operational_bss(
            packet + 25,
            tlv_len);

    __asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);

    return ret;
}

void run_all_tests_handle_ap_operational_bss(void)
{
        for (int i = 0; handle_ap_operational_bss_suite[i].test_name != NULL; i++) {
                pkt_test_case_t* test = &handle_ap_operational_bss_suite[i];

                printf("--- Running Test: %s ---\n", test->test_name);

                construct_common_headers(test->pcap_file);

                if (test->tlv_func != NULL) {
                        test->tlv_func();
                }

                int ret = construct_pcap_and_test(test_handle_ap_operational_bss);

                if (ret == test->expected_result) {
                        printf("================== %s: \033[32mPASS\033[0m ==============\n",
                                test->test_name);
                } else {
                        printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                                test->test_name,
                                test->expected_result,
                                ret);
                }

                printf("------------------------------------------------------------------------------------------------------------------------------\n");
        }
}
