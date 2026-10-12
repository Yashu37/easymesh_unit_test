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

int test_handle_unassoc_sta_link_metrics_tlv(void)
{
    int ret;

    printf("packet_len = %d\n", packet_len);
    printf("PCAP file 'output.pcap' created successfully\n");

    __asan_poison_memory_region(&packet[packet_len],
                                4096 - packet_len);

    test_em_metrics_t obj;

    // Find Unassociated STA Link Metrics Response TLV (Type = 0x98)
    unsigned int tlv_offset = 0;

    while (tlv_offset + 3 <= packet_len) {

        if (packet[tlv_offset] == 0x98) {
            break;
        }

        tlv_offset++;
    }

    // TLV header not found
    if (tlv_offset + 3 > packet_len) {
        __asan_unpoison_memory_region(&packet[packet_len],
                                      4096 - packet_len);
        return -1;
    }

    // Read TLV length
    unsigned int tlv_len =
        ntohs(*(uint16_t *)&packet[tlv_offset + 1]);

    // Check that complete TLV is present
    if (tlv_offset + 3 + tlv_len > packet_len) {
        __asan_unpoison_memory_region(&packet[packet_len],
                                      4096 - packet_len);
        return -1;
    }

    // Skip TLV Type(1) + TLV Length(2)
    unsigned char *tlv_value =
        &packet[tlv_offset + 3];

    printf("TLV offset = %u\n", tlv_offset);
    printf("TLV length = %u\n", tlv_len);

    /*
     * Save the number of stored metrics before processing.
     * For malformed TLVs, this value must not change.
     */
    dm_easy_mesh_t *dm = obj.get_data_model();

    unsigned int before_count =
        dm->m_num_unassoc_sta_metrics;

    // Call handler
    ret = obj.handle_unassoc_sta_link_metrics_tlv(
        tlv_value,
        tlv_len);

    /*
     * Check the number of stored metrics after processing.
     */
    unsigned int after_count =
        dm->m_num_unassoc_sta_metrics;

    printf("Metrics before = %u\n", before_count);
    printf("Metrics after  = %u\n", after_count);
    printf("Handler return = %d\n", ret);

    /*
     * For malformed TLVs:
     *  - handler must return -1
     *  - stored metrics must remain unchanged
     */
    if (ret == -1 && after_count != before_count) {

        printf("ERROR: Stored metrics changed for malformed TLV\n");

        __asan_unpoison_memory_region(&packet[packet_len],
                                      4096 - packet_len);

        return -1;
    }

    __asan_unpoison_memory_region(&packet[packet_len],
                                  4096 - packet_len);

    return ret;
}

void run_all_tests_handle_unassoc_sta_link_metrics_tlv()
{
    for (int i = 0;
         handle_unassoc_sta_link_metrics_suite[i].test_name != NULL;
         i++) {

        pkt_test_case_t *test =
            &handle_unassoc_sta_link_metrics_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        // 1. Setup headers using pcap file
        construct_common_headers(test->pcap_file);

        // 2. Call TLV constructor
        if (test->tlv_func != NULL) {
            test->tlv_func();
        }

        // 3. Execute test
        int ret =
            construct_pcap_and_test(test_handle_unassoc_sta_link_metrics_tlv);

        // 4. Validate result
        if (ret == test->expected_result) {
            printf("============ %s: \033[32mPASS\033[0m ============\n",
                   test->test_name);
        } else {
            printf("==== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) ====\n",
                   test->test_name,
                   test->expected_result,
                   ret);
        }

        printf("-----------------------------------------------------------------\n");
    }
}

