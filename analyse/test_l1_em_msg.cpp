/*
 * New get_radio_id() regression tests for PR #818, to be added to upstream
 * tests/test_l1_em_msg.cpp after TEST(em_msg_t, get_radio_id_empty_tlvs_buffer).
 * TLV_HEADER_SIZE and write_tlv() below are copied from that file; only the
 * TEST blocks are new.
 */
#include <gtest/gtest.h>
#include <stdio.h>
#include "em_msg.h"
#include <cstring>
#include <iostream>
#include <vector>

#define TLV_HEADER_SIZE 3u  // type (1) + len (2)

inline void write_tlv(unsigned char *buf, unsigned char type, const unsigned char *value, unsigned short len)
{
    buf[0] = type;
    uint16_t be_len = htons(len);
    memcpy(buf + 1, &be_len, 2);
    if (len > 0 && value)
        memcpy(buf + TLV_HEADER_SIZE, value, len);
}

/* ---- new tests start here ---- */
/**
 * @brief Verify that get_radio_id rejects a buffer holding only 1 byte of a TLV header
 *
 * The buffer is sized exactly to the data so any read past it is caught by ASan.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 184@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_radio_id on a 1-byte buffer holding only a TLV type | tlvBuffer = {em_tlv_type_radio_id}, len = 1 | API returns false without reading past the buffer | Should Fail |
 */
TEST(em_msg_t, get_radio_id_one_byte_tlv_header)
{
    std::cout << "Entering get_radio_id_one_byte_tlv_header" << std::endl;
    std::vector<unsigned char> tlvBuffer = {em_tlv_type_radio_id};
    em_msg_t msg(tlvBuffer.data(), static_cast<unsigned int>(tlvBuffer.size()));
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(&mac);
    EXPECT_FALSE(retVal);
    std::cout << "Exiting get_radio_id_one_byte_tlv_header" << std::endl;
}
/**
 * @brief Verify that get_radio_id rejects a buffer holding only 2 bytes of a TLV header
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 185@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_radio_id on a 2-byte buffer holding a TLV type and half of the length field | tlvBuffer = {em_tlv_type_radio_id, 0x00}, len = 2 | API returns false without reading past the buffer | Should Fail |
 */
TEST(em_msg_t, get_radio_id_two_byte_tlv_header)
{
    std::cout << "Entering get_radio_id_two_byte_tlv_header" << std::endl;
    std::vector<unsigned char> tlvBuffer = {em_tlv_type_radio_id, 0x00};
    em_msg_t msg(tlvBuffer.data(), static_cast<unsigned int>(tlvBuffer.size()));
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(&mac);
    EXPECT_FALSE(retVal);
    std::cout << "Exiting get_radio_id_two_byte_tlv_header" << std::endl;
}
/**
 * @brief Verify that get_radio_id rejects a TLV whose declared length exceeds the remaining buffer
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 186@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_radio_id on a radio_id TLV that declares 6 bytes but carries only 3 | tlvBuffer = radio_id TLV, len field = 6, value = {0x00,0x11,0x22} | API returns false without reading past the buffer | Should Fail |
 */
TEST(em_msg_t, get_radio_id_tlv_len_exceeds_buffer)
{
    std::cout << "Entering get_radio_id_tlv_len_exceeds_buffer" << std::endl;
    unsigned char partialMac[3] = {0x00, 0x11, 0x22};
    std::vector<unsigned char> tlvBuffer(TLV_HEADER_SIZE + sizeof(partialMac));
    write_tlv(tlvBuffer.data(), em_tlv_type_radio_id, partialMac, sizeof(partialMac));
    uint16_t declared_len = htons(sizeof(mac_address_t));
    memcpy(tlvBuffer.data() + 1, &declared_len, 2);
    em_msg_t msg(tlvBuffer.data(), static_cast<unsigned int>(tlvBuffer.size()));
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(&mac);
    EXPECT_FALSE(retVal);
    std::cout << "Exiting get_radio_id_tlv_len_exceeds_buffer" << std::endl;
}
/**
 * @brief Verify that get_radio_id rejects a Channel Scan Request payload shorter than em_channel_scan_req_t
 *
 * The 2-byte payload {Fresh Scan, num_radios = 1} has no RUID. The frame ends after the EOM TLV,
 * so reading the 6-byte RUID would go past the buffer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 187@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_radio_id on an undersized Channel Scan Request TLV followed by EOM | channel_scan_req payload = {0x80, 0x01}, EOM TLV | API returns false without reading the RUID | Should Fail |
 */
TEST(em_msg_t, get_radio_id_channel_scan_req_undersized)
{
    std::cout << "Entering get_radio_id_channel_scan_req_undersized" << std::endl;
    unsigned char payload[2] = {0x80, 0x01};
    std::vector<unsigned char> tlvBuffer(TLV_HEADER_SIZE + sizeof(payload) + TLV_HEADER_SIZE);
    size_t offset = 0;
    write_tlv(tlvBuffer.data() + offset, em_tlv_type_channel_scan_req, payload, sizeof(payload));
    offset += TLV_HEADER_SIZE + sizeof(payload);
    write_tlv(tlvBuffer.data() + offset, em_tlv_type_eom, nullptr, 0);
    em_msg_t msg(tlvBuffer.data(), static_cast<unsigned int>(tlvBuffer.size()));
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(&mac);
    EXPECT_FALSE(retVal);
    std::cout << "Exiting get_radio_id_channel_scan_req_undersized" << std::endl;
}
/**
 * @brief Verify that get_radio_id extracts the RUID from a valid Channel Scan Request
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 188@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call get_radio_id on a Channel Scan Request with the full fixed header followed by EOM | Fresh Scan = 0, num_radios = 1, ruid = 10:20:30:40:50:60, num_op_classes = 0, EOM TLV | API returns true and extracted MAC equals ruid | Should Pass |
 */
TEST(em_msg_t, get_radio_id_channel_scan_req_valid)
{
    std::cout << "Entering get_radio_id_channel_scan_req_valid" << std::endl;
    unsigned char expectedMac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    unsigned char payload[sizeof(em_channel_scan_req_t)] = {0};
    em_channel_scan_req_t *req = reinterpret_cast<em_channel_scan_req_t *>(payload);
    req->num_radios = 1;
    memcpy(req->ruid, expectedMac, sizeof(mac_address_t));
    req->num_op_classes = 0;
    std::vector<unsigned char> tlvBuffer(TLV_HEADER_SIZE + sizeof(payload) + TLV_HEADER_SIZE);
    size_t offset = 0;
    write_tlv(tlvBuffer.data() + offset, em_tlv_type_channel_scan_req, payload, sizeof(payload));
    offset += TLV_HEADER_SIZE + sizeof(payload);
    write_tlv(tlvBuffer.data() + offset, em_tlv_type_eom, nullptr, 0);
    em_msg_t msg(tlvBuffer.data(), static_cast<unsigned int>(tlvBuffer.size()));
    unsigned char mac[6] = {0};
    bool retVal = msg.get_radio_id(&mac);
    EXPECT_TRUE(retVal);
    EXPECT_EQ(0, std::memcmp(mac, expectedMac, 6));
    std::cout << "Exiting get_radio_id_channel_scan_req_valid" << std::endl;
}
