#include <cstring>
#include <stddef.h>
#include <arpa/inet.h>
#include "./common.h"

em_tlv_t *em_msg_t::get_next_tlv(em_tlv_t* tlv, em_tlv_t* tlvs_buff, unsigned int buff_len)
{
	EM_ASSERT_NOT_NULL(tlv, NULL, "TLV is NULL");
	EM_ASSERT_NOT_NULL(tlvs_buff, NULL, "Buffer is NULL");
	EM_ASSERT_MSG_TRUE(buff_len > 0, NULL, "Buffer length is zero");

	uint8_t* main_tlvs_buff = reinterpret_cast<uint8_t*>(tlvs_buff);

	// Calculate offset of current TLV from buffer start
	long int signed_offset = reinterpret_cast<uint8_t*>(tlv) - main_tlvs_buff;
	EM_ASSERT_MSG_TRUE(signed_offset >= 0, NULL, "TLV is before buffer start");
	size_t offset = static_cast<size_t>(signed_offset);
	EM_ASSERT_MSG_TRUE(offset < buff_len, NULL, "TLV offset exceeds buffer length");
#if 1
	if (buff_len < sizeof(em_tlv_t)) {
		em_printfout("Truncated packet: not enough space for TLV length field\n");
		return NULL;
	}
#endif
	// Calculate the size of the current TLV (header + data)
	uint16_t current_tlv_size = sizeof(em_tlv_t) + ntohs(tlv->len);

	// Shift the offset by the current TLV
	offset += current_tlv_size;
	if (offset >= buff_len) {
		return NULL; // No more TLVs
	}
#if 1
	size_t remaining_len = buff_len - offset;

	em_printfout("buff_len = %u, offset = %zu, remaining_len = %zu\n",
			buff_len, offset, remaining_len);

	if (remaining_len < sizeof(em_tlv_t)) {
		em_printfout("Truncated packet: not enough space for TLV header\n");
	}
#endif
	// Position buffer pointer to start of next TLV
	em_tlv_t* next_tlvs_buff = reinterpret_cast<em_tlv_t*>(main_tlvs_buff + offset);
	unsigned int next_tlvs_buff_len = buff_len - static_cast<unsigned int>(offset);

	// Use get_first_tlv to validate and return the next TLV
	return get_first_tlv(next_tlvs_buff, next_tlvs_buff_len);
}

