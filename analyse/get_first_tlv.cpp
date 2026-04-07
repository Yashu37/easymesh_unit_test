#include <stdio.h>
#include <cstring>
#include <stddef.h>
#include <arpa/inet.h>
#include "./common.h"
/*
#define EM_ASSERT_MSG_FALSE(x, ret, errMsg, ...) \
	if(x) { \
		em_printfout(errMsg, ## __VA_ARGS__); \
		return ret; \
	}

#define EM_ASSERT_MSG_TRUE(x, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(!(x), ret, errMsg, ## __VA_ARGS__)
#define EM_ASSERT_NOT_NULL(x, ret, errMsg, ...) EM_ASSERT_MSG_FALSE(x == NULL, ret, errMsg, ## __VA_ARGS__)

//ret = em_msg_t::get_first_tlv(reinterpret_cast<em_tlv_t*>(packet), packet_len);
*/

em_tlv_t *em_msg_t::get_first_tlv(em_tlv_t* tlvs_buff, unsigned int buff_len)
{

	if (tlvs_buff == NULL || buff_len == 0) {
		return NULL;
	}

#if 1
	if (buff_len < sizeof(em_tlv_t)) {
//		em_printfout("Truncated packet: not enough space for TLV length field\n");
		printf("Truncated packet: not enough space for TLV length field\n");
		return NULL;
	}
#endif

	em_tlv_t *tlv = tlvs_buff;
	uint16_t tlv_len = ntohs(tlv->len);

	if (tlv_len == 0 || tlv_len + sizeof(em_tlv_t) > buff_len) {
		return NULL; // Invalid TLV length or buffer too small
	}

	return tlv;
}

