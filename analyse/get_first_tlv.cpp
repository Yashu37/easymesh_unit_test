#include <stdio.h>
#include <cstring>
#include <stddef.h>
#include <arpa/inet.h>
#include "./common.h"

em_tlv_t *em_msg_t::get_first_tlv(em_tlv_t* tlvs_buff, unsigned int buff_len)
{

	if (tlvs_buff == NULL || buff_len == 0) {
		return NULL;
	}

#if 1
	if (buff_len < sizeof(em_tlv_t)) {
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

