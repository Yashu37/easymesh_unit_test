#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>


void construct_timestamp_tlv(void)
{
	*ptr++ = 0xA8;

	const char *ts = "2024-03-15T10:30:45Z";
	uint8_t ts_len = strlen(ts);

	*(uint16_t*)ptr = htons(ts_len);
	ptr += 2;

	memcpy(ptr, ts, ts_len);
	ptr += ts_len;
}

void construct_eom(void)
{
	*ptr++ = 0x00;
	*(uint16_t*)ptr = 0;
	ptr += 2;
}

#if 0
void construct_valid_timestamp_tlv_real(void)
{
	*ptr++ = 0xA8;   // Timestamp TLV

	// Real timestamp string
	const char *ts = "2024-03-15T10:30:45Z";
	uint8_t ts_len = 20;

	// TLV length = 1 (length field) + 20 (string)
	*(uint16_t*)ptr = htons(21);   // ✅ correct
	ptr += 2;

	*ptr++ = ts_len;   // timestamp length

	memcpy(ptr, ts, ts_len);   // timestamp string
	ptr += ts_len;
}

void construct_timestamp_tlv_len0(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	*ptr++ = 0x00;   // timestamp length = 0
}

void construct_timestamp_tlv_len1(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(2);
	ptr += 2;

	*ptr++ = 0x01;
	*ptr++ = 0x41;   // 'A'
}

void construct_timestamp_tlv_len2(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(3);
	ptr += 2;

	*ptr++ = 0x02;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
}

void construct_timestamp_tlv_len3(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(4);
	ptr += 2;

	*ptr++ = 0x03;

	for(int i = 0; i < 3; i++)
		*ptr++ = 0x41 + i;
}

void construct_timestamp_tlv_len4(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(5);
	ptr += 2;

	*ptr++ = 0x04;

	for(int i = 0; i < 4; i++)
		*ptr++ = 0x41 + i;
}

void construct_timestamp_tlv_len5(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(6);
	ptr += 2;

	*ptr++ = 0x05;

	for(int i = 0; i < 5; i++)
		*ptr++ = 0x41 + i;
}

void construct_timestamp_tlv_len6(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(7);
	ptr += 2;

	*ptr++ = 0x06;

	for(int i = 0; i < 6; i++)
		*ptr++ = 0x41 + i;
}

void construct_timestamp_tlv_len7(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(8);
	ptr += 2;

	*ptr++ = 0x07;

	for(int i = 0; i < 7; i++)
		*ptr++ = 0x41 + i;
}

void construct_timestamp_tlv_len8(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(9);
	ptr += 2;

	*ptr++ = 0x08;

	for(int i = 0; i < 8; i++)
		*ptr++ = 0x41 + i;
}

void construct_timestamp_tlv_len9(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(10);
	ptr += 2;

	*ptr++ = 0x09;

	for(int i = 0; i < 9; i++)
		*ptr++ = 0x41 + i;
}

void construct_timestamp_tlv_len10(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(11);
	ptr += 2;

	*ptr++ = 0x0A;

	for(int i = 0; i < 10; i++)
		*ptr++ = 0x41 + i;
}

void construct_timestamp_tlv_len11(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(12);
	ptr += 2;

	*ptr++ = 0x0B;

	for(int i = 0; i < 11; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len12(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(13);
	ptr += 2;

	*ptr++ = 0x0C;

	for(int i = 0; i < 12; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len13(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(14);
	ptr += 2;

	*ptr++ = 0x0D;

	for(int i = 0; i < 13; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len14(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(15);
	ptr += 2;

	*ptr++ = 0x0E;

	for(int i = 0; i < 14; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len15(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(16);
	ptr += 2;

	*ptr++ = 0x0F;

	for(int i = 0; i < 15; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len16(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(17);
	ptr += 2;

	*ptr++ = 0x10;

	for(int i = 0; i < 16; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len17(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(18);
	ptr += 2;

	*ptr++ = 0x11;

	for(int i = 0; i < 17; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len18(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(19);
	ptr += 2;

	*ptr++ = 0x12;

	for(int i = 0; i < 18; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len19(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(20);
	ptr += 2;

	*ptr++ = 0x13;

	for(int i = 0; i < 19; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len20(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(21);
	ptr += 2;

	*ptr++ = 0x14;

	for(int i = 0; i < 20; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len21(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(22);
	ptr += 2;

	*ptr++ = 0x15;

	for(int i = 0; i < 21; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len22(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(23);
	ptr += 2;

	*ptr++ = 0x16;

	for(int i = 0; i < 22; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len23(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(24);
	ptr += 2;

	*ptr++ = 0x17;

	for(int i = 0; i < 23; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len24(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(25);
	ptr += 2;

	*ptr++ = 0x18;

	for(int i = 0; i < 24; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len25(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(26);
	ptr += 2;

	*ptr++ = 0x19;

	for(int i = 0; i < 25; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len26(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(27);
	ptr += 2;

	*ptr++ = 0x1A;

	for(int i = 0; i < 26; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len27(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(28);
	ptr += 2;

	*ptr++ = 0x1B;

	for(int i = 0; i < 27; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len28(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(29);
	ptr += 2;

	*ptr++ = 0x1C;

	for(int i = 0; i < 28; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len29(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(30);
	ptr += 2;

	*ptr++ = 0x1D;

	for(int i = 0; i < 29; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len30(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(31);
	ptr += 2;

	*ptr++ = 0x1E;

	for(int i = 0; i < 30; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len31(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(32);
	ptr += 2;

	*ptr++ = 0x1F;

	for(int i = 0; i < 31; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len32(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(33);
	ptr += 2;

	*ptr++ = 0x20;

	for(int i = 0; i < 32; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len33(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(34);
	ptr += 2;

	*ptr++ = 0x21;

	for(int i = 0; i < 33; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len34(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(35);
	ptr += 2;

	*ptr++ = 0x22;

	for(int i = 0; i < 34; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len35(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(36);
	ptr += 2;

	*ptr++ = 0x23;

	for(int i = 0; i < 35; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len36(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(37);
	ptr += 2;

	*ptr++ = 0x24;

	for(int i = 0; i < 36; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len37(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(38);
	ptr += 2;

	*ptr++ = 0x25;

	for(int i = 0; i < 37; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len38(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(39);
	ptr += 2;

	*ptr++ = 0x26;

	for(int i = 0; i < 38; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len39(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(40);
	ptr += 2;

	*ptr++ = 0x27;

	for(int i = 0; i < 39; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len40(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(41);
	ptr += 2;

	*ptr++ = 0x28;

	for(int i = 0; i < 40; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len41(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(42);
	ptr += 2;

	*ptr++ = 0x29;

	for(int i = 0; i < 41; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len42(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(43);
	ptr += 2;

	*ptr++ = 0x2A;

	for(int i = 0; i < 42; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len43(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(44);
	ptr += 2;

	*ptr++ = 0x2B;

	for(int i = 0; i < 43; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len44(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(45);
	ptr += 2;

	*ptr++ = 0x2C;

	for(int i = 0; i < 44; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len45(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(46);
	ptr += 2;

	*ptr++ = 0x2D;

	for(int i = 0; i < 45; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len46(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(47);
	ptr += 2;

	*ptr++ = 0x2E;

	for(int i = 0; i < 46; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len47(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(48);
	ptr += 2;

	*ptr++ = 0x2F;

	for(int i = 0; i < 47; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len48(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(49);
	ptr += 2;

	*ptr++ = 0x30;

	for(int i = 0; i < 48; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len49(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(50);
	ptr += 2;

	*ptr++ = 0x31;

	for(int i = 0; i < 49; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len50(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(51);
	ptr += 2;

	*ptr++ = 0x32;

	for(int i = 0; i < 50; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len51(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(52);
	ptr += 2;

	*ptr++ = 51;

	for(int i = 0; i < 51; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len52(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(53);
	ptr += 2;

	*ptr++ = 52;

	for(int i = 0; i < 52; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len53(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(54);
	ptr += 2;

	*ptr++ = 53;

	for(int i = 0; i < 53; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len54(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(55);
	ptr += 2;

	*ptr++ = 54;

	for(int i = 0; i < 54; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len55(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(56);
	ptr += 2;

	*ptr++ = 55;

	for(int i = 0; i < 55; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len56(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(57);
	ptr += 2;

	*ptr++ = 56;

	for(int i = 0; i < 56; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len57(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(58);
	ptr += 2;

	*ptr++ = 57;

	for(int i = 0; i < 57; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len58(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(59);
	ptr += 2;

	*ptr++ = 58;

	for(int i = 0; i < 58; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len59(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(60);
	ptr += 2;

	*ptr++ = 59;

	for(int i = 0; i < 59; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len60(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(61);
	ptr += 2;

	*ptr++ = 60;

	for(int i = 0; i < 60; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len61(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(62);
	ptr += 2;

	*ptr++ = 61;

	for(int i = 0; i < 61; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len62(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(63);
	ptr += 2;

	*ptr++ = 62;

	for(int i = 0; i < 62; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len63(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(64);
	ptr += 2;

	*ptr++ = 63;

	for(int i = 0; i < 63; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len64(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(65);
	ptr += 2;

	*ptr++ = 64;

	for(int i = 0; i < 64; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len65(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(66);
	ptr += 2;

	*ptr++ = 65;

	for(int i = 0; i < 65; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len66(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(67);
	ptr += 2;

	*ptr++ = 66;

	for(int i = 0; i < 66; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len67(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(68);
	ptr += 2;

	*ptr++ = 67;

	for(int i = 0; i < 67; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len68(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(69);
	ptr += 2;

	*ptr++ = 68;

	for(int i = 0; i < 68; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len69(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(70);
	ptr += 2;

	*ptr++ = 69;

	for(int i = 0; i < 69; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len70(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(71);
	ptr += 2;

	*ptr++ = 70;

	for(int i = 0; i < 70; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len71(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(72);
	ptr += 2;

	*ptr++ = 71;

	for(int i = 0; i < 71; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len72(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(73);
	ptr += 2;

	*ptr++ = 72;

	for(int i = 0; i < 72; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len73(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(74);
	ptr += 2;

	*ptr++ = 73;

	for(int i = 0; i < 73; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len74(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(75);
	ptr += 2;

	*ptr++ = 74;

	for(int i = 0; i < 74; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len75(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(76);
	ptr += 2;

	*ptr++ = 75;

	for(int i = 0; i < 75; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len76(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(77);
	ptr += 2;

	*ptr++ = 76;

	for(int i = 0; i < 76; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len77(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(78);
	ptr += 2;

	*ptr++ = 77;

	for(int i = 0; i < 77; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len78(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(79);
	ptr += 2;

	*ptr++ = 78;

	for(int i = 0; i < 78; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len79(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(80);
	ptr += 2;

	*ptr++ = 79;

	for(int i = 0; i < 79; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len80(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(81);
	ptr += 2;

	*ptr++ = 80;

	for(int i = 0; i < 80; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len81(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(82);
	ptr += 2;

	*ptr++ = 0x51;

	for(int i = 0; i < 81; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len82(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(83);
	ptr += 2;

	*ptr++ = 0x52;

	for(int i = 0; i < 82; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len83(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(84);
	ptr += 2;

	*ptr++ = 0x53;

	for(int i = 0; i < 83; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len84(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(85);
	ptr += 2;

	*ptr++ = 0x54;

	for(int i = 0; i < 84; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len85(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(86);
	ptr += 2;

	*ptr++ = 0x55;

	for(int i = 0; i < 85; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len86(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(87);
	ptr += 2;

	*ptr++ = 0x56;

	for(int i = 0; i < 86; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len87(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(88);
	ptr += 2;

	*ptr++ = 0x57;

	for(int i = 0; i < 87; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len88(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(89);
	ptr += 2;

	*ptr++ = 0x58;

	for(int i = 0; i < 88; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len89(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(90);
	ptr += 2;

	*ptr++ = 0x59;

	for(int i = 0; i < 89; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len90(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(91);
	ptr += 2;

	*ptr++ = 0x5A;

	for(int i = 0; i < 90; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len91(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(92);
	ptr += 2;

	*ptr++ = 0x5B;

	for(int i = 0; i < 91; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len92(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(93);
	ptr += 2;

	*ptr++ = 0x5C;

	for(int i = 0; i < 92; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len93(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(94);
	ptr += 2;

	*ptr++ = 0x5D;

	for(int i = 0; i < 93; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len94(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(95);
	ptr += 2;

	*ptr++ = 0x5E;

	for(int i = 0; i < 94; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len95(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(96);
	ptr += 2;

	*ptr++ = 0x5F;

	for(int i = 0; i < 95; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len96(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(97);
	ptr += 2;

	*ptr++ = 0x60;

	for(int i = 0; i < 96; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len97(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(98);
	ptr += 2;

	*ptr++ = 0x61;

	for(int i = 0; i < 97; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len98(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(99);
	ptr += 2;

	*ptr++ = 0x62;

	for(int i = 0; i < 98; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len99(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(100);
	ptr += 2;

	*ptr++ = 0x63;

	for(int i = 0; i < 99; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len100(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(101);
	ptr += 2;

	*ptr++ = 0x64;

	for(int i = 0; i < 100; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len101(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(102);
	ptr += 2;

	*ptr++ = 101;

	for(int i = 0; i < 101; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len102(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(103);
	ptr += 2;

	*ptr++ = 102;

	for(int i = 0; i < 102; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len103(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(104);
	ptr += 2;

	*ptr++ = 103;

	for(int i = 0; i < 103; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len104(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(105);
	ptr += 2;

	*ptr++ = 104;

	for(int i = 0; i < 104; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len105(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(106);
	ptr += 2;

	*ptr++ = 105;

	for(int i = 0; i < 105; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len106(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(107);
	ptr += 2;

	*ptr++ = 106;

	for(int i = 0; i < 106; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len107(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(108);
	ptr += 2;

	*ptr++ = 107;

	for(int i = 0; i < 107; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len108(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(109);
	ptr += 2;

	*ptr++ = 108;

	for(int i = 0; i < 108; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len109(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(110);
	ptr += 2;

	*ptr++ = 109;

	for(int i = 0; i < 109; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len110(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(111);
	ptr += 2;

	*ptr++ = 110;

	for(int i = 0; i < 110; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len111(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(112);
	ptr += 2;

	*ptr++ = 111;

	for(int i = 0; i < 111; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len112(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(113);
	ptr += 2;

	*ptr++ = 112;

	for(int i = 0; i < 112; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len113(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(114);
	ptr += 2;

	*ptr++ = 113;

	for(int i = 0; i < 113; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len114(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(115);
	ptr += 2;

	*ptr++ = 114;

	for(int i = 0; i < 114; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len115(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(116);
	ptr += 2;

	*ptr++ = 115;

	for(int i = 0; i < 115; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len116(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(117);
	ptr += 2;

	*ptr++ = 116;

	for(int i = 0; i < 116; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len117(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(118);
	ptr += 2;

	*ptr++ = 117;

	for(int i = 0; i < 117; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len118(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(119);
	ptr += 2;

	*ptr++ = 118;

	for(int i = 0; i < 118; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len119(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(120);
	ptr += 2;

	*ptr++ = 119;

	for(int i = 0; i < 119; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len120(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(121);
	ptr += 2;

	*ptr++ = 120;

	for(int i = 0; i < 120; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len121(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(122);
	ptr += 2;

	*ptr++ = 121;

	for(int i = 0; i < 121; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len122(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(123);
	ptr += 2;

	*ptr++ = 122;

	for(int i = 0; i < 122; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len123(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(124);
	ptr += 2;

	*ptr++ = 123;

	for(int i = 0; i < 123; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len124(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(125);
	ptr += 2;

	*ptr++ = 124;

	for(int i = 0; i < 124; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len125(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(126);
	ptr += 2;

	*ptr++ = 125;

	for(int i = 0; i < 125; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len126(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(127);
	ptr += 2;

	*ptr++ = 126;

	for(int i = 0; i < 126; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len127(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(128);
	ptr += 2;

	*ptr++ = 127;

	for(int i = 0; i < 127; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len128(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(129);
	ptr += 2;

	*ptr++ = 128;

	for(int i = 0; i < 128; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len129(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(130);
	ptr += 2;

	*ptr++ = 129;

	for(int i = 0; i < 129; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len130(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(131);
	ptr += 2;

	*ptr++ = 130;

	for(int i = 0; i < 130; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len131(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(132);
	ptr += 2;

	*ptr++ = 131;

	for(int i = 0; i < 131; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len132(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(133);
	ptr += 2;

	*ptr++ = 132;

	for(int i = 0; i < 132; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len133(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(134);
	ptr += 2;

	*ptr++ = 133;

	for(int i = 0; i < 133; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len134(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(135);
	ptr += 2;

	*ptr++ = 134;

	for(int i = 0; i < 134; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len135(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(136);
	ptr += 2;

	*ptr++ = 135;

	for(int i = 0; i < 135; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len136(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(137);
	ptr += 2;

	*ptr++ = 136;

	for(int i = 0; i < 136; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len137(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(138);
	ptr += 2;

	*ptr++ = 137;

	for(int i = 0; i < 137; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len138(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(139);
	ptr += 2;

	*ptr++ = 138;

	for(int i = 0; i < 138; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len139(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(140);
	ptr += 2;

	*ptr++ = 139;

	for(int i = 0; i < 139; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len140(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(141);
	ptr += 2;

	*ptr++ = 140;

	for(int i = 0; i < 140; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len141(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(142);
	ptr += 2;

	*ptr++ = 141;

	for(int i = 0; i < 141; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len142(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(143);
	ptr += 2;

	*ptr++ = 142;

	for(int i = 0; i < 142; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len143(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(144);
	ptr += 2;

	*ptr++ = 143;

	for(int i = 0; i < 143; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len144(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(145);
	ptr += 2;

	*ptr++ = 144;

	for(int i = 0; i < 144; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len145(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(146);
	ptr += 2;

	*ptr++ = 145;

	for(int i = 0; i < 145; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len146(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(147);
	ptr += 2;

	*ptr++ = 146;

	for(int i = 0; i < 146; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len147(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(148);
	ptr += 2;

	*ptr++ = 147;

	for(int i = 0; i < 147; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len148(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(149);
	ptr += 2;

	*ptr++ = 148;

	for(int i = 0; i < 148; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len149(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(150);
	ptr += 2;

	*ptr++ = 149;

	for(int i = 0; i < 149; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len150(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(151);
	ptr += 2;

	*ptr++ = 150;

	for(int i = 0; i < 150; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len151(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(152);
	ptr += 2;

	*ptr++ = 151;

	for(int i = 0; i < 151; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len152(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(153);
	ptr += 2;

	*ptr++ = 152;

	for(int i = 0; i < 152; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len153(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(154);
	ptr += 2;

	*ptr++ = 153;

	for(int i = 0; i < 153; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len154(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(155);
	ptr += 2;

	*ptr++ = 154;

	for(int i = 0; i < 154; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len155(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(156);
	ptr += 2;

	*ptr++ = 155;

	for(int i = 0; i < 155; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len156(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(157);
	ptr += 2;

	*ptr++ = 156;

	for(int i = 0; i < 156; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len157(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(158);
	ptr += 2;

	*ptr++ = 157;

	for(int i = 0; i < 157; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len158(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(159);
	ptr += 2;

	*ptr++ = 158;

	for(int i = 0; i < 158; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len159(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(160);
	ptr += 2;

	*ptr++ = 159;

	for(int i = 0; i < 159; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len160(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(161);
	ptr += 2;

	*ptr++ = 160;

	for(int i = 0; i < 160; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len161(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(162);
	ptr += 2;

	*ptr++ = 0xA1;  // 161

	for(int i = 0; i < 161; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len162(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(163);
	ptr += 2;

	*ptr++ = 0xA2;

	for(int i = 0; i < 162; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len163(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(164);
	ptr += 2;

	*ptr++ = 0xA3;

	for(int i = 0; i < 163; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len164(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(165);
	ptr += 2;

	*ptr++ = 0xA4;

	for(int i = 0; i < 164; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len165(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(166);
	ptr += 2;

	*ptr++ = 0xA5;

	for(int i = 0; i < 165; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len166(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(167);
	ptr += 2;

	*ptr++ = 0xA6;

	for(int i = 0; i < 166; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len167(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(168);
	ptr += 2;

	*ptr++ = 0xA7;

	for(int i = 0; i < 167; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len168(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(169);
	ptr += 2;

	*ptr++ = 0xA8;

	for(int i = 0; i < 168; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len169(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(170);
	ptr += 2;

	*ptr++ = 0xA9;

	for(int i = 0; i < 169; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len170(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(171);
	ptr += 2;

	*ptr++ = 0xAA;

	for(int i = 0; i < 170; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len171(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(172);
	ptr += 2;

	*ptr++ = 0xAB;

	for(int i = 0; i < 171; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len172(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(173);
	ptr += 2;

	*ptr++ = 0xAC;

	for(int i = 0; i < 172; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len173(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(174);
	ptr += 2;

	*ptr++ = 0xAD;

	for(int i = 0; i < 173; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len174(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(175);
	ptr += 2;

	*ptr++ = 0xAE;

	for(int i = 0; i < 174; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len175(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(176);
	ptr += 2;

	*ptr++ = 0xAF;

	for(int i = 0; i < 175; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len176(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(177);
	ptr += 2;

	*ptr++ = 0xB0;

	for(int i = 0; i < 176; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len177(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(178);
	ptr += 2;

	*ptr++ = 0xB1;

	for(int i = 0; i < 177; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len178(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(179);
	ptr += 2;

	*ptr++ = 0xB2;

	for(int i = 0; i < 178; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len179(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(180);
	ptr += 2;

	*ptr++ = 0xB3;

	for(int i = 0; i < 179; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len180(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(181);
	ptr += 2;

	*ptr++ = 0xB4;

	for(int i = 0; i < 180; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len181(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(182);
	ptr += 2;

	*ptr++ = 0xB5;

	for(int i = 0; i < 181; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len182(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(183);
	ptr += 2;

	*ptr++ = 0xB6;

	for(int i = 0; i < 182; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len183(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(184);
	ptr += 2;

	*ptr++ = 0xB7;

	for(int i = 0; i < 183; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len184(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(185);
	ptr += 2;

	*ptr++ = 0xB8;

	for(int i = 0; i < 184; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len185(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(186);
	ptr += 2;

	*ptr++ = 0xB9;

	for(int i = 0; i < 185; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len186(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(187);
	ptr += 2;

	*ptr++ = 0xBA;

	for(int i = 0; i < 186; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len187(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(188);
	ptr += 2;

	*ptr++ = 0xBB;

	for(int i = 0; i < 187; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len188(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(189);
	ptr += 2;

	*ptr++ = 0xBC;

	for(int i = 0; i < 188; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len189(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(190);
	ptr += 2;

	*ptr++ = 0xBD;

	for(int i = 0; i < 189; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len190(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(191);
	ptr += 2;

	*ptr++ = 0xBE;

	for(int i = 0; i < 190; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len191(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(192);
	ptr += 2;

	*ptr++ = 0xBF;

	for(int i = 0; i < 191; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len192(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(193);
	ptr += 2;

	*ptr++ = 0xC0;

	for(int i = 0; i < 192; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len193(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(194);
	ptr += 2;

	*ptr++ = 0xC1;

	for(int i = 0; i < 193; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len194(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(195);
	ptr += 2;

	*ptr++ = 0xC2;

	for(int i = 0; i < 194; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len195(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(196);
	ptr += 2;

	*ptr++ = 0xC3;

	for(int i = 0; i < 195; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len196(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(197);
	ptr += 2;

	*ptr++ = 0xC4;

	for(int i = 0; i < 196; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len197(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(198);
	ptr += 2;

	*ptr++ = 0xC5;

	for(int i = 0; i < 197; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len198(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(199);
	ptr += 2;

	*ptr++ = 0xC6;

	for(int i = 0; i < 198; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len199(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(200);
	ptr += 2;

	*ptr++ = 0xC7;

	for(int i = 0; i < 199; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len200(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(201);
	ptr += 2;

	*ptr++ = 0xC8;

	for(int i = 0; i < 200; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len201(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(202);
	ptr += 2;

	*ptr++ = 0xC9;

	for(int i = 0; i < 201; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len202(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(203);
	ptr += 2;

	*ptr++ = 0xCA;

	for(int i = 0; i < 202; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len203(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(204);
	ptr += 2;

	*ptr++ = 0xCB;

	for(int i = 0; i < 203; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len204(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(205);
	ptr += 2;

	*ptr++ = 0xCC;

	for(int i = 0; i < 204; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len205(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(206);
	ptr += 2;

	*ptr++ = 0xCD;

	for(int i = 0; i < 205; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len206(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(207);
	ptr += 2;

	*ptr++ = 0xCE;

	for(int i = 0; i < 206; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len207(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(208);
	ptr += 2;

	*ptr++ = 0xCF;

	for(int i = 0; i < 207; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len208(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(209);
	ptr += 2;

	*ptr++ = 0xD0;

	for(int i = 0; i < 208; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len209(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(210);
	ptr += 2;

	*ptr++ = 0xD1;

	for(int i = 0; i < 209; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len210(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(211);
	ptr += 2;

	*ptr++ = 0xD2;

	for(int i = 0; i < 210; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len211(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(212);
	ptr += 2;

	*ptr++ = 211;

	for(int i = 0; i < 211; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len212(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(213);
	ptr += 2;

	*ptr++ = 212;

	for(int i = 0; i < 212; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len213(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(214);
	ptr += 2;

	*ptr++ = 213;

	for(int i = 0; i < 213; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len214(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(215);
	ptr += 2;

	*ptr++ = 214;

	for(int i = 0; i < 214; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len215(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(216);
	ptr += 2;

	*ptr++ = 215;

	for(int i = 0; i < 215; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len216(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(217);
	ptr += 2;

	*ptr++ = 216;

	for(int i = 0; i < 216; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len217(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(218);
	ptr += 2;

	*ptr++ = 217;

	for(int i = 0; i < 217; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len218(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(219);
	ptr += 2;

	*ptr++ = 218;

	for(int i = 0; i < 218; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len219(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(220);
	ptr += 2;

	*ptr++ = 219;

	for(int i = 0; i < 219; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len220(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(221);
	ptr += 2;

	*ptr++ = 220;

	for(int i = 0; i < 220; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len221(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(222);
	ptr += 2;
	*ptr++ = 221;

	for(int i = 0; i < 221; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len222(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(223);
	ptr += 2;
	*ptr++ = 222;

	for(int i = 0; i < 222; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len223(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(224);
	ptr += 2;
	*ptr++ = 223;

	for(int i = 0; i < 223; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len224(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(225);
	ptr += 2;
	*ptr++ = 224;

	for(int i = 0; i < 224; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len225(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(226);
	ptr += 2;
	*ptr++ = 225;

	for(int i = 0; i < 225; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len226(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(227);
	ptr += 2;
	*ptr++ = 226;

	for(int i = 0; i < 226; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len227(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(228);
	ptr += 2;
	*ptr++ = 227;

	for(int i = 0; i < 227; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len228(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(229);
	ptr += 2;
	*ptr++ = 228;

	for(int i = 0; i < 228; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len229(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(230);
	ptr += 2;
	*ptr++ = 229;

	for(int i = 0; i < 229; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len230(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(231);
	ptr += 2;
	*ptr++ = 230;

	for(int i = 0; i < 230; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len231(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(232);
	ptr += 2;
	*ptr++ = 231;

	for(int i = 0; i < 231; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len232(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(233);
	ptr += 2;
	*ptr++ = 232;

	for(int i = 0; i < 232; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len233(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(234);
	ptr += 2;
	*ptr++ = 233;

	for(int i = 0; i < 233; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len234(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(235);
	ptr += 2;
	*ptr++ = 234;

	for(int i = 0; i < 234; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len235(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(236);
	ptr += 2;
	*ptr++ = 235;

	for(int i = 0; i < 235; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len236(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(237);
	ptr += 2;
	*ptr++ = 236;

	for(int i = 0; i < 236; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len237(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(238);
	ptr += 2;
	*ptr++ = 237;

	for(int i = 0; i < 237; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len238(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(239);
	ptr += 2;
	*ptr++ = 238;

	for(int i = 0; i < 238; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len239(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(240);
	ptr += 2;
	*ptr++ = 239;

	for(int i = 0; i < 239; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len240(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(241);
	ptr += 2;
	*ptr++ = 240;

	for(int i = 0; i < 240; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len241(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(242);
	ptr += 2;
	*ptr++ = 241;

	for(int i = 0; i < 241; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len242(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(243);
	ptr += 2;
	*ptr++ = 242;

	for(int i = 0; i < 242; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len243(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(244);
	ptr += 2;
	*ptr++ = 243;

	for(int i = 0; i < 243; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len244(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(245);
	ptr += 2;
	*ptr++ = 244;

	for(int i = 0; i < 244; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len245(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(246);
	ptr += 2;
	*ptr++ = 245;

	for(int i = 0; i < 245; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len246(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(247);
	ptr += 2;
	*ptr++ = 246;

	for(int i = 0; i < 246; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len247(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(248);
	ptr += 2;
	*ptr++ = 247;

	for(int i = 0; i < 247; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len248(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(249);
	ptr += 2;
	*ptr++ = 248;

	for(int i = 0; i < 248; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len249(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(250);
	ptr += 2;
	*ptr++ = 249;

	for(int i = 0; i < 249; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len250(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(251);
	ptr += 2;

	*ptr++ = 250;

	for(int i = 0; i < 250; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len251(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(252);
	ptr += 2;

	*ptr++ = 251;

	for(int i = 0; i < 251; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len252(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(253);
	ptr += 2;

	*ptr++ = 252;

	for(int i = 0; i < 252; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len253(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(254);
	ptr += 2;

	*ptr++ = 253;

	for(int i = 0; i < 253; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len254(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(255);
	ptr += 2;

	*ptr++ = 254;

	for(int i = 0; i < 254; i++)
		*ptr++ = 0x41 + (i % 26);
}

void construct_timestamp_tlv_len255(void)
{
	*ptr++ = 0xA8;
	*(uint16_t*)ptr = htons(256);
	ptr += 2;

	*ptr++ = 255;

	for(int i = 0; i < 255; i++)
		*ptr++ = 0x41 + (i % 26);
}

pkt_test_case_t handle_channel_scan_rprt_suite[] = {

	{"valid_timestamp_tlv_real", "p1.pcap", construct_valid_timestamp_tlv_real, 0},
	{"timestamp_tlv_len0", "p2.pcap", construct_timestamp_tlv_len0, 0},
	{"timestamp_tlv_len1", "p3.pcap", construct_timestamp_tlv_len1, 0},
	{"timestamp_tlv_len2", "p4.pcap", construct_timestamp_tlv_len2, 0},
	{"timestamp_tlv_len3", "p5.pcap", construct_timestamp_tlv_len3, 0},
	{"timestamp_tlv_len4", "p6.pcap", construct_timestamp_tlv_len4, 0},
	{"timestamp_tlv_len5", "p7.pcap", construct_timestamp_tlv_len5, 0},
	{"timestamp_tlv_len6", "p8.pcap", construct_timestamp_tlv_len6, 0},
	{"timestamp_tlv_len7", "p9.pcap", construct_timestamp_tlv_len7, 0},
	{"timestamp_tlv_len8", "p10.pcap", construct_timestamp_tlv_len8, 0},
	{"timestamp_tlv_len9", "p11.pcap", construct_timestamp_tlv_len9, 0},
	{"timestamp_tlv_len10", "p12.pcap", construct_timestamp_tlv_len10, 0},
	{"timestamp_tlv_len11", "p13.pcap", construct_timestamp_tlv_len11, 0},
	{"timestamp_tlv_len12", "p14.pcap", construct_timestamp_tlv_len12, 0},
	{"timestamp_tlv_len13", "p15.pcap", construct_timestamp_tlv_len13, 0},
	{"timestamp_tlv_len14", "p16.pcap", construct_timestamp_tlv_len14, 0},
	{"timestamp_tlv_len15", "p17.pcap", construct_timestamp_tlv_len15, 0},
	{"timestamp_tlv_len16", "p18.pcap", construct_timestamp_tlv_len16, 0},
	{"timestamp_tlv_len17", "p19.pcap", construct_timestamp_tlv_len17, 0},
	{"timestamp_tlv_len18", "p20.pcap", construct_timestamp_tlv_len18, 0},
	{"timestamp_tlv_len19", "p21.pcap", construct_timestamp_tlv_len19, 0},
	{"timestamp_tlv_len20", "p22.pcap", construct_timestamp_tlv_len20, 0},
	{"timestamp_tlv_len21", "p23.pcap", construct_timestamp_tlv_len21, 0},
	{"timestamp_tlv_len22", "p24.pcap", construct_timestamp_tlv_len22, 0},
	{"timestamp_tlv_len23", "p25.pcap", construct_timestamp_tlv_len23, 0},
	{"timestamp_tlv_len24", "p26.pcap", construct_timestamp_tlv_len24, 0},
	{"timestamp_tlv_len25", "p27.pcap", construct_timestamp_tlv_len25, 0},
	{"timestamp_tlv_len26", "p28.pcap", construct_timestamp_tlv_len26, 0},
	{"timestamp_tlv_len27", "p29.pcap", construct_timestamp_tlv_len27, 0},
	{"timestamp_tlv_len28", "p30.pcap", construct_timestamp_tlv_len28, 0},
	{"timestamp_tlv_len29", "p31.pcap", construct_timestamp_tlv_len29, 0},
	{"timestamp_tlv_len30", "p32.pcap", construct_timestamp_tlv_len30, 0},
	{"timestamp_tlv_len31", "p33.pcap", construct_timestamp_tlv_len31, 0},
	{"timestamp_tlv_len32", "p34.pcap", construct_timestamp_tlv_len32, 0},
	{"timestamp_tlv_len33", "p35.pcap", construct_timestamp_tlv_len33, 0},
	{"timestamp_tlv_len34", "p36.pcap", construct_timestamp_tlv_len34, 0},
	{"timestamp_tlv_len35", "p37.pcap", construct_timestamp_tlv_len35, 0},
	{"timestamp_tlv_len36", "p38.pcap", construct_timestamp_tlv_len36, 0},
	{"timestamp_tlv_len37", "p39.pcap", construct_timestamp_tlv_len37, 0},
	{"timestamp_tlv_len38", "p40.pcap", construct_timestamp_tlv_len38, 0},
	{"timestamp_tlv_len39", "p41.pcap", construct_timestamp_tlv_len39, 0},
	{"timestamp_tlv_len40", "p42.pcap", construct_timestamp_tlv_len40, 0},
	{"timestamp_tlv_len41", "p43.pcap", construct_timestamp_tlv_len41, 0},
	{"timestamp_tlv_len42", "p44.pcap", construct_timestamp_tlv_len42, 0},
	{"timestamp_tlv_len43", "p45.pcap", construct_timestamp_tlv_len43, 0},
	{"timestamp_tlv_len44", "p46.pcap", construct_timestamp_tlv_len44, 0},
	{"timestamp_tlv_len45", "p47.pcap", construct_timestamp_tlv_len45, 0},
	{"timestamp_tlv_len46", "p48.pcap", construct_timestamp_tlv_len46, 0},
	{"timestamp_tlv_len47", "p49.pcap", construct_timestamp_tlv_len47, 0},
	{"timestamp_tlv_len48", "p50.pcap", construct_timestamp_tlv_len48, 0},
	{"timestamp_tlv_len49", "p51.pcap", construct_timestamp_tlv_len49, 0},
	{"timestamp_tlv_len50", "p52.pcap", construct_timestamp_tlv_len50, 0},
	{"timestamp_tlv_len50", "p52.pcap", construct_timestamp_tlv_len50, 0},
	{"timestamp_tlv_len51", "p53.pcap", construct_timestamp_tlv_len51, 0},
	{"timestamp_tlv_len52", "p54.pcap", construct_timestamp_tlv_len52, 0},
	{"timestamp_tlv_len53", "p55.pcap", construct_timestamp_tlv_len53, 0},
	{"timestamp_tlv_len54", "p56.pcap", construct_timestamp_tlv_len54, 0},
	{"timestamp_tlv_len55", "p57.pcap", construct_timestamp_tlv_len55, 0},
	{"timestamp_tlv_len56", "p58.pcap", construct_timestamp_tlv_len56, 0},
	{"timestamp_tlv_len57", "p59.pcap", construct_timestamp_tlv_len57, 0},
	{"timestamp_tlv_len58", "p60.pcap", construct_timestamp_tlv_len58, 0},
	{"timestamp_tlv_len59", "p61.pcap", construct_timestamp_tlv_len59, 0},
	{"timestamp_tlv_len60", "p62.pcap", construct_timestamp_tlv_len60, 0},
	{"timestamp_tlv_len61", "p63.pcap", construct_timestamp_tlv_len61, 0},
	{"timestamp_tlv_len62", "p64.pcap", construct_timestamp_tlv_len62, 0},
	{"timestamp_tlv_len63", "p65.pcap", construct_timestamp_tlv_len63, 0},
	{"timestamp_tlv_len64", "p66.pcap", construct_timestamp_tlv_len64, 0},
	{"timestamp_tlv_len65", "p67.pcap", construct_timestamp_tlv_len65, 0},
	{"timestamp_tlv_len66", "p68.pcap", construct_timestamp_tlv_len66, 0},
	{"timestamp_tlv_len67", "p69.pcap", construct_timestamp_tlv_len67, 0},
	{"timestamp_tlv_len68", "p70.pcap", construct_timestamp_tlv_len68, 0},
	{"timestamp_tlv_len69", "p71.pcap", construct_timestamp_tlv_len69, 0},
	{"timestamp_tlv_len70", "p72.pcap", construct_timestamp_tlv_len70, 0},
	{"timestamp_tlv_len71", "p73.pcap", construct_timestamp_tlv_len71, 0},
	{"timestamp_tlv_len72", "p74.pcap", construct_timestamp_tlv_len72, 0},
	{"timestamp_tlv_len73", "p75.pcap", construct_timestamp_tlv_len73, 0},
	{"timestamp_tlv_len74", "p76.pcap", construct_timestamp_tlv_len74, 0},
	{"timestamp_tlv_len75", "p77.pcap", construct_timestamp_tlv_len75, 0},
	{"timestamp_tlv_len76", "p78.pcap", construct_timestamp_tlv_len76, 0},
	{"timestamp_tlv_len77", "p79.pcap", construct_timestamp_tlv_len77, 0},
	{"timestamp_tlv_len78", "p80.pcap", construct_timestamp_tlv_len78, 0},
	{"timestamp_tlv_len79", "p81.pcap", construct_timestamp_tlv_len79, 0},
	{"timestamp_tlv_len80", "p82.pcap", construct_timestamp_tlv_len80, 0},
	{"timestamp_tlv_len81", "p83.pcap", construct_timestamp_tlv_len81, 0},
	{"timestamp_tlv_len82", "p84.pcap", construct_timestamp_tlv_len82, 0},
	{"timestamp_tlv_len83", "p85.pcap", construct_timestamp_tlv_len83, 0},
	{"timestamp_tlv_len84", "p86.pcap", construct_timestamp_tlv_len84, 0},
	{"timestamp_tlv_len85", "p87.pcap", construct_timestamp_tlv_len85, 0},
	{"timestamp_tlv_len86", "p88.pcap", construct_timestamp_tlv_len86, 0},
	{"timestamp_tlv_len87", "p89.pcap", construct_timestamp_tlv_len87, 0},
	{"timestamp_tlv_len88", "p90.pcap", construct_timestamp_tlv_len88, 0},
	{"timestamp_tlv_len89", "p91.pcap", construct_timestamp_tlv_len89, 0},
	{"timestamp_tlv_len90", "p92.pcap", construct_timestamp_tlv_len90, 0},
	{"timestamp_tlv_len91", "p93.pcap", construct_timestamp_tlv_len91, 0},
	{"timestamp_tlv_len92", "p94.pcap", construct_timestamp_tlv_len92, 0},
	{"timestamp_tlv_len93", "p95.pcap", construct_timestamp_tlv_len93, 0},
	{"timestamp_tlv_len94", "p96.pcap", construct_timestamp_tlv_len94, 0},
	{"timestamp_tlv_len95", "p97.pcap", construct_timestamp_tlv_len95, 0},
	{"timestamp_tlv_len96", "p98.pcap", construct_timestamp_tlv_len96, 0},
	{"timestamp_tlv_len97", "p99.pcap", construct_timestamp_tlv_len97, 0},
	{"timestamp_tlv_len98", "p100.pcap", construct_timestamp_tlv_len98, 0},
	{"timestamp_tlv_len99", "p101.pcap", construct_timestamp_tlv_len99, 0},
	{"timestamp_tlv_len100", "p102.pcap", construct_timestamp_tlv_len100, 0},
	{"timestamp_tlv_len101", "p103.pcap", construct_timestamp_tlv_len101, 0},
	{"timestamp_tlv_len102", "p104.pcap", construct_timestamp_tlv_len102, 0},
	{"timestamp_tlv_len103", "p105.pcap", construct_timestamp_tlv_len103, 0},
	{"timestamp_tlv_len104", "p106.pcap", construct_timestamp_tlv_len104, 0},
	{"timestamp_tlv_len105", "p107.pcap", construct_timestamp_tlv_len105, 0},
	{"timestamp_tlv_len106", "p108.pcap", construct_timestamp_tlv_len106, 0},
	{"timestamp_tlv_len107", "p109.pcap", construct_timestamp_tlv_len107, 0},
	{"timestamp_tlv_len108", "p110.pcap", construct_timestamp_tlv_len108, 0},
	{"timestamp_tlv_len109", "p111.pcap", construct_timestamp_tlv_len109, 0},
	{"timestamp_tlv_len110", "p112.pcap", construct_timestamp_tlv_len110, 0},
	{"timestamp_tlv_len111", "p113.pcap", construct_timestamp_tlv_len111, 0},
	{"timestamp_tlv_len112", "p114.pcap", construct_timestamp_tlv_len112, 0},
	{"timestamp_tlv_len113", "p115.pcap", construct_timestamp_tlv_len113, 0},
	{"timestamp_tlv_len114", "p116.pcap", construct_timestamp_tlv_len114, 0},
	{"timestamp_tlv_len115", "p117.pcap", construct_timestamp_tlv_len115, 0},
	{"timestamp_tlv_len116", "p118.pcap", construct_timestamp_tlv_len116, 0},
	{"timestamp_tlv_len117", "p119.pcap", construct_timestamp_tlv_len117, 0},
	{"timestamp_tlv_len118", "p120.pcap", construct_timestamp_tlv_len118, 0},
	{"timestamp_tlv_len119", "p121.pcap", construct_timestamp_tlv_len119, 0},
	{"timestamp_tlv_len120", "p122.pcap", construct_timestamp_tlv_len120, 0},
	{"timestamp_tlv_len121", "p123.pcap", construct_timestamp_tlv_len121, 0},
	{"timestamp_tlv_len122", "p124.pcap", construct_timestamp_tlv_len122, 0},
	{"timestamp_tlv_len123", "p125.pcap", construct_timestamp_tlv_len123, 0},
	{"timestamp_tlv_len124", "p126.pcap", construct_timestamp_tlv_len124, 0},
	{"timestamp_tlv_len125", "p127.pcap", construct_timestamp_tlv_len125, 0},
	{"timestamp_tlv_len126", "p128.pcap", construct_timestamp_tlv_len126, 0},
	{"timestamp_tlv_len127", "p129.pcap", construct_timestamp_tlv_len127, 0},
	{"timestamp_tlv_len128", "p130.pcap", construct_timestamp_tlv_len128, 0},
	{"timestamp_tlv_len129", "p131.pcap", construct_timestamp_tlv_len129, 0},
	{"timestamp_tlv_len130", "p132.pcap", construct_timestamp_tlv_len130, 0},
	{"timestamp_tlv_len131", "p133.pcap", construct_timestamp_tlv_len131, 0},
	{"timestamp_tlv_len132", "p134.pcap", construct_timestamp_tlv_len132, 0},
	{"timestamp_tlv_len133", "p135.pcap", construct_timestamp_tlv_len133, 0},
	{"timestamp_tlv_len134", "p136.pcap", construct_timestamp_tlv_len134, 0},
	{"timestamp_tlv_len135", "p137.pcap", construct_timestamp_tlv_len135, 0},
	{"timestamp_tlv_len136", "p138.pcap", construct_timestamp_tlv_len136, 0},
	{"timestamp_tlv_len137", "p139.pcap", construct_timestamp_tlv_len137, 0},
	{"timestamp_tlv_len138", "p140.pcap", construct_timestamp_tlv_len138, 0},
	{"timestamp_tlv_len139", "p141.pcap", construct_timestamp_tlv_len139, 0},
	{"timestamp_tlv_len140", "p142.pcap", construct_timestamp_tlv_len140, 0},
	{"timestamp_tlv_len141", "p143.pcap", construct_timestamp_tlv_len141, 0},
	{"timestamp_tlv_len142", "p144.pcap", construct_timestamp_tlv_len142, 0},
	{"timestamp_tlv_len143", "p145.pcap", construct_timestamp_tlv_len143, 0},
	{"timestamp_tlv_len144", "p146.pcap", construct_timestamp_tlv_len144, 0},
	{"timestamp_tlv_len145", "p147.pcap", construct_timestamp_tlv_len145, 0},
	{"timestamp_tlv_len146", "p148.pcap", construct_timestamp_tlv_len146, 0},
	{"timestamp_tlv_len147", "p149.pcap", construct_timestamp_tlv_len147, 0},
	{"timestamp_tlv_len148", "p150.pcap", construct_timestamp_tlv_len148, 0},
	{"timestamp_tlv_len149", "p151.pcap", construct_timestamp_tlv_len149, 0},
	{"timestamp_tlv_len150", "p152.pcap", construct_timestamp_tlv_len150, 0},
	{"timestamp_tlv_len151", "p153.pcap", construct_timestamp_tlv_len151, 0},
	{"timestamp_tlv_len152", "p154.pcap", construct_timestamp_tlv_len152, 0},
	{"timestamp_tlv_len153", "p155.pcap", construct_timestamp_tlv_len153, 0},
	{"timestamp_tlv_len154", "p156.pcap", construct_timestamp_tlv_len154, 0},
	{"timestamp_tlv_len155", "p157.pcap", construct_timestamp_tlv_len155, 0},
	{"timestamp_tlv_len156", "p158.pcap", construct_timestamp_tlv_len156, 0},
	{"timestamp_tlv_len157", "p159.pcap", construct_timestamp_tlv_len157, 0},
	{"timestamp_tlv_len158", "p160.pcap", construct_timestamp_tlv_len158, 0},
	{"timestamp_tlv_len159", "p161.pcap", construct_timestamp_tlv_len159, 0},
	{"timestamp_tlv_len160", "p162.pcap", construct_timestamp_tlv_len160, 0},
	{"timestamp_tlv_len161", "p163.pcap", construct_timestamp_tlv_len161, 0},
	{"timestamp_tlv_len162", "p164.pcap", construct_timestamp_tlv_len162, 0},
	{"timestamp_tlv_len163", "p165.pcap", construct_timestamp_tlv_len163, 0},
	{"timestamp_tlv_len164", "p166.pcap", construct_timestamp_tlv_len164, 0},
	{"timestamp_tlv_len165", "p167.pcap", construct_timestamp_tlv_len165, 0},
	{"timestamp_tlv_len166", "p168.pcap", construct_timestamp_tlv_len166, 0},
	{"timestamp_tlv_len167", "p169.pcap", construct_timestamp_tlv_len167, 0},
	{"timestamp_tlv_len168", "p170.pcap", construct_timestamp_tlv_len168, 0},
	{"timestamp_tlv_len169", "p171.pcap", construct_timestamp_tlv_len169, 0},
	{"timestamp_tlv_len170", "p172.pcap", construct_timestamp_tlv_len170, 0},
	{"timestamp_tlv_len171", "p173.pcap", construct_timestamp_tlv_len171, 0},
	{"timestamp_tlv_len172", "p174.pcap", construct_timestamp_tlv_len172, 0},
	{"timestamp_tlv_len173", "p175.pcap", construct_timestamp_tlv_len173, 0},
	{"timestamp_tlv_len174", "p176.pcap", construct_timestamp_tlv_len174, 0},
	{"timestamp_tlv_len175", "p177.pcap", construct_timestamp_tlv_len175, 0},
	{"timestamp_tlv_len176", "p178.pcap", construct_timestamp_tlv_len176, 0},
	{"timestamp_tlv_len177", "p179.pcap", construct_timestamp_tlv_len177, 0},
	{"timestamp_tlv_len178", "p180.pcap", construct_timestamp_tlv_len178, 0},
	{"timestamp_tlv_len179", "p181.pcap", construct_timestamp_tlv_len179, 0},
	{"timestamp_tlv_len180", "p182.pcap", construct_timestamp_tlv_len180, 0},
	{"timestamp_tlv_len181", "p183.pcap", construct_timestamp_tlv_len181, 0},
	{"timestamp_tlv_len182", "p184.pcap", construct_timestamp_tlv_len182, 0},
	{"timestamp_tlv_len183", "p185.pcap", construct_timestamp_tlv_len183, 0},
	{"timestamp_tlv_len184", "p186.pcap", construct_timestamp_tlv_len184, 0},
	{"timestamp_tlv_len185", "p187.pcap", construct_timestamp_tlv_len185, 0},
	{"timestamp_tlv_len186", "p188.pcap", construct_timestamp_tlv_len186, 0},
	{"timestamp_tlv_len187", "p189.pcap", construct_timestamp_tlv_len187, 0},
	{"timestamp_tlv_len188", "p190.pcap", construct_timestamp_tlv_len188, 0},
	{"timestamp_tlv_len189", "p191.pcap", construct_timestamp_tlv_len189, 0},
	{"timestamp_tlv_len190", "p192.pcap", construct_timestamp_tlv_len190, 0},
	{"timestamp_tlv_len191", "p193.pcap", construct_timestamp_tlv_len191, 0},
	{"timestamp_tlv_len192", "p194.pcap", construct_timestamp_tlv_len192, 0},
	{"timestamp_tlv_len193", "p195.pcap", construct_timestamp_tlv_len193, 0},
	{"timestamp_tlv_len194", "p196.pcap", construct_timestamp_tlv_len194, 0},
	{"timestamp_tlv_len195", "p197.pcap", construct_timestamp_tlv_len195, 0},
	{"timestamp_tlv_len196", "p198.pcap", construct_timestamp_tlv_len196, 0},
	{"timestamp_tlv_len197", "p199.pcap", construct_timestamp_tlv_len197, 0},
	{"timestamp_tlv_len198", "p200.pcap", construct_timestamp_tlv_len198, 0},
	{"timestamp_tlv_len199", "p201.pcap", construct_timestamp_tlv_len199, 0},
	{"timestamp_tlv_len200", "p202.pcap", construct_timestamp_tlv_len200, 0},
	{"timestamp_tlv_len201", "p203.pcap", construct_timestamp_tlv_len201, 0},
	{"timestamp_tlv_len202", "p204.pcap", construct_timestamp_tlv_len202, 0},
	{"timestamp_tlv_len203", "p205.pcap", construct_timestamp_tlv_len203, 0},
	{"timestamp_tlv_len204", "p206.pcap", construct_timestamp_tlv_len204, 0},
	{"timestamp_tlv_len205", "p207.pcap", construct_timestamp_tlv_len205, 0},
	{"timestamp_tlv_len206", "p208.pcap", construct_timestamp_tlv_len206, 0},
	{"timestamp_tlv_len207", "p209.pcap", construct_timestamp_tlv_len207, 0},
	{"timestamp_tlv_len208", "p210.pcap", construct_timestamp_tlv_len208, 0},
	{"timestamp_tlv_len209", "p211.pcap", construct_timestamp_tlv_len209, 0},
	{"timestamp_tlv_len210", "p212.pcap", construct_timestamp_tlv_len210, 0},
	{"timestamp_tlv_len211", "p213.pcap", construct_timestamp_tlv_len211, 0},
	{"timestamp_tlv_len212", "p214.pcap", construct_timestamp_tlv_len212, 0},
	{"timestamp_tlv_len213", "p215.pcap", construct_timestamp_tlv_len213, 0},
	{"timestamp_tlv_len214", "p216.pcap", construct_timestamp_tlv_len214, 0},
	{"timestamp_tlv_len215", "p217.pcap", construct_timestamp_tlv_len215, 0},
	{"timestamp_tlv_len216", "p218.pcap", construct_timestamp_tlv_len216, 0},
	{"timestamp_tlv_len217", "p219.pcap", construct_timestamp_tlv_len217, 0},
	{"timestamp_tlv_len218", "p220.pcap", construct_timestamp_tlv_len218, 0},
	{"timestamp_tlv_len219", "p221.pcap", construct_timestamp_tlv_len219, 0},
	{"timestamp_tlv_len220", "p222.pcap", construct_timestamp_tlv_len220, 0},
	{"timestamp_tlv_len221", "p223.pcap", construct_timestamp_tlv_len221, 0},
	{"timestamp_tlv_len222", "p224.pcap", construct_timestamp_tlv_len222, 0},
	{"timestamp_tlv_len223", "p225.pcap", construct_timestamp_tlv_len223, 0},
	{"timestamp_tlv_len224", "p226.pcap", construct_timestamp_tlv_len224, 0},
	{"timestamp_tlv_len225", "p227.pcap", construct_timestamp_tlv_len225, 0},
	{"timestamp_tlv_len226", "p228.pcap", construct_timestamp_tlv_len226, 0},
	{"timestamp_tlv_len227", "p229.pcap", construct_timestamp_tlv_len227, 0},
	{"timestamp_tlv_len228", "p230.pcap", construct_timestamp_tlv_len228, 0},
	{"timestamp_tlv_len229", "p231.pcap", construct_timestamp_tlv_len229, 0},
	{"timestamp_tlv_len230", "p232.pcap", construct_timestamp_tlv_len230, 0},
	{"timestamp_tlv_len231", "p233.pcap", construct_timestamp_tlv_len231, 0},
	{"timestamp_tlv_len232", "p234.pcap", construct_timestamp_tlv_len232, 0},
	{"timestamp_tlv_len233", "p235.pcap", construct_timestamp_tlv_len233, 0},
	{"timestamp_tlv_len234", "p236.pcap", construct_timestamp_tlv_len234, 0},
	{"timestamp_tlv_len235", "p237.pcap", construct_timestamp_tlv_len235, 0},
	{"timestamp_tlv_len236", "p238.pcap", construct_timestamp_tlv_len236, 0},
	{"timestamp_tlv_len237", "p239.pcap", construct_timestamp_tlv_len237, 0},
	{"timestamp_tlv_len238", "p240.pcap", construct_timestamp_tlv_len238, 0},
	{"timestamp_tlv_len239", "p241.pcap", construct_timestamp_tlv_len239, 0},
	{"timestamp_tlv_len240", "p242.pcap", construct_timestamp_tlv_len240, 0},
	{"timestamp_tlv_len241", "p243.pcap", construct_timestamp_tlv_len241, 0},
	{"timestamp_tlv_len242", "p244.pcap", construct_timestamp_tlv_len242, 0},
	{"timestamp_tlv_len243", "p245.pcap", construct_timestamp_tlv_len243, 0},
	{"timestamp_tlv_len244", "p246.pcap", construct_timestamp_tlv_len244, 0},
	{"timestamp_tlv_len245", "p247.pcap", construct_timestamp_tlv_len245, 0},
	{"timestamp_tlv_len246", "p248.pcap", construct_timestamp_tlv_len246, 0},
	{"timestamp_tlv_len247", "p249.pcap", construct_timestamp_tlv_len247, 0},
	{"timestamp_tlv_len248", "p250.pcap", construct_timestamp_tlv_len248, 0},
	{"timestamp_tlv_len249", "p251.pcap", construct_timestamp_tlv_len249, 0},
	{"timestamp_tlv_len250", "p252.pcap", construct_timestamp_tlv_len250, 0},
	{"timestamp_tlv_len251", "p253.pcap", construct_timestamp_tlv_len251, 0},
	{"timestamp_tlv_len252", "p254.pcap", construct_timestamp_tlv_len252, 0},
	{"timestamp_tlv_len253", "p255.pcap", construct_timestamp_tlv_len253, 0},
	{"timestamp_tlv_len254", "p256.pcap", construct_timestamp_tlv_len254, 0},
	{"timestamp_tlv_len255", "p257.pcap", construct_timestamp_tlv_len255, 0},

	{NULL, NULL, NULL, 0}
};

#endif
void construct_timestamp_tlv_len1_rrr(void)
{
	*ptr++ = 0xA8;

	*(uint16_t*)ptr = htons(2);
	ptr += 2;

	*ptr++ = 0x01;
	*ptr++ = 0x41;   // 'A'
}

void construct_k3_e3_len0(void)
{
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(0); // invalid
	ptr += 2;

	// no value

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_k_tlv_ruid_6(void)
{
	// -------- K TLV --------
	*ptr++ = em_tlv_type_channel_scan_rslt;   // K TLV Type

	*(uint16_t*)ptr = htons(6);   // Length = 6
	ptr += 2;

	// Only 6 bytes (partial data - RUID only)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_k_tlv_ruid_op(void)
{
	construct_timestamp_tlv();
	// -------- K TLV --------
	*ptr++ = em_tlv_type_channel_scan_rslt;   // K TLV Type

	*(uint16_t*)ptr = htons(7);   // Length = 6 (intentionally small)
	ptr += 2;

	// RUID (6 bytes)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	// 👇 These are OUTSIDE declared length (intentional)
	*ptr++ = 81;   // op_class

	// NO EOM
//	construct_eom();
}

void construct_k_tlv_ruid_op_channel(void)
{
	construct_timestamp_tlv();
	// -------- K TLV --------
	*ptr++ = em_tlv_type_channel_scan_rslt;   // K TLV Type

	*(uint16_t*)ptr = htons(8);   // Length = 6 (intentionally small)
	ptr += 2;

	// RUID (6 bytes)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	// 👇 These are OUTSIDE declared length (intentional)
	*ptr++ = 81;   // op_class
	*ptr++ = 6;    // channel

	// NO EOM
//	construct_eom();
}

void construct_k_tlv_flag_0(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	*ptr++ = 0x00;
	construct_eom();
}

void construct_k_tlv_flag_1(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	*ptr++ = 0x01;
	construct_eom();
}

void construct_k_tlv_flag_2(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	*ptr++ = 0x02;
	construct_eom();
}

void construct_k_tlv_flag_3(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	*ptr++ = 0x03;
	construct_eom();
}

void construct_k_tlv_flag_4(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 0; i <= 4; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_5(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 5; i <= 5; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_6(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 6; i <= 6; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_7(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 7; i <= 7; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_8(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 8; i <= 8; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_9(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 9; i <= 9; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_10(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 10; i <= 10; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_11(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 11; i <= 11; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_12(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 12; i <= 12; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_13(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 13; i <= 13; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_14(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 14; i <= 14; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_15(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 15; i <= 15; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_16(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 16; i <= 16; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_17(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 17; i <= 17; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_18(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 18; i <= 18; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_19(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 19; i <= 19; i++) *ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_20(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 20; i <= 20; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_21(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 21; i <= 21; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_22(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 22; i <= 22; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_23(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 23; i <= 23; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_24(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 24; i <= 24; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_25(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 25; i <= 25; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_26(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 26; i <= 26; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_27(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 27; i <= 27; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_28(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 28; i <= 28; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_29(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 29; i <= 29; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_30(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 30; i <= 30; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_31(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 31; i <= 31; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_32(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 32; i <= 32; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_33(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 33; i <= 33; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_34(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 34; i <= 34; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_35(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 35; i <= 35; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_36(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 36; i <= 36; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_37(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 37; i <= 37; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_38(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 38; i <= 38; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_39(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 39; i <= 39; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_40(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 40; i <= 40; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_41(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 41; i <= 41; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_42(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 42; i <= 42; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_43(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 43; i <= 43; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_44(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 44; i <= 44; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_45(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 45; i <= 45; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_46(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 46; i <= 46; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_47(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 47; i <= 47; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_48(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 48; i <= 48; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_49(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 49; i <= 49; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_50(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 50; i <= 50; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_51(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 51; i <= 51; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_52(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 52; i <= 52; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_53(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 53; i <= 53; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_54(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 54; i <= 54; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_55(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 55; i <= 55; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_56(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 56; i <= 56; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_57(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 57; i <= 57; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_58(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 58; i <= 58; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_59(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 59; i <= 59; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_60(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 60; i <= 60; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_61(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 61; i <= 61; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_62(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 62; i <= 62; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_63(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 63; i <= 63; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_64(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 64; i <= 64; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_65(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 65; i <= 65; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_66(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 66; i <= 66; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_67(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 67; i <= 67; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_68(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 68; i <= 68; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_69(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 69; i <= 69; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_70(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 70; i <= 70; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_71(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 71; i <= 71; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_72(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 72; i <= 72; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_73(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 73; i <= 73; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_74(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 74; i <= 74; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_75(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 75; i <= 75; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_76(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 76; i <= 76; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_77(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 77; i <= 77; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_78(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 78; i <= 78; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_79(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 79; i <= 79; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_80(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 80; i <= 80; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_81(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 81; i <= 81; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_82(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 82; i <= 82; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_83(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 83; i <= 83; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_84(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 84; i <= 84; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_85(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 85; i <= 85; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_86(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 86; i <= 86; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_87(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 87; i <= 87; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_88(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 88; i <= 88; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_89(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 89; i <= 89; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_90(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 90; i <= 90; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_91(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 91; i <= 91; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_92(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 92; i <= 92; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_93(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 93; i <= 93; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_94(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 94; i <= 94; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_95(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 95; i <= 95; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_96(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 96; i <= 96; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_97(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 97; i <= 97; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_98(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 98; i <= 98; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_99(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 99; i <= 99; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_100(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 100; i <= 100; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_101(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 101; i <= 101; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_102(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 102; i <= 102; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_103(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 103; i <= 103; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_104(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 104; i <= 104; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_105(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 105; i <= 105; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_106(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 106; i <= 106; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_107(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 107; i <= 107; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_108(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 108; i <= 108; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_109(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 109; i <= 109; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_110(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 110; i <= 110; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_111(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 111; i <= 111; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_112(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 112; i <= 112; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_113(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 113; i <= 113; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_114(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 114; i <= 114; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_115(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 115; i <= 115; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_116(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 116; i <= 116; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_117(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 117; i <= 117; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_118(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 118; i <= 118; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_119(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 119; i <= 119; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_120(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 120; i <= 120; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_121(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 121; i <= 121; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_122(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 122; i <= 122; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_123(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 123; i <= 123; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_124(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 124; i <= 124; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_125(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 125; i <= 125; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_126(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 126; i <= 126; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_127(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 127; i <= 127; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_128(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 128; i <= 128; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_129(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 129; i <= 129; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_130(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 130; i <= 130; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_131(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 131; i <= 131; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_132(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 132; i <= 132; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_133(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 133; i <= 133; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_134(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 134; i <= 134; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_135(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 135; i <= 135; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_136(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 136; i <= 136; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_137(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 137; i <= 137; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_138(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 138; i <= 138; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_139(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 139; i <= 139; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_140(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 140; i <= 140; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_141(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 141; i <= 141; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_142(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 142; i <= 142; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_143(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 143; i <= 143; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_144(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 144; i <= 144; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_145(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 145; i <= 145; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_146(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 146; i <= 146; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_147(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 147; i <= 147; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_148(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 148; i <= 148; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_149(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 149; i <= 149; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_150(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 150; i <= 150; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_151(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 151; i <= 151; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_152(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 152; i <= 152; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_153(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 153; i <= 153; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_154(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 154; i <= 154; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_155(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 155; i <= 155; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_156(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 156; i <= 156; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_157(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 157; i <= 157; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_158(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 158; i <= 158; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_159(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 159; i <= 159; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_160(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 160; i <= 160; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_161(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 161; i <= 161; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_162(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 162; i <= 162; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_163(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 163; i <= 163; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_164(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 164; i <= 164; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_165(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 165; i <= 165; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_166(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 166; i <= 166; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_167(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 167; i <= 167; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_168(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 168; i <= 168; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_169(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 169; i <= 169; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_170(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 170; i <= 170; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_171(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 171; i <= 171; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_172(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 172; i <= 172; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_173(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 173; i <= 173; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_174(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 174; i <= 174; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_175(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 175; i <= 175; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_176(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 176; i <= 176; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_177(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 177; i <= 177; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_178(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 178; i <= 178; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_179(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 179; i <= 179; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_180(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 180; i <= 180; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_181(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 181; i <= 181; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_182(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 182; i <= 182; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_183(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 183; i <= 183; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_184(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 184; i <= 184; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_185(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 185; i <= 185; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_186(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 186; i <= 186; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_187(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 187; i <= 187; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_188(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 188; i <= 188; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_189(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 189; i <= 189; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_190(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 190; i <= 190; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_191(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 191; i <= 191; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_192(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 192; i <= 192; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_193(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 193; i <= 193; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_194(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 194; i <= 194; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_195(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 195; i <= 195; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_196(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 196; i <= 196; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_197(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 197; i <= 197; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_198(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 198; i <= 198; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_199(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 199; i <= 199; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_200(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 200; i <= 200; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_201(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 201; i <= 201; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_202(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 202; i <= 202; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_203(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 203; i <= 203; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_204(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 204; i <= 204; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_205(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 205; i <= 205; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_206(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 206; i <= 206; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_207(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 207; i <= 207; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_208(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 208; i <= 208; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_209(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 209; i <= 209; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_210(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 210; i <= 210; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_211(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 211; i <= 211; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_212(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 212; i <= 212; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_213(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 213; i <= 213; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_214(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 214; i <= 214; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_215(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 215; i <= 215; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_216(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 216; i <= 216; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_217(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 217; i <= 217; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_218(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 218; i <= 218; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_219(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 219; i <= 219; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_220(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 220; i <= 220; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_221(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 221; i <= 221; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_222(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 222; i <= 222; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_223(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 223; i <= 223; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_224(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 224; i <= 224; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_225(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 225; i <= 225; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_226(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 226; i <= 226; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_227(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 227; i <= 227; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_228(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 228; i <= 228; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_229(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 229; i <= 229; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_230(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 230; i <= 230; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_231(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 231; i <= 231; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_232(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 232; i <= 232; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_233(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 233; i <= 233; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_234(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 234; i <= 234; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_235(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 235; i <= 235; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_236(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 236; i <= 236; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_237(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 237; i <= 237; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_238(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 238; i <= 238; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_239(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 239; i <= 239; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_240(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 240; i <= 240; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_241(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 241; i <= 241; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_242(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 242; i <= 242; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_243(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 243; i <= 243; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_244(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 244; i <= 244; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_245(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 245; i <= 245; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_246(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 246; i <= 246; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_247(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 247; i <= 247; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_248(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 248; i <= 248; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_249(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 249; i <= 249; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_250(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 250; i <= 250; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_251(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 251; i <= 251; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_252(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 252; i <= 252; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_253(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 253; i <= 253; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_254(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 254; i <= 254; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_flag_255(void)
{
	construct_timestamp_tlv();
	construct_k_tlv_ruid_op_channel();
	for (int i = 255; i <= 255; i++)
		*ptr++ = i;
	construct_eom();
}

void construct_k_tlv_ts_len0(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x00;
	construct_eom();
}

void construct_k_tlv_ts_len1(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(11);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x01;
	*ptr++ = 0x41;
	construct_eom();
}

void construct_k_tlv_ts_len2(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(12);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x02;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	construct_eom();
}

void construct_k_tlv_ts_len3(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(13);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	for (int i = 0; i < 3; i++) *ptr++ = 0x41 + i;
	construct_eom();
}

void construct_k_tlv_ts_len4(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(14);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x04;
	for (int i = 0; i < 4; i++) *ptr++ = 0x41 + i;
	construct_eom();
}

void construct_k_tlv_ts_len5(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(15);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x05;
	for (int i = 0; i < 5; i++) *ptr++ = 0x41 + i;
	construct_eom();
}

void construct_k_tlv_ts_len6(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(16);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x06;
	for (int i = 0; i < 6; i++) *ptr++ = 0x41 + i;
	construct_eom();
}

void construct_k_tlv_ts_len7(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(17);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x07;
	for (int i = 0; i < 7; i++) *ptr++ = 0x41 + i;
	construct_eom();
}

void construct_k_tlv_ts_len8(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(18);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x08;
	for (int i = 0; i < 8; i++) *ptr++ = 0x41 + i;
	construct_eom();
}

void construct_k_tlv_ts_len9(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(19);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x09;
	for (int i = 0; i < 9; i++) *ptr++ = 0x41 + i;
	construct_eom();
}

void construct_k_tlv_ts_len10(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(20);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x0A;
	for (int i = 0; i < 10; i++) *ptr++ = 0x41 + i;
	construct_eom();
}

void construct_k_tlv_ts_len11(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(21); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 11;
	for(int i=0;i<11;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len12(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(22); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 12;
	for(int i=0;i<12;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len13(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(23); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 13;
	for(int i=0;i<13;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len14(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(24); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 14;
	for(int i=0;i<14;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len15(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(25); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 15;
	for(int i=0;i<15;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len16(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(26); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 16;
	for(int i=0;i<16;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len17(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(27); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 17;
	for(int i=0;i<17;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len18(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(28); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 18;
	for(int i=0;i<18;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len19(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(29); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 19;
	for(int i=0;i<19;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len20(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(30); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 20;
	for(int i=0;i<20;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len21(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(31); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 21;
	for(int i=0;i<21;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len22(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(32); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 22;
	for(int i=0;i<22;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len23(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(33); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 23;
	for(int i=0;i<23;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len24(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(34); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 24;
	for(int i=0;i<24;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len25(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(35); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 25;
	for(int i=0;i<25;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len26(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(36); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 26;
	for(int i=0;i<26;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len27(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(37); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 27;
	for(int i=0;i<27;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len28(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(38); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 28;
	for(int i=0;i<28;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len29(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(39); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 29;
	for(int i=0;i<29;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len30(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(40); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 30;
	for(int i=0;i<30;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len31(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(41);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 31;
	for (int i = 0; i < 31; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len32(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(42);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 32;
	for (int i = 0; i < 32; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len33(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(43);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 33;
	for (int i = 0; i < 33; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len34(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(44);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 34;
	for (int i = 0; i < 34; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len35(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(45);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 35;
	for (int i = 0; i < 35; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len36(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(46);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 36;
	for (int i = 0; i < 36; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len37(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(47);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 37;
	for (int i = 0; i < 37; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len38(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(48);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 38;
	for (int i = 0; i < 38; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len39(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(49);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 39;
	for (int i = 0; i < 39; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len40(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(50);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 40;
	for (int i = 0; i < 40; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len41(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(51);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 41;
	for(int i=0;i<41;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len42(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(52);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 42;
	for(int i=0;i<42;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len43(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(53);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 43;
	for(int i=0;i<43;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len44(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(54);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 44;
	for(int i=0;i<44;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len45(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(55);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 45;
	for(int i=0;i<45;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len46(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(56);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 46;
	for(int i=0;i<46;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len47(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(57);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 47;
	for(int i=0;i<47;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len48(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(58);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 48;
	for(int i=0;i<48;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len49(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(59);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 49;
	for(int i=0;i<49;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len50(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(60);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 50;
	for(int i=0;i<50;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len51(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(61);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 51;
	for(int i=0;i<51;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len52(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(62);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 52;
	for(int i=0;i<52;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len53(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(63);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 53;
	for(int i=0;i<53;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len54(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(64);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 54;
	for(int i=0;i<54;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len55(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(65);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 55;
	for(int i=0;i<55;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len56(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(66);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 56;
	for(int i=0;i<56;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len57(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(67);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 57;
	for(int i=0;i<57;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len58(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(68);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 58;
	for(int i=0;i<58;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len59(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(69);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 59;
	for(int i=0;i<59;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len60(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(70);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 60;
	for(int i=0;i<60;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len61(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(71);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 61;
	for(int i=0;i<61;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len62(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(72);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 62;
	for(int i=0;i<62;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len63(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(73);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 63;
	for(int i=0;i<63;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len64(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(74);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 64;
	for(int i=0;i<64;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len65(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(75);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 65;
	for(int i=0;i<65;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len66(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(76);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 66;
	for(int i=0;i<66;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len67(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(77);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 67;
	for(int i=0;i<67;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len68(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(78);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 68;
	for(int i=0;i<68;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len69(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(79);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 69;
	for(int i=0;i<69;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len70(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(80);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 70;
	for(int i=0;i<70;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len71(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(81);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 71;
	for(int i=0;i<71;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len72(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(82);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 72;
	for(int i=0;i<72;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len73(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(83);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 73;
	for(int i=0;i<73;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len74(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(84);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 74;
	for(int i=0;i<74;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len75(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(85);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 75;
	for(int i=0;i<75;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len76(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(86);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 76;
	for(int i=0;i<76;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len77(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(87);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 77;
	for(int i=0;i<77;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len78(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(88);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 78;
	for(int i=0;i<78;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len79(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(89);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 79;
	for(int i=0;i<79;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len80(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(90);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 80;
	for(int i=0;i<80;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len81(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(91);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 81;
	for(int i=0;i<81;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len82(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(92);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 82;
	for(int i=0;i<82;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len83(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(93);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 83;
	for(int i=0;i<83;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len84(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(94);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 84;
	for(int i=0;i<84;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len85(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(95);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 85;
	for(int i=0;i<85;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len86(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(96);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 86;
	for(int i=0;i<86;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len87(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(97);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 87;
	for(int i=0;i<87;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len88(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(98);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 88;
	for(int i=0;i<88;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len89(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(99);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 89;
	for(int i=0;i<89;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len90(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(100);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 90;
	for(int i=0;i<90;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len91(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(101);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 91;
	for(int i=0;i<91;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len92(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(102);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 92;
	for(int i=0;i<92;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len93(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(103);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 93;
	for(int i=0;i<93;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len94(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(104);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 94;
	for(int i=0;i<94;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len95(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(105);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 95;
	for(int i=0;i<95;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len96(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(106);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 96;
	for(int i=0;i<96;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len97(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(107);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 97;
	for(int i=0;i<97;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len98(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(108);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 98;
	for(int i=0;i<98;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len99(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(109);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 99;
	for(int i=0;i<99;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len100(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(110);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 100;
	for(int i=0;i<100;i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len101(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 101);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 101;

	for (int i = 0; i < 101; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len102(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 102);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 102;

	for (int i = 0; i < 102; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len103(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 103);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 103;

	for (int i = 0; i < 103; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len104(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 104);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 104;

	for (int i = 0; i < 104; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len105(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 105);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 105;

	for (int i = 0; i < 105; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len106(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 106);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 106;

	for (int i = 0; i < 106; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len107(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 107);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 107;

	for (int i = 0; i < 107; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len108(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 108);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 108;

	for (int i = 0; i < 108; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len109(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 109);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 109;

	for (int i = 0; i < 109; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len110(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 110);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 110;

	for (int i = 0; i < 110; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len111(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(121);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 111;
	for (int i = 0; i < 111; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len112(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(122);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 112;
	for (int i = 0; i < 112; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len113(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(123);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 113;
	for (int i = 0; i < 113; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len114(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(124);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 114;
	for (int i = 0; i < 114; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len115(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(125);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 115;
	for (int i = 0; i < 115; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len116(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(126);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 116;
	for (int i = 0; i < 116; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len117(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(127);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 117;
	for (int i = 0; i < 117; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len118(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(128);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 118;
	for (int i = 0; i < 118; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len119(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(129);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 119;
	for (int i = 0; i < 119; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len120(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(130);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 120;
	for (int i = 0; i < 120; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len121(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(131);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 121;
	for (int i = 0; i < 121; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len122(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(132);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 122;
	for (int i = 0; i < 122; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len123(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(133);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 123;
	for (int i = 0; i < 123; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len124(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(134);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 124;
	for (int i = 0; i < 124; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len125(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(135);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 125;
	for (int i = 0; i < 125; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len126(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(136);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 126;
	for (int i = 0; i < 126; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len127(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(137);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 127;
	for (int i = 0; i < 127; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len128(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(138);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 128;
	for (int i = 0; i < 128; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len129(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(139);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 129;
	for (int i = 0; i < 129; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len130(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(140);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 130;
	for (int i = 0; i < 130; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len131(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 131);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 131;

	for (int i = 0; i < 131; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len132(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 132);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 132;

	for (int i = 0; i < 132; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len133(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 133);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 133;

	for (int i = 0; i < 133; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len134(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 134);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 134;

	for (int i = 0; i < 134; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len135(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 135);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 135;

	for (int i = 0; i < 135; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len136(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 136);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 136;

	for (int i = 0; i < 136; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len137(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 137);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 137;

	for (int i = 0; i < 137; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len138(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 138);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 138;

	for (int i = 0; i < 138; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len139(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 139);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 139;

	for (int i = 0; i < 139; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len140(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 140);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 140;

	for (int i = 0; i < 140; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len141(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 141);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 141;

	for (int i = 0; i < 141; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len142(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 142);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 142;

	for (int i = 0; i < 142; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len143(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 143);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 143;

	for (int i = 0; i < 143; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len144(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 144);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 144;

	for (int i = 0; i < 144; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len145(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 145);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 145;

	for (int i = 0; i < 145; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len146(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 146);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 146;

	for (int i = 0; i < 146; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len147(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 147);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 147;

	for (int i = 0; i < 147; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len148(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 148);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 148;

	for (int i = 0; i < 148; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len149(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 149);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 149;

	for (int i = 0; i < 149; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len150(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 150);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 150;

	for (int i = 0; i < 150; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len151(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 151);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 151;
	for (int i = 0; i < 151; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len152(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 152);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 152;
	for (int i = 0; i < 152; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len153(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 153);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 153;
	for (int i = 0; i < 153; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len154(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 154);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 154;
	for (int i = 0; i < 154; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len155(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 155);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 155;
	for (int i = 0; i < 155; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len156(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 156);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 156;
	for (int i = 0; i < 156; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len157(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 157);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 157;
	for (int i = 0; i < 157; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len158(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 158);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 158;
	for (int i = 0; i < 158; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len159(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 159);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 159;
	for (int i = 0; i < 159; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len160(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 160);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 160;
	for (int i = 0; i < 160; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len161(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 161);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 161;
	for (int i = 0; i < 161; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len162(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 162);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 162;
	for (int i = 0; i < 162; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len163(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 163);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 163;
	for (int i = 0; i < 163; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len164(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 164);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 164;
	for (int i = 0; i < 164; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len165(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 165);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 165;
	for (int i = 0; i < 165; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len166(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 166);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 166;
	for (int i = 0; i < 166; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len167(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 167);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 167;
	for (int i = 0; i < 167; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len168(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 168);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 168;
	for (int i = 0; i < 168; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len169(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 169);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 169;
	for (int i = 0; i < 169; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len170(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 170);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 170;
	for (int i = 0; i < 170; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len171(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(181);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 171;

	for(int i = 0; i < 171; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len172(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(182);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 172;

	for(int i = 0; i < 172; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len173(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(183);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 173;

	for(int i = 0; i < 173; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len174(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(184);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 174;

	for(int i = 0; i < 174; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len175(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(185);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 175;

	for(int i = 0; i < 175; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len176(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(186);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 176;

	for(int i = 0; i < 176; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len177(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(187);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 177;

	for(int i = 0; i < 177; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len178(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(188);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 178;

	for(int i = 0; i < 178; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len179(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(189);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 179;

	for(int i = 0; i < 179; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len180(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(190);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 180;

	for(int i = 0; i < 180; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len181(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(191);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 181;

	for(int i = 0; i < 181; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len182(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(192);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 182;

	for(int i = 0; i < 182; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len183(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(193);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 183;

	for(int i = 0; i < 183; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len184(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(194);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 184;

	for(int i = 0; i < 184; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len185(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(195);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 185;

	for(int i = 0; i < 185; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len186(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(196);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 186;

	for(int i = 0; i < 186; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len187(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(197);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 187;

	for(int i = 0; i < 187; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len188(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(198);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 188;

	for(int i = 0; i < 188; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len189(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(199);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 189;

	for(int i = 0; i < 189; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len190(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(200);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 190;

	for(int i = 0; i < 190; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len191(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 191);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 191;
	for (int i = 0; i < 191; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len192(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 192);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 192;
	for (int i = 0; i < 192; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len193(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 193);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 193;
	for (int i = 0; i < 193; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len194(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 194);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 194;
	for (int i = 0; i < 194; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len195(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 195);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 195;
	for (int i = 0; i < 195; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len196(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 196);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 196;
	for (int i = 0; i < 196; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len197(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 197);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 197;
	for (int i = 0; i < 197; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len198(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 198);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 198;
	for (int i = 0; i < 198; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len199(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 199);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 199;
	for (int i = 0; i < 199; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len200(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 200);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 200;
	for (int i = 0; i < 200; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len201(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 201);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 201;
	for (int i = 0; i < 201; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len202(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 202);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 202;
	for (int i = 0; i < 202; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len203(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 203);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 203;
	for (int i = 0; i < 203; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len204(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 204);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 204;
	for (int i = 0; i < 204; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len205(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 205);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 205;
	for (int i = 0; i < 205; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len206(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 206);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 206;
	for (int i = 0; i < 206; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len207(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 207);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 207;
	for (int i = 0; i < 207; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len208(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 208);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 208;
	for (int i = 0; i < 208; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len209(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 209);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 209;
	for (int i = 0; i < 209; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len210(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 210);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 210;
	for (int i = 0; i < 210; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len211(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 211);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 211;

	for(int i = 0; i < 211; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len212(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 212);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 212;

	for(int i = 0; i < 212; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len213(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 213);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 213;

	for(int i = 0; i < 213; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len214(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 214);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 214;

	for(int i = 0; i < 214; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len215(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 215);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 215;

	for(int i = 0; i < 215; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len216(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 216);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 216;

	for(int i = 0; i < 216; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len217(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 217);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 217;

	for(int i = 0; i < 217; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len218(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 218);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 218;

	for(int i = 0; i < 218; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len219(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 219);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 219;

	for(int i = 0; i < 219; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len220(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 220);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 220;

	for(int i = 0; i < 220; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len221(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 221);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 221;

	for(int i = 0; i < 221; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len222(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 222);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 222;

	for(int i = 0; i < 222; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len223(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 223);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 223;

	for(int i = 0; i < 223; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len224(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 224);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 224;

	for(int i = 0; i < 224; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len225(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 225);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 225;

	for(int i = 0; i < 225; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len226(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 226);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 226;

	for(int i = 0; i < 226; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len227(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 227);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 227;

	for(int i = 0; i < 227; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len228(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 228);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 228;

	for(int i = 0; i < 228; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len229(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 229);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 229;

	for(int i = 0; i < 229; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len230(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(10 + 230);
	ptr += 2;

	for(int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 230;

	for(int i = 0; i < 230; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len231(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(241);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 231;
	for (int i = 0; i < 231; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len232(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(242);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 232;
	for (int i = 0; i < 232; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len233(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(243);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 233;
	for (int i = 0; i < 233; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len234(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(244);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 234;
	for (int i = 0; i < 234; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len235(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(245);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 235;
	for (int i = 0; i < 235; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len236(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(246);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 236;
	for (int i = 0; i < 236; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len237(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(247);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 237;
	for (int i = 0; i < 237; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len238(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(248);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 238;
	for (int i = 0; i < 238; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len239(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(249);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 239;
	for (int i = 0; i < 239; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len240(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(250);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 240;
	for (int i = 0; i < 240; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len241(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(251);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 241;
	for (int i = 0; i < 241; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len242(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(252);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 242;
	for (int i = 0; i < 242; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len243(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(253);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 243;
	for (int i = 0; i < 243; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len244(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(254);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 244;
	for (int i = 0; i < 244; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len245(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(255);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 245;
	for (int i = 0; i < 245; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len246(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(256);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 246;
	for (int i = 0; i < 246; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len247(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(257);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 247;
	for (int i = 0; i < 247; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len248(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(258);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 248;
	for (int i = 0; i < 248; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len249(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(259);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 249;
	for (int i = 0; i < 249; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len250(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(260);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 250;
	for (int i = 0; i < 250; i++) *ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len251(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(261);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 251;

	for (int i = 0; i < 251; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len252(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(262);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 252;

	for (int i = 0; i < 252; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len253(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(263);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 253;

	for (int i = 0; i < 253; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len254(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(264);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 254;

	for (int i = 0; i < 254; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts_len255(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(265);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 255;

	for (int i = 0; i < 255; i++)
		*ptr++ = 0x41 + (i % 26);
	construct_eom();
}

void construct_k_tlv_ts3_util(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(14);   // total value length
	ptr += 2;

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	// utilization
	*ptr++ = 0x20;
	construct_eom();
}

void construct_k_tlv_ts3_util_noise(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(15);   // total value length
	ptr += 2;

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	// utilization
	*ptr++ = 0x20;

	// noise
	*ptr++ = 0x10;
	construct_eom();
}

void construct_k_tlv_ts3_full_no_neighbors(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(17);   // total value length
	ptr += 2;

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	// utilization
	*ptr++ = 0x20;

	// noise
	*ptr++ = 0x10;

	// num_neighbors (2 bytes)
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_ts3_with_bssid(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(23);   // total value length
	ptr += 2;

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	// utilization
	*ptr++ = 0x20;

	// noise
	*ptr++ = 0x10;

	// num_neighbors (1)
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor entry --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	construct_eom();
}

void construct_k_tlv_ts3_with_bssid_ssidlen(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(24);   // total value length
	ptr += 2;

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	// utilization
	*ptr++ = 0x20;

	// noise
	*ptr++ = 0x10;

	// num_neighbors (1)
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor entry --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length (1)
	*ptr++ = 0x04;   // example SSID length = 4
	construct_eom();
}

void construct_k_tlv_ssid_len0(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(23); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;      // RUID
	*ptr++ = 81;                          // op_class
	*ptr++ = 6;                           // channel
	*ptr++ = 0x00;                        // flag

	*ptr++ = 3;                           // ts_len
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20;                        // utilization
	*ptr++ = 0x10;                        // noise

	*(uint16_t*)ptr = htons(1); ptr += 2; // num_neighbors

	for(int i=0;i<6;i++) *ptr++ = i+10;   // BSSID

	*ptr++ = 0;                           // SSID_len = 0
	construct_eom();
}

void construct_k_tlv_ssid_len1(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(25); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 1;
	*ptr++ = 'A';
	construct_eom();
}

void construct_k_tlv_ssid_len2(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(26); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 2;
	*ptr++ = 'A'; *ptr++ = 'B';
	construct_eom();
}

void construct_k_tlv_ssid_len3(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(27); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 3;
	for(int i=0;i<3;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_tlv_ssid_len4(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(28); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	for(int i=0;i<4;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_tlv_ssid_len5(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(29); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 5;
	for(int i=0;i<5;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_tlv_ssid_len6(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(30); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 6;
	for(int i=0;i<6;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_tlv_ssid_len7(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(31); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 7;
	for(int i=0;i<7;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_tlv_ssid_len8(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(32); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 8;
	for(int i=0;i<8;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_tlv_ssid_len9(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(33); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 9;
	for(int i=0;i<9;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_tlv_ssid_len10(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(34); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 10;
	for(int i=0;i<10;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_tlv_ssid_len11(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(35); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 11;
	for(int i=0;i<11;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len12(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(36); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 12;
	for(int i=0;i<12;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len13(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(37); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 13;
	for(int i=0;i<13;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len14(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(38); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 14;
	for(int i=0;i<14;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len15(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(39); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 15;
	for(int i=0;i<15;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len16(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(40); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 16;
	for(int i=0;i<16;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len17(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(41); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 17;
	for(int i=0;i<17;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len18(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(42); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 18;
	for(int i=0;i<18;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len19(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(43); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 19;
	for(int i=0;i<19;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len20(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(44); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 20;
	for(int i=0;i<20;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len21(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(45); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 21;
	for(int i=0;i<21;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len22(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(46); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 22;
	for(int i=0;i<22;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len23(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(47); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 23;
	for(int i=0;i<23;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len24(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(48); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 24;
	for(int i=0;i<24;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len25(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(49); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 25;
	for(int i=0;i<25;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len26(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(50); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 26;
	for(int i=0;i<26;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len27(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(51); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 27;
	for(int i=0;i<27;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len28(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(52); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 28;
	for(int i=0;i<28;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len29(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(53); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 29;
	for(int i=0;i<29;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len30(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(54); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 30;
	for(int i=0;i<30;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len31(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(55); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 31;
	for(int i=0;i<31;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len32(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(56); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 32;
	for(int i=0;i<32;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len33(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;;
	*(uint16_t*)ptr = htons(57); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 33;
	for(int i=0;i<33;i++) *ptr++ = 'A' + (i % 26);

	construct_eom();
}

void construct_k_tlv_ssid_len34(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(58); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 34;
	for(int i=0;i<34;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len35(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(59); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 35;
	for(int i=0;i<35;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len36(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(60); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 36;
	for(int i=0;i<36;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len37(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(61); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 37;
	for(int i=0;i<37;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len38(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(62); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 38;
	for(int i=0;i<38;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len39(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(63); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 39;
	for(int i=0;i<39;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len40(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(64); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 40;
	for(int i=0;i<40;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len41(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(65); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 41;
	for(int i=0;i<41;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len42(void)
{
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(66); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 42;
	for(int i=0;i<42;i++) *ptr++ = 'A' + (i % 26);
}
 
void construct_k_tlv_ssid_len43(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(67); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 43;
	for(int i=0;i<43;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len44(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(68); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 44;
	for(int i=0;i<44;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len45(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(69); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 45;
	for(int i=0;i<45;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len46(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(70); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 46;
	for(int i=0;i<46;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len47(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(71); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 47;
	for(int i=0;i<47;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len48(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(72); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 48;
	for(int i=0;i<48;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len49(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(73); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 49;
	for(int i=0;i<49;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len50(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(74); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 50;
	for(int i=0;i<50;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len51(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(75); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 51;
	for(int i=0;i<51;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len52(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(76); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 52;
	for(int i=0;i<52;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len53(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(77); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 53;
	for(int i=0;i<53;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len54(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(78); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 54;
	for(int i=0;i<54;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len55(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(79); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 55;
	for(int i=0;i<55;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len56(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(80); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 56;
	for(int i=0;i<56;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len57(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(81); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 57;
	for(int i=0;i<57;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len58(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(82); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 58;
	for(int i=0;i<58;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len59(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(83); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 59;
	for(int i=0;i<59;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len60(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(84); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 60;
	for(int i=0;i<60;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len61(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(85); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 61;
	for(int i=0;i<61;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len62(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(86); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 62;
	for(int i=0;i<62;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len63(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(87); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 63;
	for(int i=0;i<63;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len64(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(88); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 64;
	for(int i=0;i<64;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len65(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(89); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 65;
	for(int i=0;i<65;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len66(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(90); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 66;
	for(int i=0;i<66;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len67(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(91); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 67;
	for(int i=0;i<67;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len68(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(92); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 68;
	for(int i=0;i<68;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len69(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(93); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 69;
	for(int i=0;i<69;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len70(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(94); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 70;
	for(int i=0;i<70;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len71(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(95); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 71;
	for(int i=0;i<71;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len72(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(96); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 72;
	for(int i=0;i<72;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len73(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(97); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 73;
	for(int i=0;i<73;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len74(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(98); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 74;
	for(int i=0;i<74;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len75(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(99); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 75;
	for(int i=0;i<75;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len76(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(100); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 76;
	for(int i=0;i<76;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len77(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(101); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 77;
	for(int i=0;i<77;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len78(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(102); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 78;
	for(int i=0;i<78;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len79(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(103); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 79;
	for(int i=0;i<79;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len80(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(104); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 80;
	for(int i=0;i<80;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len81(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(105); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 81;
	for(int i=0;i<81;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len82(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(106); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 82;
	for(int i=0;i<82;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len83(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(107); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 83;
	for(int i=0;i<83;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len84(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(108); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 84;
	for(int i=0;i<84;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len85(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(109); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 85;
	for(int i=0;i<85;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len86(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(110); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 86;
	for(int i=0;i<86;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len87(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(111); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 87;
	for(int i=0;i<87;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len88(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(112); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 88;
	for(int i=0;i<88;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len89(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(113); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 89;
	for(int i=0;i<89;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len90(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(114); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 90;
	for(int i=0;i<90;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len91(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(115); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 91;
	for(int i=0;i<91;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len92(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(116); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 92;
	for(int i=0;i<92;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len93(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(117); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 93;
	for(int i=0;i<93;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len94(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(118); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 94;
	for(int i=0;i<94;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len95(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(119); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 95;
	for(int i=0;i<95;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len96(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(120); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 96;
	for(int i=0;i<96;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len97(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(121); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 97;
	for(int i=0;i<97;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len98(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(122); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 98;
	for(int i=0;i<98;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len99(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(123); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 99;
	for(int i=0;i<99;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len100(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(124); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 100;
	for(int i=0;i<100;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len101(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(125); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 101;
	for(int i=0;i<101;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len102(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(126); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 102;
	for(int i=0;i<102;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len103(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(127); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 103;
	for(int i=0;i<103;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len104(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(128); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 104;
	for(int i=0;i<104;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len105(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(129); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 105;
	for(int i=0;i<105;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len106(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(130); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 106;
	for(int i=0;i<106;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len107(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(131); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 107;
	for(int i=0;i<107;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len108(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(132); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 108;
	for(int i=0;i<108;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len109(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(133); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 109;
	for(int i=0;i<109;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len110(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(134); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 110;
	for(int i=0;i<110;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len111(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(135); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 111;
	for(int i=0;i<111;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len112(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(136); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 112;
	for(int i=0;i<112;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len113(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(137); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 113;
	for(int i=0;i<113;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len114(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(138); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 114;
	for(int i=0;i<114;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len115(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(139); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 115;
	for(int i=0;i<115;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len116(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(140); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 116;
	for(int i=0;i<116;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len117(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(141); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 117;
	for(int i=0;i<117;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len118(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(142); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 118;
	for(int i=0;i<118;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len119(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(143); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 119;
	for(int i=0;i<119;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len120(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(144); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 120;
	for(int i=0;i<120;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len121(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(145); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 121;
	for(int i=0;i<121;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len122(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(146); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 122;
	for(int i=0;i<122;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len123(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(147); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 123;
	for(int i=0;i<123;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len124(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(148); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 124;
	for(int i=0;i<124;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len125(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(149); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 125;
	for(int i=0;i<125;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len126(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(150); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 126;
	for(int i=0;i<126;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len127(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(151); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 127;
	for(int i=0;i<127;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len128(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(152); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 128;
	for(int i=0;i<128;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len129(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(153); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 129;
	for(int i=0;i<129;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len130(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(154); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 130;
	for(int i=0;i<130;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len131(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(155); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 131;
	for(int i=0;i<131;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len132(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(156); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 132;
	for(int i=0;i<132;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len133(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(157); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 133;
	for(int i=0;i<133;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len134(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(158); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 134;
	for(int i=0;i<134;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len135(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(159); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 135;
	for(int i=0;i<135;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len136(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(160); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 136;
	for(int i=0;i<136;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len137(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(161); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 137;
	for(int i=0;i<137;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len138(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(162); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 138;
	for(int i=0;i<138;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len139(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(163); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 139;
	for(int i=0;i<139;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len140(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(164); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 140;
	for(int i=0;i<140;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len141(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(165); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 141;
	for(int i=0;i<141;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len142(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(166); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 142;
	for(int i=0;i<142;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len143(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(167); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 143;
	for(int i=0;i<143;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len144(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(168); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 144;
	for(int i=0;i<144;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len145(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(169); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 145;
	for(int i=0;i<145;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len146(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(170); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 146;
	for(int i=0;i<146;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len147(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(171); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 147;
	for(int i=0;i<147;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len148(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(172); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 148;
	for(int i=0;i<148;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len149(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(173); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 149;
	for(int i=0;i<149;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len150(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(174); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 150;
	for(int i=0;i<150;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len151(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(175); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 151;
	for(int i=0;i<151;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len152(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(176); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 152;
	for(int i=0;i<152;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len153(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(177); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 153;
	for(int i=0;i<153;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len154(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(178); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 154;
	for(int i=0;i<154;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len155(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(179); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 155;
	for(int i=0;i<155;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len156(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(180); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 156;
	for(int i=0;i<156;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len157(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(181); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 157;
	for(int i=0;i<157;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len158(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(182); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 158;
	for(int i=0;i<158;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len159(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(183); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 159;
	for(int i=0;i<159;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len160(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(184); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 160;
	for(int i=0;i<160;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len161(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(185); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 161;
	for(int i=0;i<161;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len162(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(186); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 162;
	for(int i=0;i<162;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len163(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(187); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 163;
	for(int i=0;i<163;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len164(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(188); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 164;
	for(int i=0;i<164;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len165(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(189); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 165;
	for(int i=0;i<165;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len166(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(190); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 166;
	for(int i=0;i<166;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len167(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(191); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 167;
	for(int i=0;i<167;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len168(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(192); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 168;
	for(int i=0;i<168;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len169(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(193); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 169;
	for(int i=0;i<169;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len170(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(194); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 170;
	for(int i=0;i<170;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len171(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(195); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 171;
	for(int i=0;i<171;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len172(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(196); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 172;
	for(int i=0;i<172;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len173(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(197); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 173;
	for(int i=0;i<173;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len174(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(198); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 174;
	for(int i=0;i<174;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len175(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(199); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 175;
	for(int i=0;i<175;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len176(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(200); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 176;
	for(int i=0;i<176;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len177(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(201); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 177;
	for(int i=0;i<177;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len178(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(202); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 178;
	for(int i=0;i<178;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len179(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(203); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 179;
	for(int i=0;i<179;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len180(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(204); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 180;
	for(int i=0;i<180;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len181(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(205); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 181;
	for(int i=0;i<181;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len182(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(206); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 182;
	for(int i=0;i<182;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len183(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(207); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 183;
	for(int i=0;i<183;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len184(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(208); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 184;
	for(int i=0;i<184;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len185(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(209); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 185;
	for(int i=0;i<185;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len186(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(210); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 186;
	for(int i=0;i<186;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len187(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(211); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 187;
	for(int i=0;i<187;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len188(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(212); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 188;
	for(int i=0;i<188;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len189(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(213); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 189;
	for(int i=0;i<189;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len190(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(214); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 190;
	for(int i=0;i<190;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len191(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(215); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 191;
	for(int i=0;i<191;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len192(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(216); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 192;
	for(int i=0;i<192;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len193(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(217); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 193;
	for(int i=0;i<193;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len194(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(218); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 194;
	for(int i=0;i<194;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len195(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(219); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 195;
	for(int i=0;i<195;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len196(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(220); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 196;
	for(int i=0;i<196;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len197(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(221); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 197;
	for(int i=0;i<197;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len198(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(222); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 198;
	for(int i=0;i<198;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len199(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(223); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 199;
	for(int i=0;i<199;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len200(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(224); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 200;
	for(int i=0;i<200;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len201(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(225); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 201;
	for(int i=0;i<201;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len202(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(226); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 202;
	for(int i=0;i<202;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len203(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(227); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 203;
	for(int i=0;i<203;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len204(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(228); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 204;
	for(int i=0;i<204;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len205(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(229); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 205;
	for(int i=0;i<205;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len206(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(230); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 206;
	for(int i=0;i<206;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len207(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(231); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 207;
	for(int i=0;i<207;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len208(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(232); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 208;
	for(int i=0;i<208;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len209(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(233); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 209;
	for(int i=0;i<209;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len210(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(234); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 210;
	for(int i=0;i<210;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len211(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(235); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 211;
	for(int i=0;i<211;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len212(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(236); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 212;
	for(int i=0;i<212;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len213(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(237); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 213;
	for(int i=0;i<213;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len214(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(238); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 214;
	for(int i=0;i<214;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len215(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(239); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 215;
	for(int i=0;i<215;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len216(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(240); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 216;
	for(int i=0;i<216;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len217(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(241); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 217;
	for(int i=0;i<217;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len218(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(242); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 218;
	for(int i=0;i<218;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len219(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(243); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 219;
	for(int i=0;i<219;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len220(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(244); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 220;
	for(int i=0;i<220;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len221(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(245); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 221;
	for(int i=0;i<221;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len222(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(246); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 222;
	for(int i=0;i<222;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len223(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(247); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 223;
	for(int i=0;i<223;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len224(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(248); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 224;
	for(int i=0;i<224;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len225(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(249); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 225;
	for(int i=0;i<225;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len226(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(250); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 226;
	for(int i=0;i<226;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len227(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(251); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 227;
	for(int i=0;i<227;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len228(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(252); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 228;
	for(int i=0;i<228;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len229(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(253); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 229;
	for(int i=0;i<229;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len230(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(254); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 230;
	for(int i=0;i<230;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_tlv_ssid_len231(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(255); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 231;
	for(int i=0;i<231;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len232(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(256); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 232;
	for(int i=0;i<232;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len233(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(257); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 233;
	for(int i=0;i<233;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len234(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(258); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 234;
	for(int i=0;i<234;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len235(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(259); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 235;
	for(int i=0;i<235;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len236(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(260); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 236;
	for(int i=0;i<236;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len237(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(261); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 237;
	for(int i=0;i<237;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len238(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(262); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 238;
	for(int i=0;i<238;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len239(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(263); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 239;
	for(int i=0;i<239;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len240(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(264); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 240;
	for(int i=0;i<240;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

// NOTE: All below are INVALID test cases (reserved SSID length)

void construct_k_tlv_ssid_len241(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(265); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 241;
	for(int i=0;i<241;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len242(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(266); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 242;
	for(int i=0;i<242;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len243(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(267); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 243;
	for(int i=0;i<243;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len244(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(268); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 244;
	for(int i=0;i<244;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len245(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(269); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 245;
	for(int i=0;i<245;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len246(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(270); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 246;
	for(int i=0;i<246;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len247(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(271); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 247;
	for(int i=0;i<247;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len248(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(272); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 248;
	for(int i=0;i<248;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len249(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(273); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 249;
	for(int i=0;i<249;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len250(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(274); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 250;
	for(int i=0;i<250;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len251(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(275); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 251;
	for(int i=0;i<251;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len252(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(276); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 252;
	for(int i=0;i<252;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len253(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(277); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 253;
	for(int i=0;i<253;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len254(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(278); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 254;
	for(int i=0;i<254;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_ssid_len255(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(279); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 255;
	for(int i=0;i<255;i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_upto_signal_strength(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(28);   // total value length
	ptr += 2;

	// -------- Base fields --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	// utilization
	*ptr++ = 0x20;

	// noise
	*ptr++ = 0x10;

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length
	*ptr++ = 0x04;

	// SSID (4 bytes)
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength (1)
	*ptr++ = 0x50;
	construct_eom();
}

// ======================= K TLV ChannelBandwidth 0 → 10 =======================

void construct_k_cb_len0(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(29); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x00;
	construct_eom();
}

void construct_k_cb_len1(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(31); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x01; *ptr++ = 'A';
	construct_eom();
}

void construct_k_cb_len2(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(32); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x02; *ptr++ = 'A'; *ptr++ = 'B';
	construct_eom();
}

void construct_k_cb_len3(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(33); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	construct_eom();
}

void construct_k_cb_len4(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(34); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x04; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C'; *ptr++ = 'D';
	construct_eom();
}

void construct_k_cb_len5(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(35); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x05; for(int i=0;i<5;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_cb_len6(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(36); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x06; for(int i=0;i<6;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_cb_len7(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(37); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x07; for(int i=0;i<7;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_cb_len8(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(38); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x08; for(int i=0;i<8;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_cb_len9(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(39); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x09; for(int i=0;i<9;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_cb_len10(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(40); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 0x0A; for(int i=0;i<10;i++) *ptr++ = 'A'+i;
	construct_eom();
}

void construct_k_cb_len11(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(41);  // 29 + 12
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 11;
	for(int i=0;i<11;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len12(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(42);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 12;
	for(int i=0;i<12;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len13(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(43);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 13;
	for(int i=0;i<13;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len14(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(44);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 14;
	for(int i=0;i<14;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len15(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(45);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 15;
	for(int i=0;i<15;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len16(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(46);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 16;
	for(int i=0;i<16;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len17(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(47);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 17;
	for(int i=0;i<17;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len18(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(48);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 18;
	for(int i=0;i<18;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len19(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(49);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 19;
	for(int i=0;i<19;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len20(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(50);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';
	*ptr++ = 0x50;

	*ptr++ = 20;
	for(int i=0;i<20;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len21(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(51); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 21;
	for(int i=0;i<21;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len22(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(52); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 22;
	for(int i=0;i<22;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len23(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(53); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 23;
	for(int i=0;i<23;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len24(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(54); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 24;
	for(int i=0;i<24;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len25(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(55); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 25;
	for(int i=0;i<25;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len26(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(56); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 26;
	for(int i=0;i<26;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len27(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(57); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 27;
	for(int i=0;i<27;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len28(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(58); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 28;
	for(int i=0;i<28;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len29(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(59); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 29;
	for(int i=0;i<29;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len30(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(60); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 30;
	for(int i=0;i<30;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len31(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(61); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=31;
	for(int i=0;i<31;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len32(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(62); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=32;
	for(int i=0;i<32;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len33(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(63); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=33;
	for(int i=0;i<33;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len34(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(64); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=34;
	for(int i=0;i<34;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len35(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(65); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=35;
	for(int i=0;i<35;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len36(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(66); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=36;
	for(int i=0;i<36;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len37(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(67); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=37;
	for(int i=0;i<37;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len38(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(68); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=38;
	for(int i=0;i<38;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len39(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(69); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=39;
	for(int i=0;i<39;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len40(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(70); ptr += 2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0x00;

	*ptr++=0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr = htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=40;
	for(int i=0;i<40;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len41(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(71); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 41;
	for (int i = 0; i < 41; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len42(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(72); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 42;
	for (int i = 0; i < 42; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len43(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(73); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 43;
	for (int i = 0; i < 43; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len44(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(74); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 44;
	for (int i = 0; i < 44; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len45(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(75); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 45;
	for (int i = 0; i < 45; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len46(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(76); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 46;
	for (int i = 0; i < 46; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len47(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(77); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 47;
	for (int i = 0; i < 47; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len48(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(78); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 48;
	for (int i = 0; i < 48; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len49(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(79); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 49;
	for (int i = 0; i < 49; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len50(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(80); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 50;
	for (int i = 0; i < 50; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len51(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(81);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 51;
	for (int i = 0; i < 51; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len52(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(82);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 52;
	for (int i = 0; i < 52; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len53(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(83);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 53;
	for (int i = 0; i < 53; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len54(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(84);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 54;
	for (int i = 0; i < 54; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len55(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(85);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 55;
	for (int i = 0; i < 55; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len56(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(86);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 56;
	for (int i = 0; i < 56; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len57(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(87);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 57;
	for (int i = 0; i < 57; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len58(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(88);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 58;
	for (int i = 0; i < 58; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len59(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(89);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 59;
	for (int i = 0; i < 59; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len60(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(90);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 60;
	for (int i = 0; i < 60; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len61(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(91);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 61;
	for (int i = 0; i < 61; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len62(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(92);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 62;
	for (int i = 0; i < 62; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len63(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(93);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 63;
	for (int i = 0; i < 63; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len64(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(94);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 64;
	for (int i = 0; i < 64; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len65(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(95);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 65;
	for (int i = 0; i < 65; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len66(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(96);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 66;
	for (int i = 0; i < 66; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len67(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(97);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 67;
	for (int i = 0; i < 67; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len68(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(98);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 68;
	for (int i = 0; i < 68; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len69(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(99);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 69;
	for (int i = 0; i < 69; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len70(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(100);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 70;
	for (int i = 0; i < 70; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len71(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(101); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 71;
	for (int i = 0; i < 71; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len72(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(102); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 72;
	for (int i = 0; i < 72; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len73(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(103); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 73;
	for (int i = 0; i < 73; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len74(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(104); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 74;
	for (int i = 0; i < 74; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len75(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(105); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 75;
	for (int i = 0; i < 75; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len76(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(106); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 76;
	for (int i = 0; i < 76; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len77(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(107); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 77;
	for (int i = 0; i < 77; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len78(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(108); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 78;
	for (int i = 0; i < 78; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len79(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(109); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 79;
	for (int i = 0; i < 79; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len80(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(110); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 80;
	for (int i = 0; i < 80; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len81(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(111); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 81;
	for (int i = 0; i < 81; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len82(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(112); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 82;
	for (int i = 0; i < 82; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len83(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(113); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 83;
	for (int i = 0; i < 83; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len84(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(114); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 84;
	for (int i = 0; i < 84; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len85(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(115); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 85;
	for (int i = 0; i < 85; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len86(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(116); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 86;
	for (int i = 0; i < 86; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len87(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(117); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 87;
	for (int i = 0; i < 87; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len88(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(118); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 88;
	for (int i = 0; i < 88; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len89(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(119); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 89;
	for (int i = 0; i < 89; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len90(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(120); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 90;
	for (int i = 0; i < 90; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len91(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(121); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 91;
	for (int i=0;i<91;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len92(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(122); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 92;
	for (int i=0;i<92;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len93(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(123); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 93;
	for (int i=0;i<93;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len94(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(124); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 94;
	for (int i=0;i<94;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len95(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(125); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 95;
	for (int i=0;i<95;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len96(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(126); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 96;
	for (int i=0;i<96;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len97(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(127); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 97;
	for (int i=0;i<97;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len98(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(128); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 98;
	for (int i=0;i<98;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len99(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(129); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 99;
	for (int i=0;i<99;i++) *ptr++ = 'A'+(i%26);
	construct_eom();
}

void construct_k_cb_len100(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(130); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 100;
	for (int i = 0; i < 100; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len101(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(131); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 101;
	for (int i = 0; i < 101; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len102(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(132); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 102;
	for (int i = 0; i < 102; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len103(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(133);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 103;
	for(int i=0;i<103;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len104(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(134);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 104;
	for(int i=0;i<104;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len105(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(135);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 105;
	for(int i=0;i<105;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len106(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(136);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 106;
	for(int i=0;i<106;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len107(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(137);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 107;
	for(int i=0;i<107;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len108(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(138);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 108;
	for(int i=0;i<108;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len109(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(139);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 109;
	for(int i=0;i<109;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len110(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(140);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 110;
	for(int i=0;i<110;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len111(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(141); // 29 + 111
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;   // RUID
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;   // op_class, channel, flag

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C'; // ts

	*ptr++ = 0x20; *ptr++ = 0x10;             // utilization, noise
	*(uint16_t*)ptr = htons(1); ptr += 2;     // num_neighbors

	for (int i = 0; i < 6; i++) *ptr++ = i + 10; // BSSID
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T'; // SSID

	*ptr++ = 0x50;                           // SignalStrength

	*ptr++ = 111;                            // CB length
	for (int i = 0; i < 111; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len112(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(142);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 112;
	for (int i = 0; i < 112; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len113(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(143);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 113;
	for (int i = 0; i < 113; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len114(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(144);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 114;
	for (int i = 0; i < 114; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len115(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(145);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 115;
	for (int i = 0; i < 115; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len116(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(146);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 116;
	for (int i = 0; i < 116; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len117(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(147);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 117;
	for (int i = 0; i < 117; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len118(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(148);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 118;
	for (int i = 0; i < 118; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len119(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(149);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 119;
	for (int i = 0; i < 119; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len120(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(150);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;
	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;
	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 120;
	for (int i = 0; i < 120; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len121(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(151);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 121;
	for (int i = 0; i < 121; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len122(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(152);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 122;
	for (int i = 0; i < 122; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len123(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(153);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 123;
	for (int i = 0; i < 123; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len124(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(154);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 124;
	for (int i = 0; i < 124; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len125(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(155);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 125;
	for (int i = 0; i < 125; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len126(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(156);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 126;
	for (int i = 0; i < 126; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len127(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(157);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 127;
	for (int i = 0; i < 127; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len128(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(158);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 128;
	for (int i = 0; i < 128; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len129(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(159);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 129;
	for (int i = 0; i < 129; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len130(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(160);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04; *ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 130;
	for (int i = 0; i < 130; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len131(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(161);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 131;
	for (int i = 0; i < 131; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len132(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(162);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 132;
	for (int i = 0; i < 132; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len133(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(163);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 133;
	for (int i = 0; i < 133; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len134(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(164);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 134;
	for (int i = 0; i < 134; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len135(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(165);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 135;
	for (int i = 0; i < 135; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len136(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(166);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 136;
	for (int i = 0; i < 136; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len137(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(167);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 137;
	for (int i = 0; i < 137; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len138(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(168);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 138;
	for (int i = 0; i < 138; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len139(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(169);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 139;
	for (int i = 0; i < 139; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len140(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(170);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 140;
	for (int i = 0; i < 140; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len141(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(171);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 141;
	for (int i = 0; i < 141; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len142(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(172);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 3;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 142;
	for (int i = 0; i < 142; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len143(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(173);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 143;
	for(int i=0;i<143;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len144(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(174);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 144;
	for(int i=0;i<144;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len145(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(175);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 145;
	for(int i=0;i<145;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len146(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(176);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 146;
	for(int i=0;i<146;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len147(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(177);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 147;
	for(int i=0;i<147;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len148(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(178);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 148;
	for(int i=0;i<148;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len149(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(179);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 149;
	for(int i=0;i<149;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len150(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(180);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 150;
	for(int i=0;i<150;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len151(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(181);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 151;
	for(int i=0;i<151;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len152(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(182);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 152;
	for(int i=0;i<152;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len153(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(183);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 153;
	for(int i=0;i<153;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len154(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(184);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 154;
	for(int i=0;i<154;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len155(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(185);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 155;
	for(int i=0;i<155;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len156(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(186);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 156;
	for(int i=0;i<156;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len157(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(187);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 157;
	for(int i=0;i<157;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len158(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(188);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 158;
	for(int i=0;i<158;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len159(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(189);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 159;
	for(int i=0;i<159;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len160(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(190);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 160;
	for(int i=0;i<160;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len161(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(191);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 161;
	for (int i = 0; i < 161; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len162(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(192);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 162;
	for (int i = 0; i < 162; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len163(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(193);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 163;
	for (int i = 0; i < 163; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len164(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(194);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 164;
	for (int i = 0; i < 164; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len165(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(195);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 165;
	for (int i = 0; i < 165; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len166(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(196);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 166;
	for(int i=0;i<166;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len167(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(197);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 167;
	for(int i=0;i<167;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len168(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(198);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 168;
	for(int i=0;i<168;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len169(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(199);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 169;
	for(int i=0;i<169;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len170(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(200);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 170;
	for(int i=0;i<170;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len171(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(201);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 171;
	for (int i = 0; i < 171; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len172(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(202);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 172;
	for (int i = 0; i < 172; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len173(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(203);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 173;
	for (int i = 0; i < 173; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len174(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(204);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 174;
	for (int i = 0; i < 174; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len175(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(205);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 175;
	for (int i = 0; i < 175; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len176(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(206);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 176;
	for (int i = 0; i < 176; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len177(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(207);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 177;
	for (int i = 0; i < 177; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len178(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(208);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 178;
	for (int i = 0; i < 178; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len179(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(209);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 'A'; *ptr++ = 'B'; *ptr++ = 'C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 179;
	for (int i = 0; i < 179; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len180(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(210);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 180;
	for(int i=0;i<180;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len181(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(211);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 181;
	for (int i = 0; i < 181; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len182(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(212);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 182;
	for (int i = 0; i < 182; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len183(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(213);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 183;
	for (int i = 0; i < 183; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len184(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(214);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 184;
	for (int i = 0; i < 184; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len185(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(215);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 185;
	for (int i = 0; i < 185; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len186(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(216);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 186;
	for (int i = 0; i < 186; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len187(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(217);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 187;
	for (int i = 0; i < 187; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len188(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(218);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 188;
	for (int i = 0; i < 188; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len189(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(219);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 189;
	for (int i = 0; i < 189; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len190(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(220);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 190;
	for (int i = 0; i < 190; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len191(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(221);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 191;
	for (int i = 0; i < 191; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len192(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(222);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 192;
	for (int i = 0; i < 192; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len193(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(223);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 193;
	for (int i = 0; i < 193; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len194(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(224);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 194;
	for (int i = 0; i < 194; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len195(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(225);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 195;
	for (int i = 0; i < 195; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len196(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(226);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 196;
	for (int i = 0; i < 196; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len197(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(227);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 197;
	for (int i = 0; i < 197; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len198(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(228);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 198;
	for (int i = 0; i < 198; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len199(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(229);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 199;
	for (int i = 0; i < 199; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len200(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(230);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 200;
	for (int i = 0; i < 200; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len201(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(231); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 201;
	for(int i=0;i<201;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len202(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(232); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 202;
	for(int i=0;i<202;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len203(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(233); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 203;
	for(int i=0;i<203;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len204(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(234); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 204;
	for(int i=0;i<204;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len205(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(235); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 205;
	for(int i=0;i<205;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len206(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(236); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 206;
	for(int i=0;i<206;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len207(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(237); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 207;
	for(int i=0;i<207;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len208(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(238); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 208;
	for(int i=0;i<208;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len209(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(239); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 209;
	for(int i=0;i<209;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len210(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(240); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 4;
	*ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 210;
	for(int i=0;i<210;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len211(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(241); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 211;
	for(int i=0;i<211;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len212(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(242); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 212;
	for(int i=0;i<212;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len213(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(243); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 213;
	for(int i=0;i<213;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len214(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(244); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 214;
	for(int i=0;i<214;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len215(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(245); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 215;
	for(int i=0;i<215;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len216(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(246); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 216;
	for(int i=0;i<216;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len217(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(247); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 217;
	for(int i=0;i<217;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len218(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(248); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 218;
	for(int i=0;i<218;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len219(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(249); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 219;
	for(int i=0;i<219;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len220(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(250); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 81; *ptr++ = 6; *ptr++ = 0x00;

	*ptr++ = 0x03; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++ = 0x20; *ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1); ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x04; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++ = 0x50;

	*ptr++ = 220;
	for(int i=0;i<220;i++) *ptr++ = 'A' + (i%26);
	construct_eom();
}

void construct_k_cb_len221(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(251);  // total length
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 221;
	for (int i = 0; i < 221; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len222(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(252);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 222;
	for (int i = 0; i < 222; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len223(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(253);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 223;
	for (int i = 0; i < 223; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len224(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(254);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 224;
	for (int i = 0; i < 224; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len225(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(255);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 225;
	for (int i = 0; i < 225; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len226(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(256);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 226;
	for (int i = 0; i < 226; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len227(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(257);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 227;
	for (int i = 0; i < 227; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len228(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(258);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 228;
	for (int i = 0; i < 228; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len229(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(259);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 229;
	for (int i = 0; i < 229; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len230(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(260);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 230;
	for (int i = 0; i < 230; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len231(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(261);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 231;
	for (int i = 0; i < 231; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len232(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(262);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 232;
	for (int i = 0; i < 232; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len233(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(263);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 233;
	for (int i = 0; i < 233; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len234(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(264);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 234;
	for (int i = 0; i < 234; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len235(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(265);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 235;
	for (int i = 0; i < 235; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len236(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(266);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 236;
	for (int i = 0; i < 236; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len237(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(267);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 237;
	for (int i = 0; i < 237; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len238(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(268);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 238;
	for (int i = 0; i < 238; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len239(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(269);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 239;
	for (int i = 0; i < 239; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len240(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(270);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;
	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41; *ptr++ = 0x42; *ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T'; *ptr++ = 'E'; *ptr++ = 'S'; *ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 240;
	for (int i = 0; i < 240; i++)
		*ptr++ = 'A' + (i % 26);
	construct_eom();
}

// ---------- 241 ----------
void construct_k_cb_len241(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(271);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=241;
	for(int i=0;i<241;i++) *ptr++='A'+(i%26);
	construct_eom();
}

// ---------- 242 ----------
void construct_k_cb_len242(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(272);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=242;
	for(int i=0;i<242;i++) *ptr++='A'+(i%26);
	construct_eom();
}

// ---------- 243 ----------
void construct_k_cb_len243(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(273);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=243;
	for(int i=0;i<243;i++) *ptr++='A'+(i%26);
	construct_eom();
}

// ---------- 244 ----------
void construct_k_cb_len244(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(274);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=244;
	for(int i=0;i<244;i++) *ptr++='A'+(i%26);
	construct_eom();
}

// ---------- 245 ----------
void construct_k_cb_len245(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(275);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=245;
	for(int i=0;i<245;i++) *ptr++='A'+(i%26);
	construct_eom();
}

// ---------- 246 ----------
void construct_k_cb_len246(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(276);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=246;
	for(int i=0;i<246;i++) *ptr++='A'+(i%26);
	construct_eom();
}

// ---------- 247 ----------
void construct_k_cb_len247(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(277);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=247;
	for(int i=0;i<247;i++) *ptr++='A'+(i%26);
	construct_eom();
}

// ---------- 248 ----------
void construct_k_cb_len248(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(278);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=248;
	for(int i=0;i<248;i++) *ptr++='A'+(i%26);
	construct_eom();
}

// ---------- 249 ----------
void construct_k_cb_len249(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(279);
	ptr += 2;

	for (int i=0;i<6;i++) *ptr++=i;
	*ptr++=81; *ptr++=6; *ptr++=0;

	*ptr++=3; *ptr++='A'; *ptr++='B'; *ptr++='C';

	*ptr++=0x20; *ptr++=0x10;

	*(uint16_t*)ptr=htons(1); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i+10;

	*ptr++=4; *ptr++='T'; *ptr++='E'; *ptr++='S'; *ptr++='T';

	*ptr++=0x50;

	*ptr++=249;
	for(int i=0;i<249;i++) *ptr++='A'+(i%26);
	construct_eom();
}

void construct_k_cb_len250(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(280);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 250;
	for (int i = 0; i < 250; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len251(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(281);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 251;
	for (int i = 0; i < 251; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len252(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(282);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 252;
	for (int i = 0; i < 252; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len253(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(283);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 253;
	for (int i = 0; i < 253; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len254(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(284);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 254;
	for (int i = 0; i < 254; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_cb_len255(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;
	*(uint16_t*)ptr = htons(285);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;
	*ptr++ = 0x10;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	*ptr++ = 0x50;

	*ptr++ = 255;
	for (int i = 0; i < 255; i++) *ptr++ = 'A' + (i % 26);
	construct_eom();
}

void construct_k_tlv_with_channel_util(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(33);
	ptr += 2;

	// -------- Base --------
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;
	*ptr++ = 6;
	*ptr++ = 0x00;

	// timestamp
	*ptr++ = 0x03;
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	*ptr++ = 0x50;  // SignalStrength

	// Channel Bandwidth
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- New field --------
	*ptr++ = 0x80;  // bit7 = 1 → present
	*ptr++ = 0x55;  // ChannelUtilization
	construct_eom();
}

void construct_k_tlv_station_count_pow2_0(void)
{
	construct_timestamp_tlv();
        *ptr++ = em_tlv_type_channel_scan_rslt;

        *(uint16_t*)ptr = htons(36);   // total length
        ptr += 2;

        // -------- Base --------

        // RUID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i;

        *ptr++ = 81;    // op_class
        *ptr++ = 6;     // channel
        *ptr++ = 0x00;  // flag

        // timestamp
        *ptr++ = 0x03;  // ts_len = 3
        *ptr++ = 0x41;
        *ptr++ = 0x42;
        *ptr++ = 0x43;

        *ptr++ = 0x20;  // utilization
        *ptr++ = 0x10;  // noise

        // num_neighbors = 1
        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        // -------- Neighbor --------

        // BSSID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i + 10;

        // SSID length + SSID
        *ptr++ = 0x04;
        *ptr++ = 'T';
        *ptr++ = 'E';
        *ptr++ = 'S';
        *ptr++ = 'T';

        // SignalStrength
        *ptr++ = 0x50;

        // Channel Bandwidth ("80")
        *ptr++ = 0x02;
        *ptr++ = '8';
        *ptr++ = '0';

        // -------- BSS Load --------

        *ptr++ = 0x80;  // bit7 = 1 (fields present)

        *ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^0 = 1 --------

	*(uint16_t*)ptr = htons(1);   // 2^0 = 1
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_1(void)
{
	construct_timestamp_tlv();
        *ptr++ = em_tlv_type_channel_scan_rslt;

        *(uint16_t*)ptr = htons(36);   // total length
        ptr += 2;

        // -------- Base --------

        // RUID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i;

        *ptr++ = 81;    // op_class
        *ptr++ = 6;     // channel
        *ptr++ = 0x00;  // flag

        // timestamp
        *ptr++ = 0x03;  // ts_len = 3
        *ptr++ = 0x41;
        *ptr++ = 0x42;
        *ptr++ = 0x43;

        *ptr++ = 0x20;  // utilization
        *ptr++ = 0x10;  // noise

        // num_neighbors = 1
        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        // -------- Neighbor --------

        // BSSID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i + 10;

        // SSID length + SSID
        *ptr++ = 0x04;
        *ptr++ = 'T';
        *ptr++ = 'E';
        *ptr++ = 'S';
        *ptr++ = 'T';

        // SignalStrength
        *ptr++ = 0x50;

        // Channel Bandwidth ("80")
        *ptr++ = 0x02;
        *ptr++ = '8';
        *ptr++ = '0';

        // -------- BSS Load --------

        *ptr++ = 0x80;  // bit7 = 1 (fields present)

        *ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^1 = 2 --------
	*(uint16_t*)ptr = htons(2);
	ptr += 2;
	construct_eom();
}


void construct_k_tlv_station_count_pow2_2(void)
{
	construct_timestamp_tlv();
        *ptr++ = em_tlv_type_channel_scan_rslt;

        *(uint16_t*)ptr = htons(36);   // total length
        ptr += 2;

        // -------- Base --------

        // RUID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i;

        *ptr++ = 81;    // op_class
        *ptr++ = 6;     // channel
        *ptr++ = 0x00;  // flag

        // timestamp
        *ptr++ = 0x03;  // ts_len = 3
        *ptr++ = 0x41;
        *ptr++ = 0x42;
        *ptr++ = 0x43;

        *ptr++ = 0x20;  // utilization
        *ptr++ = 0x10;  // noise

        // num_neighbors = 1
        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        // -------- Neighbor --------

        // BSSID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i + 10;

        // SSID length + SSID
        *ptr++ = 0x04;
        *ptr++ = 'T';
        *ptr++ = 'E';
        *ptr++ = 'S';
        *ptr++ = 'T';

        // SignalStrength
        *ptr++ = 0x50;

        // Channel Bandwidth ("80")
        *ptr++ = 0x02;
        *ptr++ = '8';
        *ptr++ = '0';

        // -------- BSS Load --------

        *ptr++ = 0x80;  // bit7 = 1 (fields present)

        *ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount (2^2 = 4) --------
	*(uint16_t*)ptr = htons(4);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_3(void)
{
	construct_timestamp_tlv();
        *ptr++ = em_tlv_type_channel_scan_rslt;

        *(uint16_t*)ptr = htons(36);   // total length
        ptr += 2;

        // -------- Base --------

        // RUID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i;

        *ptr++ = 81;    // op_class
        *ptr++ = 6;     // channel
        *ptr++ = 0x00;  // flag

        // timestamp
        *ptr++ = 0x03;  // ts_len = 3
        *ptr++ = 0x41;
        *ptr++ = 0x42;
        *ptr++ = 0x43;

        *ptr++ = 0x20;  // utilization
        *ptr++ = 0x10;  // noise

        // num_neighbors = 1
        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        // -------- Neighbor --------

        // BSSID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i + 10;

        // SSID length + SSID
        *ptr++ = 0x04;
        *ptr++ = 'T';
        *ptr++ = 'E';
        *ptr++ = 'S';
        *ptr++ = 'T';

        // SignalStrength
        *ptr++ = 0x50;

        // Channel Bandwidth ("80")
        *ptr++ = 0x02;
        *ptr++ = '8';
        *ptr++ = '0';

        // -------- BSS Load --------

        *ptr++ = 0x80;  // bit7 = 1 (fields present)

        *ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^3 = 8 --------
	*(uint16_t*)ptr = htons(8);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_4(void)
{
	construct_timestamp_tlv();
        *ptr++ = em_tlv_type_channel_scan_rslt;

        *(uint16_t*)ptr = htons(36);   // total length
        ptr += 2;

        // -------- Base --------

        // RUID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i;

        *ptr++ = 81;    // op_class
        *ptr++ = 6;     // channel
        *ptr++ = 0x00;  // flag

        // timestamp
        *ptr++ = 0x03;  // ts_len = 3
        *ptr++ = 0x41;
        *ptr++ = 0x42;
        *ptr++ = 0x43;

        *ptr++ = 0x20;  // utilization
        *ptr++ = 0x10;  // noise

        // num_neighbors = 1
        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        // -------- Neighbor --------

        // BSSID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i + 10;

        // SSID length + SSID
        *ptr++ = 0x04;
        *ptr++ = 'T';
        *ptr++ = 'E';
        *ptr++ = 'S';
        *ptr++ = 'T';

        // SignalStrength
        *ptr++ = 0x50;

        // Channel Bandwidth ("80")
        *ptr++ = 0x02;
        *ptr++ = '8';
        *ptr++ = '0';

        // -------- BSS Load --------

        *ptr++ = 0x80;  // bit7 = 1 (fields present)

        *ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^4 = 16 --------
	*(uint16_t*)ptr = htons(16);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_5(void)
{
	construct_timestamp_tlv();
        *ptr++ = em_tlv_type_channel_scan_rslt;

        *(uint16_t*)ptr = htons(36);   // total length
        ptr += 2;

        // -------- Base --------

        // RUID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i;

        *ptr++ = 81;    // op_class
        *ptr++ = 6;     // channel
        *ptr++ = 0x00;  // flag

        // timestamp
        *ptr++ = 0x03;  // ts_len = 3
        *ptr++ = 0x41;
        *ptr++ = 0x42;
        *ptr++ = 0x43;

        *ptr++ = 0x20;  // utilization
        *ptr++ = 0x10;  // noise

        // num_neighbors = 1
        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        // -------- Neighbor --------

        // BSSID (6)
        for (int i = 0; i < 6; i++)
                *ptr++ = i + 10;

        // SSID length + SSID
        *ptr++ = 0x04;
        *ptr++ = 'T';
        *ptr++ = 'E';
        *ptr++ = 'S';
        *ptr++ = 'T';

        // SignalStrength
        *ptr++ = 0x50;

        // Channel Bandwidth ("80")
        *ptr++ = 0x02;
        *ptr++ = '8';
        *ptr++ = '0';

        // -------- BSS Load --------

        *ptr++ = 0x80;  // bit7 = 1 (fields present)

        *ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^5 = 32 --------
	*(uint16_t*)ptr = htons(32);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_6(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^6 = 64 --------
	*(uint16_t*)ptr = htons(64);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_7(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^7 = 128 --------
	*(uint16_t*)ptr = htons(128);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_8(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^8 = 256 --------
	*(uint16_t*)ptr = htons(256);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_9(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^9 = 512 --------
	*(uint16_t*)ptr = htons(512);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_10(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^10 = 1024 --------
	*(uint16_t*)ptr = htons(1024);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_11(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^11 = 2048 --------
	*(uint16_t*)ptr = htons(2048);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_12(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^12 = 4096 --------
	*(uint16_t*)ptr = htons(4096);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_13(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^13 = 8192 --------
	*(uint16_t*)ptr = htons(8192);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_14(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^14 = 16384 --------
	*(uint16_t*)ptr = htons(16384);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_15(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^15 = 32768--------
	*(uint16_t*)ptr = htons(32768);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_station_count_pow2_16(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	*(uint16_t*)ptr = htons(36);   // total length
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// timestamp
	*ptr++ = 0x03;  // ts_len = 3
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	*ptr++ = 0x20;  // utilization
	*ptr++ = 0x10;  // noise

	// num_neighbors = 1
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length + SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// Channel Bandwidth ("80")
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------

	*ptr++ = 0x80;  // bit7 = 1 (fields present)

	*ptr++ = 0x55;  // ChannelUtilization

	// -------- StationCount = 2^16 = 65536--------
	*(uint16_t*)ptr = htons(65536);
	ptr += 2;
	construct_eom();
}

void construct_k_tlv_full_final(void)
{
	construct_timestamp_tlv();
	*ptr++ = em_tlv_type_channel_scan_rslt;

	// Total length = 40 bytes (calculated below)
	*(uint16_t*)ptr = htons(40);
	ptr += 2;

	// -------- Base --------

	// RUID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	*ptr++ = 81;    // op_class
	*ptr++ = 6;     // channel
	*ptr++ = 0x00;  // flag

	// -------- Timestamp --------
	*ptr++ = 0x03;  // ts_len
	*ptr++ = 0x41;
	*ptr++ = 0x42;
	*ptr++ = 0x43;

	// -------- Utilization + Noise --------
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	// -------- num_neighbors --------
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID
	*ptr++ = 0x04;
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// SignalStrength
	*ptr++ = 0x50;

	// -------- Channel Bandwidth --------
	*ptr++ = 0x02;
	*ptr++ = '8';
	*ptr++ = '0';

	// -------- BSS Load --------
	*ptr++ = 0x80;   // bit7 = 1 (present)

	*ptr++ = 0x55;   // ChannelUtilization

	*(uint16_t*)ptr = htons(8);   // StationCount (example 2^3)
	ptr += 2;

	// -------- AggregateScanDuration --------
	*(uint32_t*)ptr = htonl(100);   // 100 ms
	ptr += 4;

	// -------- Scan Type --------
	*ptr++ = 0x80;   // Active scan
	construct_eom();
}

void construct_valid_result_tlv(void)
{

	*ptr++ = em_tlv_type_channel_scan_rslt;   // ✔ correct

	unsigned char *len_ptr = ptr;
	ptr += 2;  // reserve length

	unsigned char *start = ptr;

	// -------- ruid (6 bytes) --------
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	// -------- op_class --------
	*ptr++ = 81;

	// -------- channel --------
	*ptr++ = 6;

	// -------- scan_status --------
	*ptr++ = 1;

	// -------- timestamp_len --------
	*ptr++ = 3;

	// -------- timestamp (3 bytes) --------
	*ptr++ = 'A';
	*ptr++ = 'B';
	*ptr++ = 'C';

	// -------- util + noise --------
	*ptr++ = 0x20;
	*ptr++ = 0x10;

	// -------- num_neighbors --------
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// -------- Neighbor --------

	// BSSID (6 bytes)
	for (int i = 0; i < 6; i++)
		*ptr++ = i + 10;

	// SSID length (🔥 overflow trigger)
	*ptr++ = 60;

	// SSID data (NO NULLs)
	for (int i = 0; i < 60; i++)
		*ptr++ = 'X';
	// -------- FIX TLV LENGTH --------
	//    uint16_t total_len = ptr - start;
	//  *(uint16_t*)len_ptr = htons(total_len);

}

void construct_full_valid_case(void)
{

	construct_timestamp_tlv();
	construct_valid_result_tlv();
	construct_eom();

}

#if 1
pkt_test_case_t handle_channel_scan_rprt_suite[] = {


	{"k3_e3_len0", "p1.pcap", construct_k3_e3_len0, 0},
	{"k_tlv_ruid_6", "p2.pcap", construct_k_tlv_ruid_6, 0},
	{"k_tlv_ruid_op", "p3.pcap", construct_k_tlv_ruid_op, 0},
	{"k_tlv_ruid_op_channel", "p4.pcap", construct_k_tlv_ruid_op_channel, 0},
	{"k_tlv_flag_0", "p5.pcap", construct_k_tlv_flag_0, 0},
	{"k_tlv_flag_1", "p6.pcap", construct_k_tlv_flag_1, 0},
	{"k_tlv_flag_2", "p7.pcap", construct_k_tlv_flag_2, 0},
	{"k_tlv_flag_3", "p8.pcap", construct_k_tlv_flag_3, 0},
	{"k_tlv_flag_4", "p9.pcap", construct_k_tlv_flag_4, 0},
	{"k_tlv_flag_5", "p10.pcap", construct_k_tlv_flag_5, 0},
	{"k_tlv_flag_6", "p11.pcap", construct_k_tlv_flag_6, 0},
	{"k_tlv_flag_7", "p12.pcap", construct_k_tlv_flag_7, 0},
	{"k_tlv_flag_8", "p13.pcap", construct_k_tlv_flag_8, 0},
	{"k_tlv_flag_9", "p14.pcap", construct_k_tlv_flag_9, 0},
	{"k_tlv_flag_10", "p15.pcap", construct_k_tlv_flag_10, 0},
	{"k_tlv_flag_11", "p16.pcap", construct_k_tlv_flag_11, 0},
	{"k_tlv_flag_12", "p17.pcap", construct_k_tlv_flag_12, 0},
	{"k_tlv_flag_13", "p18.pcap", construct_k_tlv_flag_13, 0},
	{"k_tlv_flag_14", "p19.pcap", construct_k_tlv_flag_14, 0},
	{"k_tlv_flag_15", "p20.pcap", construct_k_tlv_flag_15, 0},
	{"k_tlv_flag_16", "p21.pcap", construct_k_tlv_flag_16, 0},
	{"k_tlv_flag_17", "p22.pcap", construct_k_tlv_flag_17, 0},
	{"k_tlv_flag_18", "p23.pcap", construct_k_tlv_flag_18, 0},
	{"k_tlv_flag_19", "p24.pcap", construct_k_tlv_flag_19, 0},
	{"k_tlv_flag_20", "p25.pcap", construct_k_tlv_flag_20, 0},
	{"k_tlv_flag_21", "p26.pcap", construct_k_tlv_flag_21, 0},
	{"k_tlv_flag_22", "p27.pcap", construct_k_tlv_flag_22, 0},
	{"k_tlv_flag_23", "p28.pcap", construct_k_tlv_flag_23, 0},
	{"k_tlv_flag_24", "p29.pcap", construct_k_tlv_flag_24, 0},
	{"k_tlv_flag_25", "p30.pcap", construct_k_tlv_flag_25, 0},
	{"k_tlv_flag_26", "p31.pcap", construct_k_tlv_flag_26, 0},
	{"k_tlv_flag_27", "p32.pcap", construct_k_tlv_flag_27, 0},
	{"k_tlv_flag_28", "p33.pcap", construct_k_tlv_flag_28, 0},
	{"k_tlv_flag_29", "p34.pcap", construct_k_tlv_flag_29, 0},
	{"k_tlv_flag_30", "p35.pcap", construct_k_tlv_flag_30, 0},
	{"k_tlv_flag_31", "p36.pcap", construct_k_tlv_flag_31, 0},
	{"k_tlv_flag_32", "p37.pcap", construct_k_tlv_flag_32, 0},
	{"k_tlv_flag_33", "p38.pcap", construct_k_tlv_flag_33, 0},
	{"k_tlv_flag_34", "p39.pcap", construct_k_tlv_flag_34, 0},
	{"k_tlv_flag_35", "p40.pcap", construct_k_tlv_flag_35, 0},
	{"k_tlv_flag_36", "p41.pcap", construct_k_tlv_flag_36, 0},
	{"k_tlv_flag_37", "p42.pcap", construct_k_tlv_flag_37, 0},
	{"k_tlv_flag_38", "p43.pcap", construct_k_tlv_flag_38, 0},
	{"k_tlv_flag_39", "p44.pcap", construct_k_tlv_flag_39, 0},
	{"k_tlv_flag_40", "p45.pcap", construct_k_tlv_flag_40, 0},
	{"k_tlv_flag_41", "p46.pcap", construct_k_tlv_flag_41, 0},
	{"k_tlv_flag_42", "p47.pcap", construct_k_tlv_flag_42, 0},
	{"k_tlv_flag_43", "p48.pcap", construct_k_tlv_flag_43, 0},
	{"k_tlv_flag_44", "p49.pcap", construct_k_tlv_flag_44, 0},
	{"k_tlv_flag_45", "p50.pcap", construct_k_tlv_flag_45, 0},
	{"k_tlv_flag_46", "p51.pcap", construct_k_tlv_flag_46, 0},
	{"k_tlv_flag_47", "p52.pcap", construct_k_tlv_flag_47, 0},
	{"k_tlv_flag_48", "p53.pcap", construct_k_tlv_flag_48, 0},
	{"k_tlv_flag_49", "p54.pcap", construct_k_tlv_flag_49, 0},
	{"k_tlv_flag_50", "p55.pcap", construct_k_tlv_flag_50, 0},
	{"k_tlv_flag_51", "p56.pcap", construct_k_tlv_flag_51, 0},
	{"k_tlv_flag_52", "p57.pcap", construct_k_tlv_flag_52, 0},
	{"k_tlv_flag_53", "p58.pcap", construct_k_tlv_flag_53, 0},
	{"k_tlv_flag_54", "p59.pcap", construct_k_tlv_flag_54, 0},
	{"k_tlv_flag_55", "p60.pcap", construct_k_tlv_flag_55, 0},
	{"k_tlv_flag_56", "p61.pcap", construct_k_tlv_flag_56, 0},
	{"k_tlv_flag_57", "p62.pcap", construct_k_tlv_flag_57, 0},
	{"k_tlv_flag_58", "p63.pcap", construct_k_tlv_flag_58, 0},
	{"k_tlv_flag_59", "p64.pcap", construct_k_tlv_flag_59, 0},
	{"k_tlv_flag_60", "p65.pcap", construct_k_tlv_flag_60, 0},
	{"k_tlv_flag_61", "p66.pcap", construct_k_tlv_flag_61, 0},
	{"k_tlv_flag_62", "p67.pcap", construct_k_tlv_flag_62, 0},
	{"k_tlv_flag_63", "p68.pcap", construct_k_tlv_flag_63, 0},
	{"k_tlv_flag_64", "p69.pcap", construct_k_tlv_flag_64, 0},
	{"k_tlv_flag_65", "p70.pcap", construct_k_tlv_flag_65, 0},
	{"k_tlv_flag_66", "p71.pcap", construct_k_tlv_flag_66, 0},
	{"k_tlv_flag_67", "p72.pcap", construct_k_tlv_flag_67, 0},
	{"k_tlv_flag_68", "p73.pcap", construct_k_tlv_flag_68, 0},
	{"k_tlv_flag_69", "p74.pcap", construct_k_tlv_flag_69, 0},
	{"k_tlv_flag_70", "p75.pcap", construct_k_tlv_flag_70, 0},
	{"k_tlv_flag_71", "p76.pcap", construct_k_tlv_flag_71, 0},
	{"k_tlv_flag_72", "p77.pcap", construct_k_tlv_flag_72, 0},
	{"k_tlv_flag_73", "p78.pcap", construct_k_tlv_flag_73, 0},
	{"k_tlv_flag_74", "p79.pcap", construct_k_tlv_flag_74, 0},
	{"k_tlv_flag_75", "p80.pcap", construct_k_tlv_flag_75, 0},
	{"k_tlv_flag_76", "p81.pcap", construct_k_tlv_flag_76, 0},
	{"k_tlv_flag_77", "p82.pcap", construct_k_tlv_flag_77, 0},
	{"k_tlv_flag_78", "p83.pcap", construct_k_tlv_flag_78, 0},
	{"k_tlv_flag_79", "p84.pcap", construct_k_tlv_flag_79, 0},
	{"k_tlv_flag_80", "p85.pcap", construct_k_tlv_flag_80, 0},
	{"k_tlv_flag_81", "p86.pcap", construct_k_tlv_flag_81, 0},
	{"k_tlv_flag_82", "p87.pcap", construct_k_tlv_flag_82, 0},
	{"k_tlv_flag_83", "p88.pcap", construct_k_tlv_flag_83, 0},
	{"k_tlv_flag_84", "p89.pcap", construct_k_tlv_flag_84, 0},
	{"k_tlv_flag_85", "p90.pcap", construct_k_tlv_flag_85, 0},
	{"k_tlv_flag_86", "p91.pcap", construct_k_tlv_flag_86, 0},
	{"k_tlv_flag_87", "p92.pcap", construct_k_tlv_flag_87, 0},
	{"k_tlv_flag_88", "p93.pcap", construct_k_tlv_flag_88, 0},
	{"k_tlv_flag_89", "p94.pcap", construct_k_tlv_flag_89, 0},
	{"k_tlv_flag_90", "p95.pcap", construct_k_tlv_flag_90, 0},
	{"k_tlv_flag_91", "p96.pcap", construct_k_tlv_flag_91, 0},
	{"k_tlv_flag_92", "p97.pcap", construct_k_tlv_flag_92, 0},
	{"k_tlv_flag_93", "p98.pcap", construct_k_tlv_flag_93, 0},
	{"k_tlv_flag_94", "p99.pcap", construct_k_tlv_flag_94, 0},
	{"k_tlv_flag_95", "p100.pcap", construct_k_tlv_flag_95, 0},
	{"k_tlv_flag_96", "p101.pcap", construct_k_tlv_flag_96, 0},
	{"k_tlv_flag_97", "p102.pcap", construct_k_tlv_flag_97, 0},
	{"k_tlv_flag_98", "p103.pcap", construct_k_tlv_flag_98, 0},
	{"k_tlv_flag_99", "p104.pcap", construct_k_tlv_flag_99, 0},
	{"k_tlv_flag_100", "p105.pcap", construct_k_tlv_flag_100, 0},
	{"k_tlv_flag_101", "p106.pcap", construct_k_tlv_flag_101, 0},
	{"k_tlv_flag_102", "p107.pcap", construct_k_tlv_flag_102, 0},
	{"k_tlv_flag_103", "p108.pcap", construct_k_tlv_flag_103, 0},
	{"k_tlv_flag_104", "p109.pcap", construct_k_tlv_flag_104, 0},
	{"k_tlv_flag_105", "p110.pcap", construct_k_tlv_flag_105, 0},
	{"k_tlv_flag_106", "p111.pcap", construct_k_tlv_flag_106, 0},
	{"k_tlv_flag_107", "p112.pcap", construct_k_tlv_flag_107, 0},
	{"k_tlv_flag_108", "p113.pcap", construct_k_tlv_flag_108, 0},
	{"k_tlv_flag_109", "p114.pcap", construct_k_tlv_flag_109, 0},
	{"k_tlv_flag_110", "p115.pcap", construct_k_tlv_flag_110, 0},
	{"k_tlv_flag_111", "p116.pcap", construct_k_tlv_flag_111, 0},
	{"k_tlv_flag_112", "p117.pcap", construct_k_tlv_flag_112, 0},
	{"k_tlv_flag_113", "p118.pcap", construct_k_tlv_flag_113, 0},
	{"k_tlv_flag_114", "p119.pcap", construct_k_tlv_flag_114, 0},
	{"k_tlv_flag_115", "p120.pcap", construct_k_tlv_flag_115, 0},
	{"k_tlv_flag_116", "p121.pcap", construct_k_tlv_flag_116, 0},
	{"k_tlv_flag_117", "p122.pcap", construct_k_tlv_flag_117, 0},
	{"k_tlv_flag_118", "p123.pcap", construct_k_tlv_flag_118, 0},
	{"k_tlv_flag_119", "p124.pcap", construct_k_tlv_flag_119, 0},
	{"k_tlv_flag_120", "p125.pcap", construct_k_tlv_flag_120, 0},
	{"k_tlv_flag_121", "p126.pcap", construct_k_tlv_flag_121, 0},
	{"k_tlv_flag_122", "p127.pcap", construct_k_tlv_flag_122, 0},
	{"k_tlv_flag_123", "p128.pcap", construct_k_tlv_flag_123, 0},
	{"k_tlv_flag_124", "p129.pcap", construct_k_tlv_flag_124, 0},
	{"k_tlv_flag_125", "p130.pcap", construct_k_tlv_flag_125, 0},
	{"k_tlv_flag_126", "p131.pcap", construct_k_tlv_flag_126, 0},
	{"k_tlv_flag_127", "p132.pcap", construct_k_tlv_flag_127, 0},
	{"k_tlv_flag_128", "p133.pcap", construct_k_tlv_flag_128, 0},
	{"k_tlv_flag_129", "p134.pcap", construct_k_tlv_flag_129, 0},
	{"k_tlv_flag_130", "p135.pcap", construct_k_tlv_flag_130, 0},
	{"k_tlv_flag_131", "p136.pcap", construct_k_tlv_flag_131, 0},
	{"k_tlv_flag_132", "p137.pcap", construct_k_tlv_flag_132, 0},
	{"k_tlv_flag_133", "p138.pcap", construct_k_tlv_flag_133, 0},
	{"k_tlv_flag_134", "p139.pcap", construct_k_tlv_flag_134, 0},
	{"k_tlv_flag_135", "p140.pcap", construct_k_tlv_flag_135, 0},
	{"k_tlv_flag_136", "p141.pcap", construct_k_tlv_flag_136, 0},
	{"k_tlv_flag_137", "p142.pcap", construct_k_tlv_flag_137, 0},
	{"k_tlv_flag_138", "p143.pcap", construct_k_tlv_flag_138, 0},
	{"k_tlv_flag_139", "p144.pcap", construct_k_tlv_flag_139, 0},
	{"k_tlv_flag_140", "p145.pcap", construct_k_tlv_flag_140, 0},
	{"k_tlv_flag_141", "p146.pcap", construct_k_tlv_flag_141, 0},
	{"k_tlv_flag_142", "p147.pcap", construct_k_tlv_flag_142, 0},
	{"k_tlv_flag_143", "p148.pcap", construct_k_tlv_flag_143, 0},
	{"k_tlv_flag_144", "p149.pcap", construct_k_tlv_flag_144, 0},
	{"k_tlv_flag_145", "p150.pcap", construct_k_tlv_flag_145, 0},
	{"k_tlv_flag_146", "p151.pcap", construct_k_tlv_flag_146, 0},
	{"k_tlv_flag_147", "p152.pcap", construct_k_tlv_flag_147, 0},
	{"k_tlv_flag_148", "p153.pcap", construct_k_tlv_flag_148, 0},
	{"k_tlv_flag_149", "p154.pcap", construct_k_tlv_flag_149, 0},
	{"k_tlv_flag_150", "p155.pcap", construct_k_tlv_flag_150, 0},
	{"k_tlv_flag_151", "p156.pcap", construct_k_tlv_flag_151, 0},
	{"k_tlv_flag_152", "p157.pcap", construct_k_tlv_flag_152, 0},
	{"k_tlv_flag_153", "p158.pcap", construct_k_tlv_flag_153, 0},
	{"k_tlv_flag_154", "p159.pcap", construct_k_tlv_flag_154, 0},
	{"k_tlv_flag_155", "p160.pcap", construct_k_tlv_flag_155, 0},
	{"k_tlv_flag_156", "p161.pcap", construct_k_tlv_flag_156, 0},
	{"k_tlv_flag_157", "p162.pcap", construct_k_tlv_flag_157, 0},
	{"k_tlv_flag_158", "p163.pcap", construct_k_tlv_flag_158, 0},
	{"k_tlv_flag_159", "p164.pcap", construct_k_tlv_flag_159, 0},
	{"k_tlv_flag_160", "p165.pcap", construct_k_tlv_flag_160, 0},
	{"k_tlv_flag_161", "p166.pcap", construct_k_tlv_flag_161, 0},
	{"k_tlv_flag_162", "p167.pcap", construct_k_tlv_flag_162, 0},
	{"k_tlv_flag_163", "p168.pcap", construct_k_tlv_flag_163, 0},
	{"k_tlv_flag_164", "p169.pcap", construct_k_tlv_flag_164, 0},
	{"k_tlv_flag_165", "p170.pcap", construct_k_tlv_flag_165, 0},
	{"k_tlv_flag_166", "p171.pcap", construct_k_tlv_flag_166, 0},
	{"k_tlv_flag_167", "p172.pcap", construct_k_tlv_flag_167, 0},
	{"k_tlv_flag_168", "p173.pcap", construct_k_tlv_flag_168, 0},
	{"k_tlv_flag_169", "p174.pcap", construct_k_tlv_flag_169, 0},
	{"k_tlv_flag_170", "p175.pcap", construct_k_tlv_flag_170, 0},
	{"k_tlv_flag_171", "p176.pcap", construct_k_tlv_flag_171, 0},
	{"k_tlv_flag_172", "p177.pcap", construct_k_tlv_flag_172, 0},
	{"k_tlv_flag_173", "p178.pcap", construct_k_tlv_flag_173, 0},
	{"k_tlv_flag_174", "p179.pcap", construct_k_tlv_flag_174, 0},
	{"k_tlv_flag_175", "p180.pcap", construct_k_tlv_flag_175, 0},
	{"k_tlv_flag_176", "p181.pcap", construct_k_tlv_flag_176, 0},
	{"k_tlv_flag_177", "p182.pcap", construct_k_tlv_flag_177, 0},
	{"k_tlv_flag_178", "p183.pcap", construct_k_tlv_flag_178, 0},
	{"k_tlv_flag_179", "p184.pcap", construct_k_tlv_flag_179, 0},
	{"k_tlv_flag_180", "p185.pcap", construct_k_tlv_flag_180, 0},
	{"k_tlv_flag_181", "p186.pcap", construct_k_tlv_flag_181, 0},
	{"k_tlv_flag_182", "p187.pcap", construct_k_tlv_flag_182, 0},
	{"k_tlv_flag_183", "p188.pcap", construct_k_tlv_flag_183, 0},
	{"k_tlv_flag_184", "p189.pcap", construct_k_tlv_flag_184, 0},
	{"k_tlv_flag_185", "p190.pcap", construct_k_tlv_flag_185, 0},
	{"k_tlv_flag_186", "p191.pcap", construct_k_tlv_flag_186, 0},
	{"k_tlv_flag_187", "p192.pcap", construct_k_tlv_flag_187, 0},
	{"k_tlv_flag_188", "p193.pcap", construct_k_tlv_flag_188, 0},
	{"k_tlv_flag_189", "p194.pcap", construct_k_tlv_flag_189, 0},
	{"k_tlv_flag_190", "p195.pcap", construct_k_tlv_flag_190, 0},
	{"k_tlv_flag_191", "p196.pcap", construct_k_tlv_flag_191, 0},
	{"k_tlv_flag_192", "p197.pcap", construct_k_tlv_flag_192, 0},
	{"k_tlv_flag_193", "p198.pcap", construct_k_tlv_flag_193, 0},
	{"k_tlv_flag_194", "p199.pcap", construct_k_tlv_flag_194, 0},
	{"k_tlv_flag_195", "p200.pcap", construct_k_tlv_flag_195, 0},
	{"k_tlv_flag_196", "p201.pcap", construct_k_tlv_flag_196, 0},
	{"k_tlv_flag_197", "p202.pcap", construct_k_tlv_flag_197, 0},
	{"k_tlv_flag_198", "p203.pcap", construct_k_tlv_flag_198, 0},
	{"k_tlv_flag_199", "p204.pcap", construct_k_tlv_flag_199, 0},
	{"k_tlv_flag_200", "p205.pcap", construct_k_tlv_flag_200, 0},
	{"k_tlv_flag_201", "p206.pcap", construct_k_tlv_flag_201, 0},
	{"k_tlv_flag_202", "p207.pcap", construct_k_tlv_flag_202, 0},
	{"k_tlv_flag_203", "p208.pcap", construct_k_tlv_flag_203, 0},
	{"k_tlv_flag_204", "p209.pcap", construct_k_tlv_flag_204, 0},
	{"k_tlv_flag_205", "p210.pcap", construct_k_tlv_flag_205, 0},
	{"k_tlv_flag_206", "p211.pcap", construct_k_tlv_flag_206, 0},
	{"k_tlv_flag_207", "p212.pcap", construct_k_tlv_flag_207, 0},
	{"k_tlv_flag_208", "p213.pcap", construct_k_tlv_flag_208, 0},
	{"k_tlv_flag_209", "p214.pcap", construct_k_tlv_flag_209, 0},
	{"k_tlv_flag_210", "p215.pcap", construct_k_tlv_flag_210, 0},
	{"k_tlv_flag_211", "p216.pcap", construct_k_tlv_flag_211, 0},
	{"k_tlv_flag_212", "p217.pcap", construct_k_tlv_flag_212, 0},
	{"k_tlv_flag_213", "p218.pcap", construct_k_tlv_flag_213, 0},
	{"k_tlv_flag_214", "p219.pcap", construct_k_tlv_flag_214, 0},
	{"k_tlv_flag_215", "p220.pcap", construct_k_tlv_flag_215, 0},
	{"k_tlv_flag_216", "p221.pcap", construct_k_tlv_flag_216, 0},
	{"k_tlv_flag_217", "p222.pcap", construct_k_tlv_flag_217, 0},
	{"k_tlv_flag_218", "p223.pcap", construct_k_tlv_flag_218, 0},
	{"k_tlv_flag_219", "p224.pcap", construct_k_tlv_flag_219, 0},
	{"k_tlv_flag_220", "p225.pcap", construct_k_tlv_flag_220, 0},
	{"k_tlv_flag_221", "p226.pcap", construct_k_tlv_flag_221, 0},
	{"k_tlv_flag_222", "p227.pcap", construct_k_tlv_flag_222, 0},
	{"k_tlv_flag_223", "p228.pcap", construct_k_tlv_flag_223, 0},
	{"k_tlv_flag_224", "p229.pcap", construct_k_tlv_flag_224, 0},
	{"k_tlv_flag_225", "p230.pcap", construct_k_tlv_flag_225, 0},
	{"k_tlv_flag_226", "p231.pcap", construct_k_tlv_flag_226, 0},
	{"k_tlv_flag_227", "p232.pcap", construct_k_tlv_flag_227, 0},
	{"k_tlv_flag_228", "p233.pcap", construct_k_tlv_flag_228, 0},
	{"k_tlv_flag_229", "p234.pcap", construct_k_tlv_flag_229, 0},
	{"k_tlv_flag_230", "p235.pcap", construct_k_tlv_flag_230, 0},
	{"k_tlv_flag_231", "p236.pcap", construct_k_tlv_flag_231, 0},
	{"k_tlv_flag_232", "p237.pcap", construct_k_tlv_flag_232, 0},
	{"k_tlv_flag_233", "p238.pcap", construct_k_tlv_flag_233, 0},
	{"k_tlv_flag_234", "p239.pcap", construct_k_tlv_flag_234, 0},
	{"k_tlv_flag_235", "p240.pcap", construct_k_tlv_flag_235, 0},
	{"k_tlv_flag_236", "p241.pcap", construct_k_tlv_flag_236, 0},
	{"k_tlv_flag_237", "p242.pcap", construct_k_tlv_flag_237, 0},
	{"k_tlv_flag_238", "p243.pcap", construct_k_tlv_flag_238, 0},
	{"k_tlv_flag_239", "p244.pcap", construct_k_tlv_flag_239, 0},
	{"k_tlv_flag_240", "p245.pcap", construct_k_tlv_flag_240, 0},
	{"k_tlv_flag_241", "p246.pcap", construct_k_tlv_flag_241, 0},
	{"k_tlv_flag_242", "p247.pcap", construct_k_tlv_flag_242, 0},
	{"k_tlv_flag_243", "p248.pcap", construct_k_tlv_flag_243, 0},
	{"k_tlv_flag_244", "p249.pcap", construct_k_tlv_flag_244, 0},
	{"k_tlv_flag_245", "p250.pcap", construct_k_tlv_flag_245, 0},
	{"k_tlv_flag_246", "p251.pcap", construct_k_tlv_flag_246, 0},
	{"k_tlv_flag_247", "p252.pcap", construct_k_tlv_flag_247, 0},
	{"k_tlv_flag_248", "p253.pcap", construct_k_tlv_flag_248, 0},
	{"k_tlv_flag_249", "p254.pcap", construct_k_tlv_flag_249, 0},
	{"k_tlv_flag_250", "p255.pcap", construct_k_tlv_flag_250, 0},
	{"k_tlv_flag_251", "p256.pcap", construct_k_tlv_flag_251, 0},
	{"k_tlv_flag_252", "p257.pcap", construct_k_tlv_flag_252, 0},
	{"k_tlv_flag_253", "p258.pcap", construct_k_tlv_flag_253, 0},
	{"k_tlv_flag_254", "p259.pcap", construct_k_tlv_flag_254, 0},
	{"k_tlv_flag_255", "p260.pcap", construct_k_tlv_flag_255, 0},


	{"k_tlv_ts_len0", "p261.pcap", construct_k_tlv_ts_len0, 0},
	{"k_tlv_ts_len1", "p262.pcap", construct_k_tlv_ts_len1, 0},
	{"k_tlv_ts_len2", "p263.pcap", construct_k_tlv_ts_len2, 0},
	{"k_tlv_ts_len3", "p264.pcap", construct_k_tlv_ts_len3, 0},
	{"k_tlv_ts_len4", "p265.pcap", construct_k_tlv_ts_len4, 0},
	{"k_tlv_ts_len5", "p266.pcap", construct_k_tlv_ts_len5, 0},
	{"k_tlv_ts_len6", "p267.pcap", construct_k_tlv_ts_len6, 0},
	{"k_tlv_ts_len7", "p268.pcap", construct_k_tlv_ts_len7, 0},
	{"k_tlv_ts_len8", "p269.pcap", construct_k_tlv_ts_len8, 0},
	{"k_tlv_ts_len9", "p270.pcap", construct_k_tlv_ts_len9, 0},
	{"k_tlv_ts_len10", "p271.pcap", construct_k_tlv_ts_len10, 0},
	{"k_tlv_ts_len11", "p272.pcap", construct_k_tlv_ts_len11, 0},
	{"k_tlv_ts_len12", "p273.pcap", construct_k_tlv_ts_len12, 0},
	{"k_tlv_ts_len13", "p274.pcap", construct_k_tlv_ts_len13, 0},
	{"k_tlv_ts_len14", "p275.pcap", construct_k_tlv_ts_len14, 0},
	{"k_tlv_ts_len15", "p276.pcap", construct_k_tlv_ts_len15, 0},
	{"k_tlv_ts_len16", "p277.pcap", construct_k_tlv_ts_len16, 0},
	{"k_tlv_ts_len17", "p278.pcap", construct_k_tlv_ts_len17, 0},
	{"k_tlv_ts_len18", "p279.pcap", construct_k_tlv_ts_len18, 0},
	{"k_tlv_ts_len19", "p280.pcap", construct_k_tlv_ts_len19, 0},
	{"k_tlv_ts_len20", "p281.pcap", construct_k_tlv_ts_len20, 0},
	{"k_tlv_ts_len21", "p282.pcap", construct_k_tlv_ts_len21, 0},
	{"k_tlv_ts_len22", "p283.pcap", construct_k_tlv_ts_len22, 0},
	{"k_tlv_ts_len23", "p284.pcap", construct_k_tlv_ts_len23, 0},
	{"k_tlv_ts_len24", "p285.pcap", construct_k_tlv_ts_len24, 0},
	{"k_tlv_ts_len25", "p286.pcap", construct_k_tlv_ts_len25, 0},
	{"k_tlv_ts_len26", "p287.pcap", construct_k_tlv_ts_len26, 0},
	{"k_tlv_ts_len27", "p288.pcap", construct_k_tlv_ts_len27, 0},
	{"k_tlv_ts_len28", "p289.pcap", construct_k_tlv_ts_len28, 0},
	{"k_tlv_ts_len29", "p290.pcap", construct_k_tlv_ts_len29, 0},
	{"k_tlv_ts_len30", "p291.pcap", construct_k_tlv_ts_len30, 0},
	{"k_tlv_ts_len31", "p292.pcap", construct_k_tlv_ts_len31, 0},
	{"k_tlv_ts_len32", "p293.pcap", construct_k_tlv_ts_len32, 0},
	{"k_tlv_ts_len33", "p294.pcap", construct_k_tlv_ts_len33, 0},
	{"k_tlv_ts_len34", "p295.pcap", construct_k_tlv_ts_len34, 0},
	{"k_tlv_ts_len35", "p296.pcap", construct_k_tlv_ts_len35, 0},
	{"k_tlv_ts_len36", "p297.pcap", construct_k_tlv_ts_len36, 0},
	{"k_tlv_ts_len37", "p298.pcap", construct_k_tlv_ts_len37, 0},
	{"k_tlv_ts_len38", "p299.pcap", construct_k_tlv_ts_len38, 0},
	{"k_tlv_ts_len39", "p300.pcap", construct_k_tlv_ts_len39, 0},
	{"k_tlv_ts_len40", "p301.pcap", construct_k_tlv_ts_len40, 0},
	{"k_tlv_ts_len41", "p302.pcap", construct_k_tlv_ts_len41, 0},
	{"k_tlv_ts_len42", "p303.pcap", construct_k_tlv_ts_len42, 0},
	{"k_tlv_ts_len43", "p304.pcap", construct_k_tlv_ts_len43, 0},
	{"k_tlv_ts_len44", "p305.pcap", construct_k_tlv_ts_len44, 0},
	{"k_tlv_ts_len45", "p306.pcap", construct_k_tlv_ts_len45, 0},
	{"k_tlv_ts_len46", "p307.pcap", construct_k_tlv_ts_len46, 0},
	{"k_tlv_ts_len47", "p308.pcap", construct_k_tlv_ts_len47, 0},
	{"k_tlv_ts_len48", "p309.pcap", construct_k_tlv_ts_len48, 0},
	{"k_tlv_ts_len49", "p310.pcap", construct_k_tlv_ts_len49, 0},
	{"k_tlv_ts_len50", "p311.pcap", construct_k_tlv_ts_len50, 0},
	{"k_tlv_ts_len51", "p311.pcap", construct_k_tlv_ts_len51, 0},
	{"k_tlv_ts_len52", "p312.pcap", construct_k_tlv_ts_len52, 0},
	{"k_tlv_ts_len53", "p313.pcap", construct_k_tlv_ts_len53, 0},
	{"k_tlv_ts_len54", "p314.pcap", construct_k_tlv_ts_len54, 0},
	{"k_tlv_ts_len55", "p315.pcap", construct_k_tlv_ts_len55, 0},
	{"k_tlv_ts_len56", "p316.pcap", construct_k_tlv_ts_len56, 0},
	{"k_tlv_ts_len57", "p317.pcap", construct_k_tlv_ts_len57, 0},
	{"k_tlv_ts_len58", "p318.pcap", construct_k_tlv_ts_len58, 0},
	{"k_tlv_ts_len59", "p319.pcap", construct_k_tlv_ts_len59, 0},
	{"k_tlv_ts_len60", "p320.pcap", construct_k_tlv_ts_len60, 0},
	{"k_tlv_ts_len61", "p321.pcap", construct_k_tlv_ts_len61, 0},
	{"k_tlv_ts_len62", "p322.pcap", construct_k_tlv_ts_len62, 0},
	{"k_tlv_ts_len63", "p323.pcap", construct_k_tlv_ts_len63, 0},
	{"k_tlv_ts_len64", "p324.pcap", construct_k_tlv_ts_len64, 0},
	{"k_tlv_ts_len65", "p325.pcap", construct_k_tlv_ts_len65, 0},
	{"k_tlv_ts_len66", "p326.pcap", construct_k_tlv_ts_len66, 0},
	{"k_tlv_ts_len67", "p327.pcap", construct_k_tlv_ts_len67, 0},
	{"k_tlv_ts_len68", "p328.pcap", construct_k_tlv_ts_len68, 0},
	{"k_tlv_ts_len69", "p329.pcap", construct_k_tlv_ts_len69, 0},
	{"k_tlv_ts_len70", "p330.pcap", construct_k_tlv_ts_len70, 0},
	{"k_tlv_ts_len71", "p331.pcap", construct_k_tlv_ts_len71, 0},
	{"k_tlv_ts_len72", "p332.pcap", construct_k_tlv_ts_len72, 0},
	{"k_tlv_ts_len73", "p333.pcap", construct_k_tlv_ts_len73, 0},
	{"k_tlv_ts_len74", "p334.pcap", construct_k_tlv_ts_len74, 0},
	{"k_tlv_ts_len75", "p335.pcap", construct_k_tlv_ts_len75, 0},
	{"k_tlv_ts_len76", "p336.pcap", construct_k_tlv_ts_len76, 0},
	{"k_tlv_ts_len77", "p337.pcap", construct_k_tlv_ts_len77, 0},
	{"k_tlv_ts_len78", "p338.pcap", construct_k_tlv_ts_len78, 0},
	{"k_tlv_ts_len79", "p339.pcap", construct_k_tlv_ts_len79, 0},
	{"k_tlv_ts_len80", "p340.pcap", construct_k_tlv_ts_len80, 0},
	{"k_tlv_ts_len81", "p341.pcap", construct_k_tlv_ts_len81, 0},
	{"k_tlv_ts_len82", "p342.pcap", construct_k_tlv_ts_len82, 0},
	{"k_tlv_ts_len83", "p343.pcap", construct_k_tlv_ts_len83, 0},
	{"k_tlv_ts_len84", "p344.pcap", construct_k_tlv_ts_len84, 0},
	{"k_tlv_ts_len85", "p345.pcap", construct_k_tlv_ts_len85, 0},
	{"k_tlv_ts_len86", "p346.pcap", construct_k_tlv_ts_len86, 0},
	{"k_tlv_ts_len87", "p347.pcap", construct_k_tlv_ts_len87, 0},
	{"k_tlv_ts_len88", "p348.pcap", construct_k_tlv_ts_len88, 0},
	{"k_tlv_ts_len89", "p349.pcap", construct_k_tlv_ts_len89, 0},
	{"k_tlv_ts_len90", "p350.pcap", construct_k_tlv_ts_len90, 0},
	{"k_tlv_ts_len91", "p351.pcap", construct_k_tlv_ts_len91, 0},
	{"k_tlv_ts_len92", "p352.pcap", construct_k_tlv_ts_len92, 0},
	{"k_tlv_ts_len93", "p353.pcap", construct_k_tlv_ts_len93, 0},
	{"k_tlv_ts_len94", "p354.pcap", construct_k_tlv_ts_len94, 0},
	{"k_tlv_ts_len95", "p355.pcap", construct_k_tlv_ts_len95, 0},
	{"k_tlv_ts_len96", "p356.pcap", construct_k_tlv_ts_len96, 0},
	{"k_tlv_ts_len97", "p357.pcap", construct_k_tlv_ts_len97, 0},
	{"k_tlv_ts_len98", "p358.pcap", construct_k_tlv_ts_len98, 0},
	{"k_tlv_ts_len99", "p359.pcap", construct_k_tlv_ts_len99, 0},
	{"k_tlv_ts_len100", "p360.pcap", construct_k_tlv_ts_len100, 0},
	{"k_tlv_ts_len101", "p361.pcap", construct_k_tlv_ts_len101, 0},
	{"k_tlv_ts_len102", "p362.pcap", construct_k_tlv_ts_len102, 0},
	{"k_tlv_ts_len103", "p363.pcap", construct_k_tlv_ts_len103, 0},
	{"k_tlv_ts_len104", "p364.pcap", construct_k_tlv_ts_len104, 0},
	{"k_tlv_ts_len105", "p365.pcap", construct_k_tlv_ts_len105, 0},
	{"k_tlv_ts_len106", "p366.pcap", construct_k_tlv_ts_len106, 0},
	{"k_tlv_ts_len107", "p367.pcap", construct_k_tlv_ts_len107, 0},
	{"k_tlv_ts_len108", "p368.pcap", construct_k_tlv_ts_len108, 0},
	{"k_tlv_ts_len109", "p369.pcap", construct_k_tlv_ts_len109, 0},
	{"k_tlv_ts_len110", "p370.pcap", construct_k_tlv_ts_len110, 0},
	{"k_tlv_ts_len111", "p371.pcap", construct_k_tlv_ts_len111, 0},
	{"k_tlv_ts_len112", "p372.pcap", construct_k_tlv_ts_len112, 0},
	{"k_tlv_ts_len113", "p373.pcap", construct_k_tlv_ts_len113, 0},
	{"k_tlv_ts_len114", "p374.pcap", construct_k_tlv_ts_len114, 0},
	{"k_tlv_ts_len115", "p375.pcap", construct_k_tlv_ts_len115, 0},
	{"k_tlv_ts_len116", "p376.pcap", construct_k_tlv_ts_len116, 0},
	{"k_tlv_ts_len117", "p377.pcap", construct_k_tlv_ts_len117, 0},
	{"k_tlv_ts_len118", "p378.pcap", construct_k_tlv_ts_len118, 0},
	{"k_tlv_ts_len119", "p379.pcap", construct_k_tlv_ts_len119, 0},
	{"k_tlv_ts_len120", "p380.pcap", construct_k_tlv_ts_len120, 0},
	{"k_tlv_ts_len121", "p381.pcap", construct_k_tlv_ts_len121, 0},
	{"k_tlv_ts_len122", "p382.pcap", construct_k_tlv_ts_len122, 0},
	{"k_tlv_ts_len123", "p383.pcap", construct_k_tlv_ts_len123, 0},
	{"k_tlv_ts_len124", "p384.pcap", construct_k_tlv_ts_len124, 0},
	{"k_tlv_ts_len125", "p385.pcap", construct_k_tlv_ts_len125, 0},
	{"k_tlv_ts_len126", "p386.pcap", construct_k_tlv_ts_len126, 0},
	{"k_tlv_ts_len127", "p387.pcap", construct_k_tlv_ts_len127, 0},
	{"k_tlv_ts_len128", "p388.pcap", construct_k_tlv_ts_len128, 0},
	{"k_tlv_ts_len129", "p389.pcap", construct_k_tlv_ts_len129, 0},
	{"k_tlv_ts_len130", "p390.pcap", construct_k_tlv_ts_len130, 0},
	{"k_tlv_ts_len131", "p391.pcap", construct_k_tlv_ts_len131, 0},
	{"k_tlv_ts_len132", "p392.pcap", construct_k_tlv_ts_len132, 0},
	{"k_tlv_ts_len133", "p393.pcap", construct_k_tlv_ts_len133, 0},
	{"k_tlv_ts_len134", "p394.pcap", construct_k_tlv_ts_len134, 0},
	{"k_tlv_ts_len135", "p395.pcap", construct_k_tlv_ts_len135, 0},
	{"k_tlv_ts_len136", "p396.pcap", construct_k_tlv_ts_len136, 0},
	{"k_tlv_ts_len137", "p397.pcap", construct_k_tlv_ts_len137, 0},
	{"k_tlv_ts_len138", "p398.pcap", construct_k_tlv_ts_len138, 0},
	{"k_tlv_ts_len139", "p399.pcap", construct_k_tlv_ts_len139, 0},
	{"k_tlv_ts_len140", "p400.pcap", construct_k_tlv_ts_len140, 0},
	{"k_tlv_ts_len141", "p401.pcap", construct_k_tlv_ts_len141, 0},
	{"k_tlv_ts_len142", "p402.pcap", construct_k_tlv_ts_len142, 0},
	{"k_tlv_ts_len143", "p403.pcap", construct_k_tlv_ts_len143, 0},
	{"k_tlv_ts_len144", "p404.pcap", construct_k_tlv_ts_len144, 0},
	{"k_tlv_ts_len145", "p405.pcap", construct_k_tlv_ts_len145, 0},
	{"k_tlv_ts_len146", "p406.pcap", construct_k_tlv_ts_len146, 0},
	{"k_tlv_ts_len147", "p407.pcap", construct_k_tlv_ts_len147, 0},
	{"k_tlv_ts_len148", "p408.pcap", construct_k_tlv_ts_len148, 0},
	{"k_tlv_ts_len149", "p409.pcap", construct_k_tlv_ts_len149, 0},
	{"k_tlv_ts_len150", "p410.pcap", construct_k_tlv_ts_len150, 0},
	{"k_tlv_ts_len151", "p411.pcap", construct_k_tlv_ts_len151, 0},
	{"k_tlv_ts_len152", "p412.pcap", construct_k_tlv_ts_len152, 0},
	{"k_tlv_ts_len153", "p413.pcap", construct_k_tlv_ts_len153, 0},
	{"k_tlv_ts_len154", "p414.pcap", construct_k_tlv_ts_len154, 0},
	{"k_tlv_ts_len155", "p415.pcap", construct_k_tlv_ts_len155, 0},
	{"k_tlv_ts_len156", "p416.pcap", construct_k_tlv_ts_len156, 0},
	{"k_tlv_ts_len157", "p417.pcap", construct_k_tlv_ts_len157, 0},
	{"k_tlv_ts_len158", "p418.pcap", construct_k_tlv_ts_len158, 0},
	{"k_tlv_ts_len159", "p419.pcap", construct_k_tlv_ts_len159, 0},
	{"k_tlv_ts_len160", "p420.pcap", construct_k_tlv_ts_len160, 0},
	{"k_tlv_ts_len161", "p420.pcap", construct_k_tlv_ts_len161, 0},
	{"k_tlv_ts_len162", "p421.pcap", construct_k_tlv_ts_len162, 0},
	{"k_tlv_ts_len163", "p422.pcap", construct_k_tlv_ts_len163, 0},
	{"k_tlv_ts_len164", "p423.pcap", construct_k_tlv_ts_len164, 0},
	{"k_tlv_ts_len165", "p424.pcap", construct_k_tlv_ts_len165, 0},
	{"k_tlv_ts_len166", "p425.pcap", construct_k_tlv_ts_len166, 0},
	{"k_tlv_ts_len167", "p426.pcap", construct_k_tlv_ts_len167, 0},
	{"k_tlv_ts_len168", "p427.pcap", construct_k_tlv_ts_len168, 0},
	{"k_tlv_ts_len169", "p428.pcap", construct_k_tlv_ts_len169, 0},
	{"k_tlv_ts_len170", "p429.pcap", construct_k_tlv_ts_len170, 0},
	{"k_tlv_ts_len171", "p430.pcap", construct_k_tlv_ts_len171, 0},
	{"k_tlv_ts_len172", "p431.pcap", construct_k_tlv_ts_len172, 0},
	{"k_tlv_ts_len173", "p432.pcap", construct_k_tlv_ts_len173, 0},
	{"k_tlv_ts_len174", "p433.pcap", construct_k_tlv_ts_len174, 0},
	{"k_tlv_ts_len175", "p434.pcap", construct_k_tlv_ts_len175, 0},
	{"k_tlv_ts_len176", "p435.pcap", construct_k_tlv_ts_len176, 0},
	{"k_tlv_ts_len177", "p436.pcap", construct_k_tlv_ts_len177, 0},
	{"k_tlv_ts_len178", "p437.pcap", construct_k_tlv_ts_len178, 0},
	{"k_tlv_ts_len179", "p438.pcap", construct_k_tlv_ts_len179, 0},
	{"k_tlv_ts_len180", "p439.pcap", construct_k_tlv_ts_len180, 0},
	{"k_tlv_ts_len181", "p440.pcap", construct_k_tlv_ts_len181, 0},
	{"k_tlv_ts_len182", "p441.pcap", construct_k_tlv_ts_len182, 0},
	{"k_tlv_ts_len183", "p442.pcap", construct_k_tlv_ts_len183, 0},
	{"k_tlv_ts_len184", "p443.pcap", construct_k_tlv_ts_len184, 0},
	{"k_tlv_ts_len185", "p444.pcap", construct_k_tlv_ts_len185, 0},
	{"k_tlv_ts_len186", "p445.pcap", construct_k_tlv_ts_len186, 0},
	{"k_tlv_ts_len187", "p446.pcap", construct_k_tlv_ts_len187, 0},
	{"k_tlv_ts_len188", "p447.pcap", construct_k_tlv_ts_len188, 0},
	{"k_tlv_ts_len189", "p448.pcap", construct_k_tlv_ts_len189, 0},
	{"k_tlv_ts_len190", "p449.pcap", construct_k_tlv_ts_len190, 0},
	{"k_tlv_ts_len191", "p450.pcap", construct_k_tlv_ts_len191, 0},
	{"k_tlv_ts_len192", "p451.pcap", construct_k_tlv_ts_len192, 0},
	{"k_tlv_ts_len193", "p452.pcap", construct_k_tlv_ts_len193, 0},
	{"k_tlv_ts_len194", "p453.pcap", construct_k_tlv_ts_len194, 0},
	{"k_tlv_ts_len195", "p454.pcap", construct_k_tlv_ts_len195, 0},
	{"k_tlv_ts_len196", "p455.pcap", construct_k_tlv_ts_len196, 0},
	{"k_tlv_ts_len197", "p456.pcap", construct_k_tlv_ts_len197, 0},
	{"k_tlv_ts_len198", "p457.pcap", construct_k_tlv_ts_len198, 0},
	{"k_tlv_ts_len199", "p458.pcap", construct_k_tlv_ts_len199, 0},
	{"k_tlv_ts_len200", "p459.pcap", construct_k_tlv_ts_len200, 0},
	{"k_tlv_ts_len201", "p460.pcap", construct_k_tlv_ts_len201, 0},
	{"k_tlv_ts_len202", "p461.pcap", construct_k_tlv_ts_len202, 0},
	{"k_tlv_ts_len203", "p462.pcap", construct_k_tlv_ts_len203, 0},
	{"k_tlv_ts_len204", "p463.pcap", construct_k_tlv_ts_len204, 0},
	{"k_tlv_ts_len205", "p464.pcap", construct_k_tlv_ts_len205, 0},
	{"k_tlv_ts_len206", "p465.pcap", construct_k_tlv_ts_len206, 0},
	{"k_tlv_ts_len207", "p466.pcap", construct_k_tlv_ts_len207, 0},
	{"k_tlv_ts_len208", "p467.pcap", construct_k_tlv_ts_len208, 0},
	{"k_tlv_ts_len209", "p468.pcap", construct_k_tlv_ts_len209, 0},
	{"k_tlv_ts_len210", "p469.pcap", construct_k_tlv_ts_len210, 0},
	{"k_tlv_ts_len211", "p470.pcap", construct_k_tlv_ts_len211, 0},
	{"k_tlv_ts_len212", "p471.pcap", construct_k_tlv_ts_len212, 0},
	{"k_tlv_ts_len213", "p472.pcap", construct_k_tlv_ts_len213, 0},
	{"k_tlv_ts_len214", "p473.pcap", construct_k_tlv_ts_len214, 0},
	{"k_tlv_ts_len215", "p474.pcap", construct_k_tlv_ts_len215, 0},
	{"k_tlv_ts_len216", "p475.pcap", construct_k_tlv_ts_len216, 0},
	{"k_tlv_ts_len217", "p476.pcap", construct_k_tlv_ts_len217, 0},
	{"k_tlv_ts_len218", "p477.pcap", construct_k_tlv_ts_len218, 0},
	{"k_tlv_ts_len219", "p478.pcap", construct_k_tlv_ts_len219, 0},
	{"k_tlv_ts_len220", "p479.pcap", construct_k_tlv_ts_len220, 0},
	{"k_tlv_ts_len221", "p480.pcap", construct_k_tlv_ts_len221, 0},
	{"k_tlv_ts_len222", "p481.pcap", construct_k_tlv_ts_len222, 0},
	{"k_tlv_ts_len223", "p482.pcap", construct_k_tlv_ts_len223, 0},
	{"k_tlv_ts_len224", "p483.pcap", construct_k_tlv_ts_len224, 0},
	{"k_tlv_ts_len225", "p484.pcap", construct_k_tlv_ts_len225, 0},
	{"k_tlv_ts_len226", "p485.pcap", construct_k_tlv_ts_len226, 0},
	{"k_tlv_ts_len227", "p486.pcap", construct_k_tlv_ts_len227, 0},
	{"k_tlv_ts_len228", "p487.pcap", construct_k_tlv_ts_len228, 0},
	{"k_tlv_ts_len229", "p488.pcap", construct_k_tlv_ts_len229, 0},
	{"k_tlv_ts_len230", "p489.pcap", construct_k_tlv_ts_len230, 0},
	{"k_tlv_ts_len231", "p490.pcap", construct_k_tlv_ts_len231, 0},
	{"k_tlv_ts_len232", "p491.pcap", construct_k_tlv_ts_len232, 0},
	{"k_tlv_ts_len233", "p492.pcap", construct_k_tlv_ts_len233, 0},
	{"k_tlv_ts_len234", "p493.pcap", construct_k_tlv_ts_len234, 0},
	{"k_tlv_ts_len235", "p494.pcap", construct_k_tlv_ts_len235, 0},
	{"k_tlv_ts_len236", "p495.pcap", construct_k_tlv_ts_len236, 0},
	{"k_tlv_ts_len237", "p496.pcap", construct_k_tlv_ts_len237, 0},
	{"k_tlv_ts_len238", "p497.pcap", construct_k_tlv_ts_len238, 0},
	{"k_tlv_ts_len239", "p498.pcap", construct_k_tlv_ts_len239, 0},
	{"k_tlv_ts_len240", "p499.pcap", construct_k_tlv_ts_len240, 0},
	{"k_tlv_ts_len241", "p500.pcap", construct_k_tlv_ts_len241, 0},
	{"k_tlv_ts_len242", "p501.pcap", construct_k_tlv_ts_len242, 0},
	{"k_tlv_ts_len243", "p502.pcap", construct_k_tlv_ts_len243, 0},
	{"k_tlv_ts_len244", "p503.pcap", construct_k_tlv_ts_len244, 0},
	{"k_tlv_ts_len245", "p504.pcap", construct_k_tlv_ts_len245, 0},
	{"k_tlv_ts_len246", "p505.pcap", construct_k_tlv_ts_len246, 0},
	{"k_tlv_ts_len247", "p506.pcap", construct_k_tlv_ts_len247, 0},
	{"k_tlv_ts_len248", "p507.pcap", construct_k_tlv_ts_len248, 0},
	{"k_tlv_ts_len249", "p508.pcap", construct_k_tlv_ts_len249, 0},
	{"k_tlv_ts_len250", "p509.pcap", construct_k_tlv_ts_len250, 0},
	{"k_tlv_ts_len251", "p510.pcap", construct_k_tlv_ts_len251, 0},
	{"k_tlv_ts_len252", "p511.pcap", construct_k_tlv_ts_len252, 0},
	{"k_tlv_ts_len253", "p512.pcap", construct_k_tlv_ts_len253, 0},
	{"k_tlv_ts_len254", "p513.pcap", construct_k_tlv_ts_len254, 0},
	{"k_tlv_ts_len255", "p514.pcap", construct_k_tlv_ts_len255, 0},
	{"k_tlv_ts3_util", "p515.pcap", construct_k_tlv_ts3_util,0},
	{"k_tlv_ts3_util_noise", "p516.pcap", construct_k_tlv_ts3_util_noise, 0},
	{"k_tlv_ts3_full_no_neighbors", "p517.pcap", construct_k_tlv_ts3_full_no_neighbors, 0},
	{"k_tlv_ts3_with_bssid", "p518.pcap", construct_k_tlv_ts3_with_bssid, 0},
	{"k_tlv_ts3_with_bssid_ssidlen", "p519.pcap", construct_k_tlv_ts3_with_bssid_ssidlen,0},

	{"k_tlv_ssid_len0", "p520.pcap", construct_k_tlv_ssid_len0, 0},
	{"k_tlv_ssid_len1", "p521.pcap", construct_k_tlv_ssid_len1, 0},
	{"k_tlv_ssid_len2", "p522.pcap", construct_k_tlv_ssid_len2, 0},
	{"k_tlv_ssid_len3", "p523.pcap", construct_k_tlv_ssid_len3, 0},
	{"k_tlv_ssid_len4", "p524.pcap", construct_k_tlv_ssid_len4, 0},
	{"k_tlv_ssid_len5", "p525.pcap", construct_k_tlv_ssid_len5, 0},
	{"k_tlv_ssid_len6", "p526.pcap", construct_k_tlv_ssid_len6, 0},
	{"k_tlv_ssid_len7", "p527.pcap", construct_k_tlv_ssid_len7, 0},
	{"k_tlv_ssid_len8", "p528.pcap", construct_k_tlv_ssid_len8, 0},
	{"k_tlv_ssid_len9", "p529.pcap", construct_k_tlv_ssid_len9, 0},
	{"k_tlv_ssid_len10", "p530.pcap", construct_k_tlv_ssid_len10, 0},
	{"k_tlv_ssid_len11", "p531.pcap", construct_k_tlv_ssid_len11, 0},
	{"k_tlv_ssid_len12", "p532.pcap", construct_k_tlv_ssid_len12, 0},
	{"k_tlv_ssid_len13", "p533.pcap", construct_k_tlv_ssid_len13, 0},
	{"k_tlv_ssid_len14", "p534.pcap", construct_k_tlv_ssid_len14, 0},
	{"k_tlv_ssid_len15", "p535.pcap", construct_k_tlv_ssid_len15, 0},
	{"k_tlv_ssid_len16", "p536.pcap", construct_k_tlv_ssid_len16, 0},
	{"k_tlv_ssid_len17", "p537.pcap", construct_k_tlv_ssid_len17, 0},
	{"k_tlv_ssid_len18", "p538.pcap", construct_k_tlv_ssid_len18, 0},
	{"k_tlv_ssid_len19", "p539.pcap", construct_k_tlv_ssid_len19, 0},
	{"k_tlv_ssid_len20", "p540.pcap", construct_k_tlv_ssid_len20, 0},
	{"k_tlv_ssid_len21", "p541.pcap", construct_k_tlv_ssid_len21, 0},
	{"k_tlv_ssid_len22", "p542.pcap", construct_k_tlv_ssid_len22, 0},
	{"k_tlv_ssid_len23", "p543.pcap", construct_k_tlv_ssid_len23, 0},
	{"k_tlv_ssid_len24", "p544.pcap", construct_k_tlv_ssid_len24, 0},
	{"k_tlv_ssid_len25", "p545.pcap", construct_k_tlv_ssid_len25, 0},
	{"k_tlv_ssid_len26", "p546.pcap", construct_k_tlv_ssid_len26, 0},
	{"k_tlv_ssid_len27", "p547.pcap", construct_k_tlv_ssid_len27, 0},
	{"k_tlv_ssid_len28", "p548.pcap", construct_k_tlv_ssid_len28, 0},
	{"k_tlv_ssid_len29", "p549.pcap", construct_k_tlv_ssid_len29, 0},
	{"k_tlv_ssid_len30", "p550.pcap", construct_k_tlv_ssid_len30, 0},
	{"k_tlv_ssid_len31", "p551.pcap", construct_k_tlv_ssid_len31, 0},
	{"k_tlv_ssid_len32", "p552.pcap", construct_k_tlv_ssid_len32, 0},
	{"timestamp_tlv_len1_rrr", "p2000.pcap", construct_timestamp_tlv_len1_rrr, 0},
	// 🔴 INVALID RANGE STARTS
	{"k_tlv_ssid_len33", "p553.pcap", construct_k_tlv_ssid_len33, 0},
	{"k_tlv_ssid_len34", "p554.pcap", construct_k_tlv_ssid_len34, 0},
	{"k_tlv_ssid_len35", "p555.pcap", construct_k_tlv_ssid_len35, 0},
	{"k_tlv_ssid_len36", "p556.pcap", construct_k_tlv_ssid_len36, 0},
	{"k_tlv_ssid_len37", "p557.pcap", construct_k_tlv_ssid_len37, 0},
	{"k_tlv_ssid_len38", "p558.pcap", construct_k_tlv_ssid_len38, 0},
	{"k_tlv_ssid_len39", "p559.pcap", construct_k_tlv_ssid_len39, 0},
	{"k_tlv_ssid_len40", "p560.pcap", construct_k_tlv_ssid_len40, 0},
	{"k_tlv_ssid_len41", "p561.pcap", construct_k_tlv_ssid_len41, 0},
	{"k_tlv_ssid_len42", "p562.pcap", construct_k_tlv_ssid_len42, 0},
	{"k_tlv_ssid_len43", "p563.pcap", construct_k_tlv_ssid_len43, 0},
	{"k_tlv_ssid_len44", "p564.pcap", construct_k_tlv_ssid_len44, 0},
	{"k_tlv_ssid_len45", "p565.pcap", construct_k_tlv_ssid_len45, 0},
	{"k_tlv_ssid_len46", "p566.pcap", construct_k_tlv_ssid_len46, 0},
	{"k_tlv_ssid_len47", "p567.pcap", construct_k_tlv_ssid_len47, 0},
	{"k_tlv_ssid_len48", "p568.pcap", construct_k_tlv_ssid_len48, 0},
	{"k_tlv_ssid_len49", "p569.pcap", construct_k_tlv_ssid_len49, 0},
	{"k_tlv_ssid_len50", "p570.pcap", construct_k_tlv_ssid_len50, 0},
	{"k_tlv_ssid_len51", "p571.pcap", construct_k_tlv_ssid_len51, 0},
	{"k_tlv_ssid_len52", "p572.pcap", construct_k_tlv_ssid_len52, 0},
	{"k_tlv_ssid_len53", "p573.pcap", construct_k_tlv_ssid_len53, 0},
	{"k_tlv_ssid_len54", "p574.pcap", construct_k_tlv_ssid_len54, 0},
	{"k_tlv_ssid_len55", "p575.pcap", construct_k_tlv_ssid_len55, 0},
	{"k_tlv_ssid_len56", "p576.pcap", construct_k_tlv_ssid_len56, 0},
	{"k_tlv_ssid_len57", "p577.pcap", construct_k_tlv_ssid_len57, 0},
	{"k_tlv_ssid_len58", "p578.pcap", construct_k_tlv_ssid_len58, 0},
	{"k_tlv_ssid_len59", "p579.pcap", construct_k_tlv_ssid_len59, 0},
	{"k_tlv_ssid_len60", "p580.pcap", construct_k_tlv_ssid_len60, 0},
	{"k_tlv_ssid_len61", "p581.pcap", construct_k_tlv_ssid_len61, 0},
	{"k_tlv_ssid_len62", "p582.pcap", construct_k_tlv_ssid_len62, 0},
	{"k_tlv_ssid_len63", "p583.pcap", construct_k_tlv_ssid_len63, 0},
	{"k_tlv_ssid_len64", "p584.pcap", construct_k_tlv_ssid_len64, 0},
	{"k_tlv_ssid_len65", "p585.pcap", construct_k_tlv_ssid_len65, 0},
	{"k_tlv_ssid_len66", "p586.pcap", construct_k_tlv_ssid_len66, 0},
	{"k_tlv_ssid_len67", "p587.pcap", construct_k_tlv_ssid_len67, 0},
	{"k_tlv_ssid_len68", "p588.pcap", construct_k_tlv_ssid_len68, 0},
	{"k_tlv_ssid_len69", "p589.pcap", construct_k_tlv_ssid_len69, 0},
	{"k_tlv_ssid_len70", "p590.pcap", construct_k_tlv_ssid_len70, 0},
	{"k_tlv_ssid_len71", "p591.pcap", construct_k_tlv_ssid_len71, 0},
	{"k_tlv_ssid_len72", "p592.pcap", construct_k_tlv_ssid_len72, 0},
	{"k_tlv_ssid_len73", "p593.pcap", construct_k_tlv_ssid_len73, 0},
	{"k_tlv_ssid_len74", "p594.pcap", construct_k_tlv_ssid_len74, 0},
	{"k_tlv_ssid_len75", "p595.pcap", construct_k_tlv_ssid_len75, 0},
	{"k_tlv_ssid_len76", "p596.pcap", construct_k_tlv_ssid_len76, 0},
	{"k_tlv_ssid_len77", "p597.pcap", construct_k_tlv_ssid_len77, 0},
	{"k_tlv_ssid_len78", "p598.pcap", construct_k_tlv_ssid_len78, 0},
	{"k_tlv_ssid_len79", "p599.pcap", construct_k_tlv_ssid_len79, 0},
	{"k_tlv_ssid_len80", "p600.pcap", construct_k_tlv_ssid_len80, 0},
	{"k_tlv_ssid_len81", "p601.pcap", construct_k_tlv_ssid_len81, 0},
	{"k_tlv_ssid_len82", "p602.pcap", construct_k_tlv_ssid_len82, 0},
	{"k_tlv_ssid_len83", "p603.pcap", construct_k_tlv_ssid_len83, 0},
	{"k_tlv_ssid_len84", "p604.pcap", construct_k_tlv_ssid_len84, 0},
	{"k_tlv_ssid_len85", "p605.pcap", construct_k_tlv_ssid_len85, 0},
	{"k_tlv_ssid_len86", "p606.pcap", construct_k_tlv_ssid_len86, 0},
	{"k_tlv_ssid_len87", "p607.pcap", construct_k_tlv_ssid_len87, 0},
	{"k_tlv_ssid_len88", "p608.pcap", construct_k_tlv_ssid_len88, 0},
	{"k_tlv_ssid_len89", "p609.pcap", construct_k_tlv_ssid_len89, 0},
	{"k_tlv_ssid_len90", "p610.pcap", construct_k_tlv_ssid_len90, 0},
	{"k_tlv_ssid_len91", "p611.pcap", construct_k_tlv_ssid_len91, 0},
	{"k_tlv_ssid_len92", "p612.pcap", construct_k_tlv_ssid_len92, 0},
	{"k_tlv_ssid_len93", "p613.pcap", construct_k_tlv_ssid_len93, 0},
	{"k_tlv_ssid_len94", "p614.pcap", construct_k_tlv_ssid_len94, 0},
	{"k_tlv_ssid_len95", "p615.pcap", construct_k_tlv_ssid_len95, 0},
	{"k_tlv_ssid_len96", "p616.pcap", construct_k_tlv_ssid_len96, 0},
	{"k_tlv_ssid_len97", "p617.pcap", construct_k_tlv_ssid_len97, 0},
	{"k_tlv_ssid_len98", "p618.pcap", construct_k_tlv_ssid_len98, 0},
	{"k_tlv_ssid_len99", "p619.pcap", construct_k_tlv_ssid_len99, 0},
	{"k_tlv_ssid_len100", "p620.pcap", construct_k_tlv_ssid_len100, 0},
	{"k_tlv_ssid_len101", "p621.pcap", construct_k_tlv_ssid_len101, 0},
	{"k_tlv_ssid_len102", "p622.pcap", construct_k_tlv_ssid_len102, 0},
	{"k_tlv_ssid_len103", "p623.pcap", construct_k_tlv_ssid_len103, 0},
	{"k_tlv_ssid_len104", "p624.pcap", construct_k_tlv_ssid_len104, 0},
	{"k_tlv_ssid_len105", "p625.pcap", construct_k_tlv_ssid_len105, 0},
	{"k_tlv_ssid_len106", "p626.pcap", construct_k_tlv_ssid_len106, 0},
	{"k_tlv_ssid_len107", "p627.pcap", construct_k_tlv_ssid_len107, 0},
	{"k_tlv_ssid_len108", "p628.pcap", construct_k_tlv_ssid_len108, 0},
	{"k_tlv_ssid_len109", "p629.pcap", construct_k_tlv_ssid_len109, 0},
	{"k_tlv_ssid_len110", "p630.pcap", construct_k_tlv_ssid_len110, 0},
	{"k_tlv_ssid_len111", "p631.pcap", construct_k_tlv_ssid_len111, 0},
	{"k_tlv_ssid_len112", "p632.pcap", construct_k_tlv_ssid_len112, 0},
	{"k_tlv_ssid_len113", "p633.pcap", construct_k_tlv_ssid_len113, 0},
	{"k_tlv_ssid_len114", "p634.pcap", construct_k_tlv_ssid_len114, 0},
	{"k_tlv_ssid_len115", "p635.pcap", construct_k_tlv_ssid_len115, 0},
	{"k_tlv_ssid_len116", "p636.pcap", construct_k_tlv_ssid_len116, 0},
	{"k_tlv_ssid_len117", "p637.pcap", construct_k_tlv_ssid_len117, 0},
	{"k_tlv_ssid_len118", "p638.pcap", construct_k_tlv_ssid_len118, 0},
	{"k_tlv_ssid_len119", "p639.pcap", construct_k_tlv_ssid_len119, 0},
	{"k_tlv_ssid_len120", "p640.pcap", construct_k_tlv_ssid_len120, 0},
	{"k_tlv_ssid_len121", "p641.pcap", construct_k_tlv_ssid_len121, 0},
	{"k_tlv_ssid_len122", "p642.pcap", construct_k_tlv_ssid_len122, 0},
	{"k_tlv_ssid_len123", "p643.pcap", construct_k_tlv_ssid_len123, 0},
	{"k_tlv_ssid_len124", "p644.pcap", construct_k_tlv_ssid_len124, 0},
	{"k_tlv_ssid_len125", "p645.pcap", construct_k_tlv_ssid_len125, 0},
	{"k_tlv_ssid_len126", "p646.pcap", construct_k_tlv_ssid_len126, 0},
	{"k_tlv_ssid_len127", "p647.pcap", construct_k_tlv_ssid_len127, 0},
	{"k_tlv_ssid_len128", "p648.pcap", construct_k_tlv_ssid_len128, 0},
	{"k_tlv_ssid_len129", "p649.pcap", construct_k_tlv_ssid_len129, 0},
	{"k_tlv_ssid_len130", "p650.pcap", construct_k_tlv_ssid_len130, 0},
	{"k_tlv_ssid_len131", "p651.pcap", construct_k_tlv_ssid_len131, 0},
	{"k_tlv_ssid_len132", "p652.pcap", construct_k_tlv_ssid_len132, 0},
	{"k_tlv_ssid_len133", "p653.pcap", construct_k_tlv_ssid_len133, 0},
	{"k_tlv_ssid_len134", "p654.pcap", construct_k_tlv_ssid_len134, 0},
	{"k_tlv_ssid_len135", "p655.pcap", construct_k_tlv_ssid_len135, 0},
	{"k_tlv_ssid_len136", "p656.pcap", construct_k_tlv_ssid_len136, 0},
	{"k_tlv_ssid_len137", "p657.pcap", construct_k_tlv_ssid_len137, 0},
	{"k_tlv_ssid_len138", "p658.pcap", construct_k_tlv_ssid_len138, 0},
	{"k_tlv_ssid_len139", "p659.pcap", construct_k_tlv_ssid_len139, 0},
	{"k_tlv_ssid_len140", "p660.pcap", construct_k_tlv_ssid_len140, 0},
	{"k_tlv_ssid_len141", "p661.pcap", construct_k_tlv_ssid_len141, 0},
	{"k_tlv_ssid_len142", "p662.pcap", construct_k_tlv_ssid_len142, 0},
	{"k_tlv_ssid_len143", "p663.pcap", construct_k_tlv_ssid_len143, 0},
	{"k_tlv_ssid_len144", "p664.pcap", construct_k_tlv_ssid_len144, 0},
	{"k_tlv_ssid_len145", "p665.pcap", construct_k_tlv_ssid_len145, 0},
	{"k_tlv_ssid_len146", "p666.pcap", construct_k_tlv_ssid_len146, 0},
	{"k_tlv_ssid_len147", "p667.pcap", construct_k_tlv_ssid_len147, 0},
	{"k_tlv_ssid_len148", "p668.pcap", construct_k_tlv_ssid_len148, 0},
	{"k_tlv_ssid_len149", "p669.pcap", construct_k_tlv_ssid_len149, 0},
	{"k_tlv_ssid_len150", "p670.pcap", construct_k_tlv_ssid_len150, 0},
	{"k_tlv_ssid_len151", "p671.pcap", construct_k_tlv_ssid_len151, 0},
	{"k_tlv_ssid_len152", "p672.pcap", construct_k_tlv_ssid_len152, 0},
	{"k_tlv_ssid_len153", "p673.pcap", construct_k_tlv_ssid_len153, 0},
	{"k_tlv_ssid_len154", "p674.pcap", construct_k_tlv_ssid_len154, 0},
	{"k_tlv_ssid_len155", "p675.pcap", construct_k_tlv_ssid_len155, 0},
	{"k_tlv_ssid_len156", "p676.pcap", construct_k_tlv_ssid_len156, 0},
	{"k_tlv_ssid_len157", "p677.pcap", construct_k_tlv_ssid_len157, 0},
	{"k_tlv_ssid_len158", "p678.pcap", construct_k_tlv_ssid_len158, 0},
	{"k_tlv_ssid_len159", "p679.pcap", construct_k_tlv_ssid_len159, 0},
	{"k_tlv_ssid_len160", "p680.pcap", construct_k_tlv_ssid_len160, 0},
	{"k_tlv_ssid_len161", "p681.pcap", construct_k_tlv_ssid_len161, 0},
	{"k_tlv_ssid_len162", "p682.pcap", construct_k_tlv_ssid_len162, 0},
	{"k_tlv_ssid_len163", "p683.pcap", construct_k_tlv_ssid_len163, 0},
	{"k_tlv_ssid_len164", "p684.pcap", construct_k_tlv_ssid_len164, 0},
	{"k_tlv_ssid_len165", "p685.pcap", construct_k_tlv_ssid_len165, 0},
	{"k_tlv_ssid_len166", "p686.pcap", construct_k_tlv_ssid_len166, 0},
	{"k_tlv_ssid_len167", "p687.pcap", construct_k_tlv_ssid_len167, 0},
	{"k_tlv_ssid_len168", "p688.pcap", construct_k_tlv_ssid_len168, 0},
	{"k_tlv_ssid_len169", "p689.pcap", construct_k_tlv_ssid_len169, 0},
	{"k_tlv_ssid_len170", "p690.pcap", construct_k_tlv_ssid_len170, 0},
	{"k_tlv_ssid_len171", "p691.pcap", construct_k_tlv_ssid_len171, 0},
	{"k_tlv_ssid_len172", "p692.pcap", construct_k_tlv_ssid_len172, 0},
	{"k_tlv_ssid_len173", "p693.pcap", construct_k_tlv_ssid_len173, 0},
	{"k_tlv_ssid_len174", "p694.pcap", construct_k_tlv_ssid_len174, 0},
	{"k_tlv_ssid_len175", "p695.pcap", construct_k_tlv_ssid_len175, 0},
	{"k_tlv_ssid_len176", "p696.pcap", construct_k_tlv_ssid_len176, 0},
	{"k_tlv_ssid_len177", "p697.pcap", construct_k_tlv_ssid_len177, 0},
	{"k_tlv_ssid_len178", "p698.pcap", construct_k_tlv_ssid_len178, 0},
	{"k_tlv_ssid_len179", "p699.pcap", construct_k_tlv_ssid_len179, 0},
	{"k_tlv_ssid_len180", "p700.pcap", construct_k_tlv_ssid_len180, 0},
	{"k_tlv_ssid_len181", "p701.pcap", construct_k_tlv_ssid_len181, 0},
	{"k_tlv_ssid_len182", "p702.pcap", construct_k_tlv_ssid_len182, 0},
	{"k_tlv_ssid_len183", "p703.pcap", construct_k_tlv_ssid_len183, 0},
	{"k_tlv_ssid_len184", "p704.pcap", construct_k_tlv_ssid_len184, 0},
	{"k_tlv_ssid_len185", "p705.pcap", construct_k_tlv_ssid_len185, 0},
	{"k_tlv_ssid_len186", "p706.pcap", construct_k_tlv_ssid_len186, 0},
	{"k_tlv_ssid_len187", "p707.pcap", construct_k_tlv_ssid_len187, 0},
	{"k_tlv_ssid_len188", "p708.pcap", construct_k_tlv_ssid_len188, 0},
	{"k_tlv_ssid_len189", "p709.pcap", construct_k_tlv_ssid_len189, 0},
	{"k_tlv_ssid_len190", "p710.pcap", construct_k_tlv_ssid_len190, 0},
	{"k_tlv_ssid_len191", "p711.pcap", construct_k_tlv_ssid_len191, 0},
	{"k_tlv_ssid_len192", "p712.pcap", construct_k_tlv_ssid_len192, 0},
	{"k_tlv_ssid_len193", "p713.pcap", construct_k_tlv_ssid_len193, 0},
	{"k_tlv_ssid_len194", "p714.pcap", construct_k_tlv_ssid_len194, 0},
	{"k_tlv_ssid_len195", "p715.pcap", construct_k_tlv_ssid_len195, 0},
	{"k_tlv_ssid_len196", "p716.pcap", construct_k_tlv_ssid_len196, 0},
	{"k_tlv_ssid_len197", "p717.pcap", construct_k_tlv_ssid_len197, 0},
	{"k_tlv_ssid_len198", "p718.pcap", construct_k_tlv_ssid_len198, 0},
	{"k_tlv_ssid_len199", "p719.pcap", construct_k_tlv_ssid_len199, 0},
	{"k_tlv_ssid_len200", "p720.pcap", construct_k_tlv_ssid_len200, 0},
	{"k_tlv_ssid_len201", "p721.pcap", construct_k_tlv_ssid_len201, 0},
	{"k_tlv_ssid_len202", "p722.pcap", construct_k_tlv_ssid_len202, 0},
	{"k_tlv_ssid_len203", "p723.pcap", construct_k_tlv_ssid_len203, 0},
	{"k_tlv_ssid_len204", "p724.pcap", construct_k_tlv_ssid_len204, 0},
	{"k_tlv_ssid_len205", "p725.pcap", construct_k_tlv_ssid_len205, 0},
	{"k_tlv_ssid_len206", "p726.pcap", construct_k_tlv_ssid_len206, 0},
	{"k_tlv_ssid_len207", "p727.pcap", construct_k_tlv_ssid_len207, 0},
	{"k_tlv_ssid_len208", "p728.pcap", construct_k_tlv_ssid_len208, 0},
	{"k_tlv_ssid_len209", "p729.pcap", construct_k_tlv_ssid_len209, 0},
	{"k_tlv_ssid_len210", "p730.pcap", construct_k_tlv_ssid_len210, 0},
	{"k_tlv_ssid_len211", "p731.pcap", construct_k_tlv_ssid_len211, 0},
	{"k_tlv_ssid_len212", "p732.pcap", construct_k_tlv_ssid_len212, 0},
	{"k_tlv_ssid_len213", "p733.pcap", construct_k_tlv_ssid_len213, 0},
	{"k_tlv_ssid_len214", "p734.pcap", construct_k_tlv_ssid_len214, 0},
	{"k_tlv_ssid_len215", "p735.pcap", construct_k_tlv_ssid_len215, 0},
	{"k_tlv_ssid_len216", "p736.pcap", construct_k_tlv_ssid_len216, 0},
	{"k_tlv_ssid_len217", "p737.pcap", construct_k_tlv_ssid_len217, 0},
	{"k_tlv_ssid_len218", "p738.pcap", construct_k_tlv_ssid_len218, 0},
	{"k_tlv_ssid_len219", "p739.pcap", construct_k_tlv_ssid_len219, 0},
	{"k_tlv_ssid_len220", "p740.pcap", construct_k_tlv_ssid_len220, 0},
	{"k_tlv_ssid_len221", "p741.pcap", construct_k_tlv_ssid_len221, 0},
	{"k_tlv_ssid_len222", "p742.pcap", construct_k_tlv_ssid_len222, 0},
	{"k_tlv_ssid_len223", "p743.pcap", construct_k_tlv_ssid_len223, 0},
	{"k_tlv_ssid_len224", "p744.pcap", construct_k_tlv_ssid_len224, 0},
	{"k_tlv_ssid_len225", "p745.pcap", construct_k_tlv_ssid_len225, 0},
	{"k_tlv_ssid_len226", "p746.pcap", construct_k_tlv_ssid_len226, 0},
	{"k_tlv_ssid_len227", "p747.pcap", construct_k_tlv_ssid_len227, 0},
	{"k_tlv_ssid_len228", "p748.pcap", construct_k_tlv_ssid_len228, 0},
	{"k_tlv_ssid_len229", "p749.pcap", construct_k_tlv_ssid_len229, 0},
	{"k_tlv_ssid_len230", "p750.pcap", construct_k_tlv_ssid_len230, 0},
	{"k_tlv_ssid_len231", "p751.pcap", construct_k_tlv_ssid_len231, 0},
	{"k_tlv_ssid_len232", "p752.pcap", construct_k_tlv_ssid_len232, 0},
	{"k_tlv_ssid_len233", "p753.pcap", construct_k_tlv_ssid_len233, 0},
	{"k_tlv_ssid_len234", "p754.pcap", construct_k_tlv_ssid_len234, 0},
	{"k_tlv_ssid_len235", "p755.pcap", construct_k_tlv_ssid_len235, 0},
	{"k_tlv_ssid_len236", "p756.pcap", construct_k_tlv_ssid_len236, 0},
	{"k_tlv_ssid_len237", "p757.pcap", construct_k_tlv_ssid_len237, 0},
	{"k_tlv_ssid_len238", "p758.pcap", construct_k_tlv_ssid_len238, 0},
	{"k_tlv_ssid_len239", "p759.pcap", construct_k_tlv_ssid_len239, 0},
	{"k_tlv_ssid_len240", "p760.pcap", construct_k_tlv_ssid_len240, 0},
	{"k_tlv_ssid_len241", "p761.pcap", construct_k_tlv_ssid_len241, 0},
	{"k_tlv_ssid_len242", "p762.pcap", construct_k_tlv_ssid_len242, 0},
	{"k_tlv_ssid_len243", "p763.pcap", construct_k_tlv_ssid_len243, 0},
	{"k_tlv_ssid_len244", "p764.pcap", construct_k_tlv_ssid_len244, 0},
	{"k_tlv_ssid_len245", "p765.pcap", construct_k_tlv_ssid_len245, 0},
	{"k_tlv_ssid_len246", "p766.pcap", construct_k_tlv_ssid_len246, 0},
	{"k_tlv_ssid_len247", "p767.pcap", construct_k_tlv_ssid_len247, 0},
	{"k_tlv_ssid_len248", "p768.pcap", construct_k_tlv_ssid_len248, 0},
	{"k_tlv_ssid_len249", "p769.pcap", construct_k_tlv_ssid_len249, 0},
	{"k_tlv_ssid_len250", "p770.pcap", construct_k_tlv_ssid_len250, 0},
	{"k_tlv_ssid_len251", "p771.pcap", construct_k_tlv_ssid_len251, 0},
	{"k_tlv_ssid_len252", "p772.pcap", construct_k_tlv_ssid_len252, 0},
	{"k_tlv_ssid_len253", "p773.pcap", construct_k_tlv_ssid_len253, 0},
	{"k_tlv_ssid_len254", "p774.pcap", construct_k_tlv_ssid_len254, 0},
	{"k_tlv_ssid_len255", "p775.pcap", construct_k_tlv_ssid_len255, 0},
	{"k_tlv_upto_signal_strength", "p776.pcap", construct_k_tlv_upto_signal_strength, 0},

	{"k_cb_len0", "p777.pcap", construct_k_cb_len0, 0},
	{"k_cb_len1", "p778.pcap", construct_k_cb_len1, 0},
	{"k_cb_len2", "p779.pcap", construct_k_cb_len2, 0},
	{"k_cb_len3", "p780.pcap", construct_k_cb_len3, 0},
	{"k_cb_len4", "p781.pcap", construct_k_cb_len4, 0},
	{"k_cb_len5", "p782.pcap", construct_k_cb_len5, 0},
	{"k_cb_len6", "p783.pcap", construct_k_cb_len6, 0},
	{"k_cb_len7", "p784.pcap", construct_k_cb_len7, 0},
	{"k_cb_len8", "p785.pcap", construct_k_cb_len8, 0},
	{"k_cb_len9", "p786.pcap", construct_k_cb_len9, 0},
	{"k_cb_len10", "p787.pcap", construct_k_cb_len10, 0},
	{"k_cb_len11", "p788.pcap", construct_k_cb_len11, 0},
	{"k_cb_len12", "p789.pcap", construct_k_cb_len12, 0},
	{"k_cb_len13", "p790.pcap", construct_k_cb_len13, 0},
	{"k_cb_len14", "p791.pcap", construct_k_cb_len14, 0},
	{"k_cb_len15", "p792.pcap", construct_k_cb_len15, 0},
	{"k_cb_len16", "p793.pcap", construct_k_cb_len16, 0},
	{"k_cb_len17", "p794.pcap", construct_k_cb_len17, 0},
	{"k_cb_len18", "p795.pcap", construct_k_cb_len18, 0},
	{"k_cb_len19", "p796.pcap", construct_k_cb_len19, 0},
	{"k_cb_len20", "p797.pcap", construct_k_cb_len20, 0},
	{"k_cb_len21", "p798.pcap", construct_k_cb_len21, 0},
	{"k_cb_len22", "p799.pcap", construct_k_cb_len22, 0},
	{"k_cb_len23", "p800.pcap", construct_k_cb_len23, 0},
	{"k_cb_len24", "p801.pcap", construct_k_cb_len24, 0},
	{"k_cb_len25", "p802.pcap", construct_k_cb_len25, 0},
	{"k_cb_len26", "p803.pcap", construct_k_cb_len26, 0},
	{"k_cb_len27", "p804.pcap", construct_k_cb_len27, 0},
	{"k_cb_len28", "p805.pcap", construct_k_cb_len28, 0},
	{"k_cb_len29", "p806.pcap", construct_k_cb_len29, 0},
	{"k_cb_len30", "p807.pcap", construct_k_cb_len30, 0},
	{"k_cb_len31", "p808.pcap", construct_k_cb_len31, 0},
	{"k_cb_len32", "p809.pcap", construct_k_cb_len32, 0},
	{"k_cb_len33", "p810.pcap", construct_k_cb_len33, 0},
	{"k_cb_len34", "p811.pcap", construct_k_cb_len34, 0},
	{"k_cb_len35", "p812.pcap", construct_k_cb_len35, 0},
	{"k_cb_len36", "p813.pcap", construct_k_cb_len36, 0},
	{"k_cb_len37", "p814.pcap", construct_k_cb_len37, 0},
	{"k_cb_len38", "p815.pcap", construct_k_cb_len38, 0},
	{"k_cb_len39", "p816.pcap", construct_k_cb_len39, 0},
	{"k_cb_len40", "p817.pcap", construct_k_cb_len40, 0},
	{"k_cb_len41", "p818.pcap", construct_k_cb_len41, 0},
	{"k_cb_len42", "p819.pcap", construct_k_cb_len42, 0},
	{"k_cb_len43", "p820.pcap", construct_k_cb_len43, 0},
	{"k_cb_len44", "p821.pcap", construct_k_cb_len44, 0},
	{"k_cb_len45", "p822.pcap", construct_k_cb_len45, 0},
	{"k_cb_len46", "p823.pcap", construct_k_cb_len46, 0},
	{"k_cb_len47", "p824.pcap", construct_k_cb_len47, 0},
	{"k_cb_len48", "p825.pcap", construct_k_cb_len48, 0},
	{"k_cb_len49", "p826.pcap", construct_k_cb_len49, 0},
	{"k_cb_len50", "p827.pcap", construct_k_cb_len50, 0},
	{"k_cb_len51", "p828.pcap", construct_k_cb_len51, 0},
	{"k_cb_len52", "p829.pcap", construct_k_cb_len52, 0},
	{"k_cb_len53", "p830.pcap", construct_k_cb_len53, 0},
	{"k_cb_len54", "p831.pcap", construct_k_cb_len54, 0},
	{"k_cb_len55", "p832.pcap", construct_k_cb_len55, 0},
	{"k_cb_len56", "p833.pcap", construct_k_cb_len56, 0},
	{"k_cb_len57", "p834.pcap", construct_k_cb_len57, 0},
	{"k_cb_len58", "p835.pcap", construct_k_cb_len58, 0},
	{"k_cb_len59", "p836.pcap", construct_k_cb_len59, 0},
	{"k_cb_len60", "p837.pcap", construct_k_cb_len60, 0},
	{"k_cb_len61", "p838.pcap", construct_k_cb_len61, 0},
	{"k_cb_len62", "p839.pcap", construct_k_cb_len62, 0},
	{"k_cb_len63", "p840.pcap", construct_k_cb_len63, 0},
	{"k_cb_len64", "p841.pcap", construct_k_cb_len64, 0},
	{"k_cb_len65", "p842.pcap", construct_k_cb_len65, 0},
	{"k_cb_len66", "p843.pcap", construct_k_cb_len66, 0},
	{"k_cb_len67", "p844.pcap", construct_k_cb_len67, 0},
	{"k_cb_len68", "p845.pcap", construct_k_cb_len68, 0},
	{"k_cb_len69", "p846.pcap", construct_k_cb_len69, 0},
	{"k_cb_len70", "p847.pcap", construct_k_cb_len70, 0},
	{"k_cb_len71", "p848.pcap", construct_k_cb_len71, 0},
	{"k_cb_len72", "p849.pcap", construct_k_cb_len72, 0},
	{"k_cb_len73", "p850.pcap", construct_k_cb_len73, 0},
	{"k_cb_len74", "p851.pcap", construct_k_cb_len74, 0},
	{"k_cb_len75", "p852.pcap", construct_k_cb_len75, 0},
	{"k_cb_len76", "p853.pcap", construct_k_cb_len76, 0},
	{"k_cb_len77", "p854.pcap", construct_k_cb_len77, 0},
	{"k_cb_len78", "p855.pcap", construct_k_cb_len78, 0},
	{"k_cb_len79", "p856.pcap", construct_k_cb_len79, 0},
	{"k_cb_len80", "p857.pcap", construct_k_cb_len80, 0},
	{"k_cb_len81", "p858.pcap", construct_k_cb_len81, 0},
	{"k_cb_len82", "p859.pcap", construct_k_cb_len82, 0},
	{"k_cb_len83", "p860.pcap", construct_k_cb_len83, 0},
	{"k_cb_len84", "p861.pcap", construct_k_cb_len84, 0},
	{"k_cb_len85", "p862.pcap", construct_k_cb_len85, 0},
	{"k_cb_len86", "p863.pcap", construct_k_cb_len86, 0},
	{"k_cb_len87", "p864.pcap", construct_k_cb_len87, 0},
	{"k_cb_len88", "p865.pcap", construct_k_cb_len88, 0},
	{"k_cb_len89", "p866.pcap", construct_k_cb_len89, 0},
	{"k_cb_len90", "p867.pcap", construct_k_cb_len90, 0},
	{"k_cb_len91", "p868.pcap", construct_k_cb_len91, 0},
	{"k_cb_len92", "p869.pcap", construct_k_cb_len92, 0},
	{"k_cb_len93", "p870.pcap", construct_k_cb_len93, 0},
	{"k_cb_len94", "p871.pcap", construct_k_cb_len94, 0},
	{"k_cb_len95", "p872.pcap", construct_k_cb_len95, 0},
	{"k_cb_len96", "p873.pcap", construct_k_cb_len96, 0},
	{"k_cb_len97", "p874.pcap", construct_k_cb_len97, 0},
	{"k_cb_len98", "p875.pcap", construct_k_cb_len98, 0},
	{"k_cb_len99", "p876.pcap", construct_k_cb_len99, 0},
	{"k_cb_len100", "p877.pcap", construct_k_cb_len100, 0},
	{"k_cb_len101", "p878.pcap", construct_k_cb_len101, 0},
	{"k_cb_len102", "p879.pcap", construct_k_cb_len102, 0},
	{"k_cb_len103", "p880.pcap", construct_k_cb_len103, 0},
	{"k_cb_len104", "p881.pcap", construct_k_cb_len104, 0},
	{"k_cb_len105", "p882.pcap", construct_k_cb_len105, 0},
	{"k_cb_len106", "p883.pcap", construct_k_cb_len106, 0},
	{"k_cb_len107", "p884.pcap", construct_k_cb_len107, 0},
	{"k_cb_len108", "p885.pcap", construct_k_cb_len108, 0},
	{"k_cb_len109", "p886.pcap", construct_k_cb_len109, 0},
	{"k_cb_len110", "p887.pcap", construct_k_cb_len110, 0},
	{"k_cb_len111", "p888.pcap", construct_k_cb_len111, 0},
	{"k_cb_len112", "p889.pcap", construct_k_cb_len112, 0},
	{"k_cb_len113", "p890.pcap", construct_k_cb_len113, 0},
	{"k_cb_len114", "p891.pcap", construct_k_cb_len114, 0},
	{"k_cb_len115", "p892.pcap", construct_k_cb_len115, 0},
	{"k_cb_len116", "p893.pcap", construct_k_cb_len116, 0},
	{"k_cb_len117", "p894.pcap", construct_k_cb_len117, 0},
	{"k_cb_len118", "p895.pcap", construct_k_cb_len118, 0},
	{"k_cb_len119", "p896.pcap", construct_k_cb_len119, 0},
	{"k_cb_len120", "p897.pcap", construct_k_cb_len120, 0},
	{"k_cb_len121", "p898.pcap", construct_k_cb_len121, 0},
	{"k_cb_len122", "p899.pcap", construct_k_cb_len122, 0},
	{"k_cb_len123", "p900.pcap", construct_k_cb_len123, 0},
	{"k_cb_len124", "p901.pcap", construct_k_cb_len124, 0},
	{"k_cb_len125", "p902.pcap", construct_k_cb_len125, 0},
	{"k_cb_len126", "p903.pcap", construct_k_cb_len126, 0},
	{"k_cb_len127", "p904.pcap", construct_k_cb_len127, 0},
	{"k_cb_len128", "p905.pcap", construct_k_cb_len128, 0},
	{"k_cb_len129", "p906.pcap", construct_k_cb_len129, 0},
	{"k_cb_len130", "p907.pcap", construct_k_cb_len130, 0},
	{"k_cb_len131", "p908.pcap", construct_k_cb_len131, 0},
	{"k_cb_len132", "p909.pcap", construct_k_cb_len132, 0},
	{"k_cb_len133", "p910.pcap", construct_k_cb_len133, 0},
	{"k_cb_len134", "p911.pcap", construct_k_cb_len134, 0},
	{"k_cb_len135", "p912.pcap", construct_k_cb_len135, 0},
	{"k_cb_len136", "p913.pcap", construct_k_cb_len136, 0},
	{"k_cb_len137", "p914.pcap", construct_k_cb_len137, 0},
	{"k_cb_len138", "p915.pcap", construct_k_cb_len138, 0},
	{"k_cb_len139", "p916.pcap", construct_k_cb_len139, 0},
	{"k_cb_len140", "p917.pcap", construct_k_cb_len140, 0},
	{"k_cb_len141", "p918.pcap", construct_k_cb_len141, 0},
	{"k_cb_len142", "p919.pcap", construct_k_cb_len142, 0},
	{"k_cb_len143", "p920.pcap", construct_k_cb_len143, 0},
	{"k_cb_len144", "p921.pcap", construct_k_cb_len144, 0},
	{"k_cb_len145", "p922.pcap", construct_k_cb_len145, 0},
	{"k_cb_len146", "p923.pcap", construct_k_cb_len146, 0},
	{"k_cb_len147", "p924.pcap", construct_k_cb_len147, 0},
	{"k_cb_len148", "p925.pcap", construct_k_cb_len148, 0},
	{"k_cb_len149", "p926.pcap", construct_k_cb_len149, 0},
	{"k_cb_len150", "p927.pcap", construct_k_cb_len150, 0},
	{"k_cb_len151", "p928.pcap", construct_k_cb_len151, 0},
	{"k_cb_len152", "p929.pcap", construct_k_cb_len152, 0},
	{"k_cb_len153", "p930.pcap", construct_k_cb_len153, 0},
	{"k_cb_len154", "p931.pcap", construct_k_cb_len154, 0},
	{"k_cb_len155", "p932.pcap", construct_k_cb_len155, 0},
	{"k_cb_len156", "p933.pcap", construct_k_cb_len156, 0},
	{"k_cb_len157", "p934.pcap", construct_k_cb_len157, 0},
	{"k_cb_len158", "p935.pcap", construct_k_cb_len158, 0},
	{"k_cb_len159", "p936.pcap", construct_k_cb_len159, 0},
	{"k_cb_len160", "p937.pcap", construct_k_cb_len160, 0},
	{"k_cb_len161", "p938.pcap", construct_k_cb_len161, 0},
	{"k_cb_len162", "p939.pcap", construct_k_cb_len162, 0},
	{"k_cb_len163", "p940.pcap", construct_k_cb_len163, 0},
	{"k_cb_len164", "p941.pcap", construct_k_cb_len164, 0},
	{"k_cb_len165", "p942.pcap", construct_k_cb_len165, 0},
	{"k_cb_len166", "p943.pcap", construct_k_cb_len166, 0},
	{"k_cb_len167", "p944.pcap", construct_k_cb_len167, 0},
	{"k_cb_len168", "p945.pcap", construct_k_cb_len168, 0},
	{"k_cb_len169", "p946.pcap", construct_k_cb_len169, 0},
	{"k_cb_len170", "p947.pcap", construct_k_cb_len170, 0},
	{"k_cb_len171", "p948.pcap", construct_k_cb_len171, 0},
	{"k_cb_len172", "p949.pcap", construct_k_cb_len172, 0},
	{"k_cb_len173", "p950.pcap", construct_k_cb_len173, 0},
	{"k_cb_len174", "p951.pcap", construct_k_cb_len174, 0},
	{"k_cb_len175", "p952.pcap", construct_k_cb_len175, 0},
	{"k_cb_len176", "p953.pcap", construct_k_cb_len176, 0},
	{"k_cb_len177", "p954.pcap", construct_k_cb_len177, 0},
	{"k_cb_len178", "p955.pcap", construct_k_cb_len178, 0},
	{"k_cb_len179", "p956.pcap", construct_k_cb_len179, 0},
	{"k_cb_len180", "p957.pcap", construct_k_cb_len180, 0},
	{"k_cb_len181", "p958.pcap", construct_k_cb_len181, 0},
	{"k_cb_len182", "p959.pcap", construct_k_cb_len182, 0},
	{"k_cb_len183", "p960.pcap", construct_k_cb_len183, 0},
	{"k_cb_len184", "p961.pcap", construct_k_cb_len184, 0},
	{"k_cb_len185", "p962.pcap", construct_k_cb_len185, 0},
	{"k_cb_len186", "p963.pcap", construct_k_cb_len186, 0},
	{"k_cb_len187", "p964.pcap", construct_k_cb_len187, 0},
	{"k_cb_len188", "p965.pcap", construct_k_cb_len188, 0},
	{"k_cb_len189", "p966.pcap", construct_k_cb_len189, 0},
	{"k_cb_len190", "p967.pcap", construct_k_cb_len190, 0},
	{"k_cb_len191", "p968.pcap", construct_k_cb_len191, 0},
	{"k_cb_len192", "p969.pcap", construct_k_cb_len192, 0},
	{"k_cb_len193", "p970.pcap", construct_k_cb_len193, 0},
	{"k_cb_len194", "p971.pcap", construct_k_cb_len194, 0},
	{"k_cb_len195", "p972.pcap", construct_k_cb_len195, 0},
	{"k_cb_len196", "p973.pcap", construct_k_cb_len196, 0},
	{"k_cb_len197", "p974.pcap", construct_k_cb_len197, 0},
	{"k_cb_len198", "p975.pcap", construct_k_cb_len198, 0},
	{"k_cb_len199", "p976.pcap", construct_k_cb_len199, 0},
	{"k_cb_len200", "p977.pcap", construct_k_cb_len200, 0},
	{"k_cb_len201", "p978.pcap", construct_k_cb_len201, 0},
	{"k_cb_len202", "p979.pcap", construct_k_cb_len202, 0},
	{"k_cb_len203", "p980.pcap", construct_k_cb_len203, 0},
	{"k_cb_len204", "p981.pcap", construct_k_cb_len204, 0},
	{"k_cb_len205", "p982.pcap", construct_k_cb_len205, 0},
	{"k_cb_len206", "p983.pcap", construct_k_cb_len206, 0},
	{"k_cb_len207", "p984.pcap", construct_k_cb_len207, 0},
	{"k_cb_len208", "p985.pcap", construct_k_cb_len208, 0},
	{"k_cb_len209", "p986.pcap", construct_k_cb_len209, 0},
	{"k_cb_len210", "p987.pcap", construct_k_cb_len210, 0},
	{"k_cb_len211", "p988.pcap", construct_k_cb_len211, 0},
	{"k_cb_len212", "p989.pcap", construct_k_cb_len212, 0},
	{"k_cb_len213", "p990.pcap", construct_k_cb_len213, 0},
	{"k_cb_len214", "p991.pcap", construct_k_cb_len214, 0},
	{"k_cb_len215", "p992.pcap", construct_k_cb_len215, 0},
	{"k_cb_len216", "p993.pcap", construct_k_cb_len216, 0},
	{"k_cb_len217", "p994.pcap", construct_k_cb_len217, 0},
	{"k_cb_len218", "p995.pcap", construct_k_cb_len218, 0},
	{"k_cb_len219", "p996.pcap", construct_k_cb_len219, 0},
	{"k_cb_len220", "p997.pcap", construct_k_cb_len220, 0},
	{"k_cb_len221", "p998.pcap", construct_k_cb_len221, 0},
	{"k_cb_len222", "p999.pcap", construct_k_cb_len222, 0},
	{"k_cb_len223", "p1000.pcap", construct_k_cb_len223, 0},
	{"k_cb_len224", "p1001.pcap", construct_k_cb_len224, 0},
	{"k_cb_len225", "p1002.pcap", construct_k_cb_len225, 0},
	{"k_cb_len226", "p1003.pcap", construct_k_cb_len226, 0},
	{"k_cb_len227", "p1004.pcap", construct_k_cb_len227, 0},
	{"k_cb_len228", "p1005.pcap", construct_k_cb_len228, 0},
	{"k_cb_len229", "p1006.pcap", construct_k_cb_len229, 0},
	{"k_cb_len230", "p1007.pcap", construct_k_cb_len230, 0},
	{"k_cb_len231", "p1008.pcap", construct_k_cb_len231, 0},
	{"k_cb_len232", "p1009.pcap", construct_k_cb_len232, 0},
	{"k_cb_len233", "p1010.pcap", construct_k_cb_len233, 0},
	{"k_cb_len234", "p1011.pcap", construct_k_cb_len234, 0},
	{"k_cb_len235", "p1012.pcap", construct_k_cb_len235, 0},
	{"k_cb_len236", "p1013.pcap", construct_k_cb_len236, 0},
	{"k_cb_len237", "p1014.pcap", construct_k_cb_len237, 0},
	{"k_cb_len238", "p1015.pcap", construct_k_cb_len238, 0},
	{"k_cb_len239", "p1016.pcap", construct_k_cb_len239, 0},
	{"k_cb_len240", "p1017.pcap", construct_k_cb_len240, 0},
	{"k_cb_len241", "p1018.pcap", construct_k_cb_len241, 0},
	{"k_cb_len242", "p1019.pcap", construct_k_cb_len242, 0},
	{"k_cb_len243", "p1020.pcap", construct_k_cb_len243, 0},
	{"k_cb_len244", "p1021.pcap", construct_k_cb_len244, 0},
	{"k_cb_len245", "p1022.pcap", construct_k_cb_len245, 0},
	{"k_cb_len246", "p1023.pcap", construct_k_cb_len246, 0},
	{"k_cb_len247", "p1024.pcap", construct_k_cb_len247, 0},
	{"k_cb_len248", "p1025.pcap", construct_k_cb_len248, 0},
	{"k_cb_len249", "p1026.pcap", construct_k_cb_len249, 0},
	{"k_cb_len250", "p1027.pcap", construct_k_cb_len250, 0},
	{"k_cb_len251", "p1028.pcap", construct_k_cb_len251, 0},
	{"k_cb_len252", "p1029.pcap", construct_k_cb_len252, 0},
	{"k_cb_len253", "p1030.pcap", construct_k_cb_len253, 0},
	{"k_cb_len254", "p1031.pcap", construct_k_cb_len254, 0},
	{"k_cb_len255", "p1032.pcap", construct_k_cb_len255, 0},
	{"k_tlv_with_channel_util", "p1033.pcap", construct_k_tlv_with_channel_util, 0},

	{"k_tlv_station_count_pow2_0", "p1034.pcap",  construct_k_tlv_station_count_pow2_0, 0},
	{"k_tlv_station_count_pow2_1", "p1035.pcap",  construct_k_tlv_station_count_pow2_1, 0},
	{"k_tlv_station_count_pow2_2", "p1036.pcap",  construct_k_tlv_station_count_pow2_2, 0},
	{"k_tlv_station_count_pow2_3", "p1037.pcap",  construct_k_tlv_station_count_pow2_3, 0},
	{"k_tlv_station_count_pow2_4", "p1038.pcap",  construct_k_tlv_station_count_pow2_4, 0},
	{"k_tlv_station_count_pow2_5", "p1039.pcap",  construct_k_tlv_station_count_pow2_5, 0},
	{"k_tlv_station_count_pow2_6", "p1040.pcap",  construct_k_tlv_station_count_pow2_6, 0},
	{"k_tlv_station_count_pow2_7", "p1041.pcap",  construct_k_tlv_station_count_pow2_7, 0},
	{"k_tlv_station_count_pow2_8", "p1042.pcap",  construct_k_tlv_station_count_pow2_8, 0},
	{"k_tlv_station_count_pow2_9", "p1043.pcap",  construct_k_tlv_station_count_pow2_9, 0},
	{"k_tlv_station_count_pow2_10", "p1044.pcap",  construct_k_tlv_station_count_pow2_10, 0},
	{"k_tlv_station_count_pow2_11", "p1045.pcap",  construct_k_tlv_station_count_pow2_11, 0},
	{"k_tlv_station_count_pow2_12", "p1046.pcap",  construct_k_tlv_station_count_pow2_12, 0},
	{"k_tlv_station_count_pow2_13", "p1047.pcap",  construct_k_tlv_station_count_pow2_13, 0},
	{"k_tlv_station_count_pow2_14", "p1048.pcap",  construct_k_tlv_station_count_pow2_14, 0},
	{"k_tlv_station_count_pow2_15", "p1049.pcap",  construct_k_tlv_station_count_pow2_15, 0},
	{"k_tlv_station_count_pow2_16", "p1050.pcap",  construct_k_tlv_station_count_pow2_16, 0},

	{"k_tlv_full_final", "p1051.pcap", construct_k_tlv_full_final, 0},
	
	{NULL, NULL, NULL, 0}
};

#endif
