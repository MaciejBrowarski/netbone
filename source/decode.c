#include "common-client.h"

char key_code[6][8] = {
        {0xf7, 0x67, 0x4d, 0x21, 0xab, 0xcd, 0x3e, 0x4e},
        {0x8b, 0x43, 0xcf, 0xe5, 0x11, 0x87, 0xa1, 0x2b},
        {0x55, 0xe2, 0xef, 0xc1, 0x72, 0xab, 0x3c, 0x3f},
        {0x31, 0x88, 0xf3, 0x3d, 0xab, 0xde, 0xb9, 0xff},
        {0xb6, 0x83, 0xcb, 0x45, 0x18, 0xc5, 0x59, 0x4f},
        {0x54, 0xdd, 0x39, 0x7d, 0x2e, 0x66, 0xd3, 0xbb}
};

/*
 * internal function for code
 * IN:
 * str - ptr to buffer
 * size - size of buffer
 * key - which key to use
 * len - len of crypt key
 * OUT:
 * none - str variable has crypted data
 */
void code_k(char *str, int32_t size, int8_t key, int8_t len)
{
    int8_t j = 0;
  //  int8_t j_start = offset_key % len;
    int32_t i;
    // WLOG_NB("Key %d len %d\n", key, len);
    for (i = 0; i < size; i++) {
        /*
         * how long is they secure key
         */
        j = i % len;
//                printf("i %d j %d %d code with %x\n", i, j, str[i], key_code[key][j]);
        str[i] ^= key_code[key][j];
    }
}

void code_decode(char *str, int32_t size)
{	
//	WLOG_NB_TRACE("size %d\n", size);
	return code(str, size);
}

void code_encode(char *str, int32_t size)
{
	if (UNLIKE(debug_code_encode)) {
        	// WLOG_NB_TRACE("size %d offset %d\n", size, offset);
	 	WLOG_NB("size %d\n", size);
	}
        return code(str, size);
}

/*
 * hash str via keys
 * IN:
 * str - ptr to buffer
 * size - size of buffer
 */
void code(char *str, int32_t size)
{
     /*
      * choose key depend on size
      * currently we have 5 keys
      */
//	WLOG_NB("size %d offset %d\n", size, offset);
//        int8_t k = size % 5;  
     int8_t k = 2;   
     code_k(str, size, k, 8);
     code_k(str, size, 5 - k, 5);
}
/*
 * calculate CRC for buffer
 * in:
 * *p - ptr to buffer
 * n - size of buffer
 * out:
 * n - crc number (0 - error)
 */
uint32_t calc_crc (char *p, uint32_t size)
{
	uint32_t a = 0;
	uint32_t s = 0;	
	for (a = 0; a < size; a++) {
		s ^= (0x000000ff & p[a]);

	}
	if (s == 0) s = 1;
	 if (UNLIKE(debug_calc_crc)) {
		WLOG_NB("for size %d CRC is %x\n", size, s);
	}
	return s;
}
/*
 * check CRC for data
 * in:
 * crc - CRC code to check
 * *p - pointer to data
 * n - size of data
 *
 * out:
 * 0 - bad
 * 1 - good
 */

int check_crc (uint32_t crc, char *p, uint32_t size)
{
	uint32_t r = calc_crc(p, size);
	/* calc need to return number, not 0 */
	if ((r) && (crc == r)) return 1; 
	WLOG_NB("not equal CRC: from packet is %u we calculate as %u\n", crc, r); 
	// DUMP_BUF_RAW(p, size);
        return 0;
}

