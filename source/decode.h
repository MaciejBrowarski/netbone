#include <stdint.h>

#ifndef DECODE_H
#define DECODE_H 1
/*
 * hash str via keys
 * IN:
 * str - ptr to buffer
 * size - size of buffer
 * offset
 * offset_key
 */
void code_decode(char *, int32_t);
void code_encode(char *, int32_t);

void code(char *, int32_t);

int check_crc (uint32_t, char *, uint32_t);
uint32_t calc_crc (char *, uint32_t);
#endif
