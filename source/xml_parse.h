/*
 * NAME: head parse function
 * IN:
 * *str - pointer to UDP packet
 * *request - pointer to request structure, which we should fill
 * n - size of UDP packet
 * out:
 * 1 - good (request struct should be filled correct)
 * 0 - not valid XML header
 */
uint16_t xml_parse_buf(char *, struct comm *, uint32_t, char *, int32_t);
uint16_t xml_parse(char *, struct comm *, uint32_t );

