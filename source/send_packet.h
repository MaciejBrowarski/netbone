/*
 * NAME: sent_packet
 * SYNOPSIS:
 * function send packet
 * first compres head
 * add after head buffer
 * and sent whole packet to cad
 * IN:
 * 1 - ptr to head
 * 2 - ptr to data
 * 3 - size of data
 * 4 - socket from which we should send data
 * 5 - cad struct where we should send data
 * OUT:
 * >0 - sent bytes
 *
 * -1 error in compress
 * -2 header after compress exeed 255 bytes or whole packet exceed BUF (size of network packet)
 *
 */
int32_t send_packet(char *, char *, uint32_t, int , struct sockaddr_in);

