/*
 * common library for clients
 *
 * Version: 5.0
 *
 * History:
 * 0.1.0 - 2010 October - created
 * 0.1.1 - 2010 November - add to read_file 2 parameters: name and listen to accept on dedicated ip address
 *                         correct time (set to 1s) in get_list for response.
 * 0.1.2 - 2010 November - add WLOG macro for logging with (un)lock, add lock and unlock to monitor mutex (un)locks
 * 0.1.3 - 2010 December - create separate file with function body
 * 0.1.4 - 2011 August - rewrite client_request (create client_request_get function)
 * 0.2.0 - 2013 January - add TCP protcol to send_packet function
 * 0.2.1 - 2013 July - add back_trace procedure
 * 0.2.2 - 2013 October - add debug=on in parameter file, fix cache issue
 * 3.0 - 2013 December - add buffer data cache
 * 3.1 - 2014 February - dynamic increase  and do compress on buffer data cache
 * 3.2 - 2014 September - add code function
 * 4.0 - 2014 November - use code_* function in UDP transmission
 * 4.1 - 2014 December - dump_buf fuction to dump buffers into file for debug
 * 4.2 - 2015 January - add debug variables
 * 4.3 - 2015 February - add network_size for sendd as parameter from file
 * 4.4 - 2015 May - new file
 * 5.0 2015 September - send_packet.c as seperate file
 *
 * Copyright by BROWARSKI
 */
#include "common-client.h"
//#define DEBUG_SEND_PACKET 1
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
 * 5 - cad struct where we should send data (can_family = NULL for TCP connection)
 * OUT:
 * >0 - sent bytes
 *
 * -1 error in compress
 * -2 header after compress exeed 255 bytes or whole packet exceed BUF (size of network packet)
 * -3 - error in send a data
 * -4 - out of memory
 */
int32_t send_packet(char *head, char *data, uint32_t data_s, int Clifd, struct sockaddr_in cad)
{
    int32_t ret;
    uLongf buf_s;
    int c;
    /*
     * buffer for whole packet
     */
    char *buf;

	uint32_t  buf_size = BUF;
    /*
     * for TCP change bufor size for whole data
     * (UDSP can send only one packet, so BUF is enough)
     */
	if (cad.sin_family == AF_UNSPEC) {
		buf_size = DATA_MAX;
	}

    buf = malloc(buf_size);
    if (! buf) {
          WLOG_NB("unable to alloc of %d memory for temp buffer\n", buf_size);
        return -4;
    }
    if (debug_memory) {
        WLOG_NB("MALLOC: %d in %p\n", buf_size, buf);
    }
    memset(buf, 0, buf_size);

    /*
	 * add CRC to header 
	 * this should be place in header, as this is static buffer which should have HEAD_BUF size
     */
	if ((net_crc) && (data) && (data_s > 0))    {
            uint32_t crc;
            crc = calc_crc(data, data_s);
            sprintf(head, "%s<c%x/c>", head, crc);
    }
    
    buf_s = BUF_HEAD;
	/*
	 * compress the header
	*/
    c = compress2 ((Bytef *)buf + 1,  &buf_s, (Bytef *)head, strlen(head), 9);
    if (c != Z_OK) {
        if (c == Z_BUF_ERROR)  WLOG_NB("compress buffer error\n");
        if (c == Z_MEM_ERROR) WLOG_NB("compress memory\n");
        if (c == Z_DATA_ERROR) WLOG_NB("compress input data stream error\n");
         ret = -1;
         goto out;
    }
    #ifdef DEBUG_SEND_PACKET
    WLOG_NB("after compress, before copy data size of head %ld\n", buf_s);
    #endif
	 /*
      * first char in packet
      * is size of compressed header
	  * check, first, is this higher than 255 (if yes, then stop proccessing)
      */

	if (buf_s > 255) { 
        ret = -2; 
        goto out; 
    }

    buf[0] = (uint8_t) buf_s;
	/*
	 * TCP connection
	 */
 	if (cad.sin_family == AF_UNSPEC) {
		 /*
          * first send a header
          */
		int32_t i = 0, j = 0;
        uint32_t data_t = 0;
		/*
		 * code header
		 */
        if (data_s) memcpy (buf + buf_s + 1, data, data_s);
        /*
         * sum of data+head size
         */
        data_t = buf_s + 1 + data_s;

        if (code_trans) {
            code_decode (buf, data_t);
        }

		for (;i < data_t;i += j) {
            int32_t size;
			if (data_t - i > 65534) 
				size = 65535;
			else 
				size = data_t - i;

			j = write(Clifd, &buf[i], size);
            if (UNLIKE(debug_send_packet)) {
              WLOG_NB("tcp: send %d of size %d\n", j, size);
            } 
			if (j < 1) {	
				WLOG_NB("TCP write (size: %d) error: %s\n", size, strerror(errno));
				ret = -3;
                goto out;
            }
		}
        
		ret = i;

	} else {
			
		/*
		 * UDP connection
		 */
		/*
		 * check is header and data are fit in one UDP packet
		 */
		if ((buf_s + data_s + 1) > BUF) {
            ret = -2;
            goto out;
        }
        /*
         * copy data after head in local head buffer
         */	
	    if (data_s) memcpy (buf + buf_s + 1, data, data_s);
		/*
	     * code it
	     */
	
        if (code_trans) {
		    code_decode (buf, buf_s + data_s + 1);
        }
	
		#ifdef DEBUG_SEND_PACKET
	    WLOG_NB ("before send data\n");
	    #endif
		ret = sendto(Clifd, buf, buf_s + data_s + 1, 0, (struct sockaddr *) & cad, sizeof(cad));
	}
out:	
    if (UNLIKE(debug_send_packet)) {   
        WLOG_NB("sent %d bytes (%s) to %s\n", ret, head, inet_ntoa(cad.sin_addr));
    }
    if (buf) {
        free (buf);
        if (debug_memory) {
            WLOG_NB("FREE: %p\n", buf);
        }

    }
    return ret;
}

