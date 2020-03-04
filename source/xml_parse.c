/*
 * common library for clients
 *
 * Version: 4.5
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
 * 4.4 - 2015 May - separate xml_parse
 * 4.5 - 2016 July - add crc check to xml_parse (for xml_parse_buf - TCP - this needs to be checked after get all packets with data)
 *
 * Copyright by BROWARSKI
 */
#include "common-client.h"
// #define DEBUG_XML_PARSE

/*
 * NAME: head parse function
 * DESCRIPTION:
 * function which parse raw data received from socket
 *
 * USED BY:
 * datad.c: tcp_server
 * datad.c: main_loop (UDP server)
 * common-client.c: send_request (client)
 *
 * IN:
 * *str - pointer to UDP packet
 * *request - pointer to request structure, which this function will fill
 * n - size of UDP packet
 * out:
 * 1 - good (request struct should be filled correct)
 * 0 - not valid XML header (short head, can't uncompress header)
 */

/*
 * parameters to find:
 * c - CRC number
 * r - command Request
 * s - seek Start
 * e - seek End
 * v - Version
 * u - user permission
 * o - owner
 * n - name
 * p - part
 * i - ID packet	
 *
 */
uint16_t xml_parse(char *strh, struct comm *request, uint32_t n)
{
    uint16_t ret = xml_parse_buf(strh, request, n, 0, 0);
	if (net_crc) {
                /*
                 * CRC set but check_crc return false, mean data are bad
                 */
                if ((request->size) && (! check_crc (request->crc, request->buf, request->size))) {
                        WLOG_NB("bad CRC: for %s crc %u size: %d\n", request->command, request->crc, request->size);
			request->good = 0;
                        return 0;
                }
        }
	return ret;
}
/*
 * same as above with dedicated data buffer (mainly for TCP) 
 * if data buffer not provided function will alloc memory for data
 *
 * USED BY: get_object
 */
uint16_t xml_parse_buf(char *strh, struct comm *request, uint32_t n, char *buf, int32_t buf_size)
{
    int16_t astart, astop;
    uint8_t stop;
    char str[BUF_HEAD_R];
    uLongf strl = 0;
    int c;

    memset(str, 0, BUF_HEAD_R);
    memset(request, 0, sizeof(struct comm));
    request->good = 0;

    if (code_trans) {
        code_encode(strh, n);
    }

    strl = BUF_HEAD_R;
    stop = (uint8_t)strh[0];

    if (stop < 5) {
        return 0;
    }
	if (UNLIKE(debug_xml_parse)) {
    WLOG_NB_TRACE( "stop %d wielosc pakietu %d\n", stop, n);
	}
    /*
     * uncompress header
     * str - where put decompress data
     * strl - size uncompressed data
     * strh - ptr to header data
     * stop - where header ends (strh[0])
     */
    c = uncompress((Bytef *)str,&strl,(Bytef *)strh + 1, stop);
    if (c != Z_OK) {
	if (UNLIKE(debug_xml_parse)) {
        	if (c == Z_BUF_ERROR)  WLOG_NB("uncompress buffer error\n");
        	if (c == Z_MEM_ERROR) WLOG_NB("uncompress memory\n");
        	if (c == Z_DATA_ERROR) {
			WLOG_NB("uncompress input data stream error\n");
			DUMP_BUF_RAW(strh + 1, stop);
		}
	}
        return 0;
    }
	if (UNLIKE(debug_xml_parse)) {
        WLOG_NB( "head >%s< size of head %ld\n", str, strl);    
	}
	/*
	 * we check CRC here, even size is 0 
	 * becuase header with TCP can have size 0 even data will be provided in other packets
 	 */
	if (net_crc) {
		/*
		 * is CRC in header
		 */
		uint32_t crc = 0;
		astart = strfind(str, "<c");
		astop = strfind(str, "/c>");

        if ((astart >= 0) && (astop > 0)) {
            astart += 2;
            sscanf (str + astart, "%x", &crc);
        }
        if (UNLIKE(debug_xml_parse)) {
			WLOG_NB( "CRC from packet is %x\n", crc);
        }
        request->crc = crc;
    }

	/*
     * Data SIZE in this packet
     */
    request->size = n - stop - 1;

    if (request->size > 0) {
        /*
         * have we dedicated buffer for data
         * mainly used by TCP protocol
         */
	
        if ((buf)&& (buf_size)) {
            if (request->size < buf_size) {
                /*
                 * then copy data which is after the header
                 */
		// sprintf(log_buf_debug, "%s:%d: %p %p %d\n", __FILE__, __LINE__,buf, strh + stop + 1, request->size );
                memcpy(buf, strh + stop + 1, request->size);
            } else request->size = 0;
        } else {
	/*
	 * create data in structure
	 */
            if (request->size <= BUF_DATA) {
                request->buf = malloc(request->size);

                if (!request->buf) {
			WLOG_NB("malloc error\n");
			return 0;
		}
                /*
                 * copy data from packet to request structure
                 */
                memcpy(request->buf, strh + stop + 1,request->size);
            } else request->size = 0;
        }
    } else
        request->size = 0;
    /*
     * seek request
     */
    astart = strfind(str, "<r");
    astop = strfind(str, "/r>");
    #ifdef DEBUG_XML_PARSE
    WLOG_NB("command astart %d astop %d\n", astart, astop);
    #endif

    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
	// sprintf(log_buf_debug, "%s:%d: %p %p %d\n", __FILE__, __LINE__,request->command, str + astart, astop - astart);
        memcpy(request->command, str + astart, astop - astart);
	 if (UNLIKE(debug_xml_parse)) {
    WLOG_NB( "command %s\n", request->command);
        }
    }
    /*
     * seek START
     */
    astart = strfind(str, "<s");
    astop = strfind(str, "/s>");

    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
        request->start = atol(str + astart);
    } else
        request->start = 0;
#ifdef DEBUG_XML_PARSE
        WLOG_NB("request->start %d\n", request->start);        
#endif
    /*
     * seek END
     */
    astart = strfind(str, "<e");
    astop = strfind(str, "/e>");
    #ifdef DEBUG_XML_PARSE
    WLOG_NB("seek stop astart %d stop %d\n", astart, astop);
    
    #endif
    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
        request->stop = atol(str + astart);
    } else
        request->stop = 0;

    /*
     * version
     */
    request->t_sec = 0;
    request->t_msec = 0;
    astart = strfind(str, "<v");
    astop = strfind(str, "/v>");

    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
        sscanf (str + astart, "%u.%u", &request->t_sec, &request->t_msec);
#ifdef DEBUG_XML_PARSE
        WLOG_NB("version astart %d stop %d %u %u\n", astart, astop, request->t_sec, request->t_msec);
        
#endif
    }
#ifdef IDS_FOR_FILE
    /*
     * permission
     */
    request->mode = 0;
    astart = strfind(str, "<u");
    astop = strfind(str, "/u>");
    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
        sscanf (str + astart, "%u", &request->mode);
#ifdef DEBUG_XML_PARSE
        WLOG_NB("permission astart %d stop %d %u\n", astart, astop, request->mode);
        
#endif
    }
    /*
     * owner and group
     * default are -1 (not allow)
     */
    request->owner = -1;
    request->group = -1;
    astart = strfind(str, "<o");
    astop = strfind(str, "/o>");
    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
        sscanf (str + astart, "%u %u", &request->owner, &request->group);

    }
#endif
    /*
     * NAME
     */
    astart = strfind(str, "<n");
    astop = strfind(str, "/n>");
    memset(request->name, 0, NAME_SIZE);
#ifdef DEBUG_XML_PARSE
        WLOG_NB("name astart %d stop %d\n", astart, astop);        
#endif
    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
	
	// sprintf(log_buf_debug, "%s:%d: %p %p %d\n", __FILE__, __LINE__,request->name, str + astart, astop - astart);

        if (astop - astart < NAME_SIZE)
            memcpy(request->name, str + astart, astop - astart);
         else
            memcpy(request->name, str + astart, NAME_SIZE);
    }
        /*
         * PARTS
         */
    astart = strfind(str, "<p");
    astop = strfind(str, "/p>");

    request->part_1 = 0;
    request->part_2 = 0;

    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
        sscanf (str + astart, "%u %u", &request->part_1, &request->part_2);
    }
#ifdef DEBUG_XML_PARSE
    WLOG_NB( "part astart %d stop %d p1 %d p2 %d\n", astart, astop, request->part_1, request->part_2);
#endif
        /*
         * identyfikator
         */
     astart = strfind(str, "<i");
    astop = strfind(str, "/i>");
#ifdef DEBUG_XML_PARSE
        WLOG_NB("id astart %d stop %d\n", astart, astop);        
#endif
        request->id = 0;

    if ((astart >= 0) && (astop > 0)) {
        astart += 2;
        request->id = atol(str + astart);
    }
     /*
      * struktura request jest w pelni zapelniona
      * to jest ok, gdy buf != 0 oznacza to ze xml_parse_buf ma tylko nagłówek (to dla TCP)
      */
    if (! buf) request->good = 1;

   #ifdef DEBUG_XML_PARSE
        WLOG("size after all %d\n", request->size);        
#endif
    return 1;
}

