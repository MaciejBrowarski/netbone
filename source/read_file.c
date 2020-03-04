/*
 * read file - read configuration file
 *
 * Version: 4.2
 *
 * 4.3 - 2015 February - add network_size for sendd as parameter from file
 *
 * Copyright by BROWARSKI
 */
#include "common-client.h"
// #define DEBUG_READ_FILE

uint8_t debug;
uint8_t debug_calc_crc;
uint8_t debug_client_request_get;
uint8_t debug_client_request;
uint8_t debug_code_encode;
uint8_t debug_get_list_meta_data;
uint8_t debug_main_loop;
uint8_t debug_memory;
uint8_t debug_request_get;
uint8_t debug_request_list;
uint8_t debug_get_list_meta_data;
uint8_t debug_checker;
uint8_t debug_get_object;
uint8_t debug_checker_buffer;
uint8_t debug_request_put;
uint8_t debug_sendd_name_version;
uint8_t debug_send_packet;
uint8_t debug_tcp_server;
uint8_t debug_xml_parse;

uint8_t debug_send_request;
#if defined SMS
/*
 *  * SMS Gateway address
 *   */
char *hostname_gw;
/*
 *  * port on which service listen
 *   */
int32_t port_gw;

/*
 * is ssl connection ?
 * 0 - normal socket
 * 1 - ssl
 */
int ssl_req = 0;

/*
 * convert text to one long string (replace special characters to %<hex number> e.g. <space> to %20)
 */
int convert_txt = 0;
/*
 * PEM key
 */
char *pem_key;

char *url;

char *confirm;
#endif

#ifndef LOG_DIR_DEF
#ifdef WIN32
char log_dir[PATH_MAX] = "c:\\agent\\log";
#else
char log_dir[PATH_MAX] = "/var/tmp";
#endif
#define LOG_DIR_DEF 1
#endif


/*
 * function name: read_file
 * synopsis: read parameters from configuration file
 * paramters are written to global variables
 *
 * agruments:
 *  in:
 *      str - name of configuration file
 *      buf - array where IP should be written
 *	dynamic - 0 - first read, 1 next read file in launch (some parameters can't be changed after first set)
 *  out:
 *
 */
int read_file(char *nazwa, char **buf, uint16_t dynamic)
{
	struct stat plik;
	char *cfg, *ptr;
	int f;
	unsigned int size,a, nl;
#if defined NETBONE || defined AGENT
        uint16_t ser_num = 0;
#endif
#if defined NETBONE
        uint16_t i;
#endif
	#ifdef DEBUG_READ_FILE
	WLOG_NB("try to open file %s\n", nazwa);
	#endif
	f = open(nazwa, O_RDONLY);
        if (f < 0) {
            WLOG("file %s failed: %s\n", nazwa, strerror(errno));
            return 0;
        }
	fstat(f, &plik);
	size = plik.st_size;
        #ifdef DEBUG_READ_FILE
	// only printf as some WLOG paramters are not set yet
	printf( "wielkosc pliku %d\n", size);
        #endif
	cfg = (char *)malloc(size);
	if (!cfg) {
		printf("Blad malloc\n");
		return 0;
	}
	size = read(f, cfg, plik.st_size);
	close (f);

        if (size != plik.st_size) {
		WLOG("read from cfg file failed");
		return 0;
	}
        /*
         * change all end of line to 0
         * this is needed for function which think 0 is end of line
         */
	for(a = 0;a < size;a++) {
		if (cfg[a] == 10) cfg[a] = 0;
	}
	nl = 0;
        rpath[0] = '\0';
	/*
	 * initial variable for first run
	 */
#if defined NETBONE
	if (! dynamic) {
        	buf[ser_num] = 0;
	} else {
		/*
		 * clear old IP addresses for second read file execute
	 	 */
		for (i = 0; i < ser_num; i++) {
			if (buf[i]) free(buf[i]);
			buf[i] = 0;
		}
	}
#endif
	/*
	 * if this isn't set, always be off
	 */
	debug = 0;
	debug_calc_crc = 0;
    debug_client_request_get = 0;
    debug_client_request = 0;
	debug_code_encode = 0;
    debug_get_list_meta_data = 0;
	debug_main_loop = 0;
    debug_memory = 0;
	debug_request_get = 0;
	debug_request_list = 0;
	debug_get_list_meta_data = 0;
	debug_checker_buffer = 0;
	debug_get_object = 0;
	debug_checker = 0;
	debug_sendd_name_version = 0;
    debug_send_packet = 0;
    debug_tcp_server = 0;
	debug_xml_parse = 0;
	debug_send_request = 0;

	bpath_load = 0;

	for (a = 0; a < size;a++) {
        uint16_t s;
		ptr = cfg + a;
		if (nl) {
            /*
             * if read char is 0 mean that new line is reached
             */
			if (ptr[0] == 0) {
				nl = 0;
			}
			continue;
		}
        if (! ptr[0]) continue;
        /*
         * if first char in line isn't hash
         * than check is this one of the option
         */

        if (ptr[0] != '#') {
            #ifdef DEBUG_READ_FILE
            printf ( "line to parse %s\n", ptr);
            #endif

#if defined NETBONE
            if ((! strncmp(ptr, "listen=", 7)) && (! dynamic)) {
                start_ip = inet_addr(ptr + 7);
                if (start_ip == -1) {
                    printf("Error listen on %s back to 0.0.0.0\n", ptr + 7);
                    start_ip = INADDR_ANY;
                }
                #ifdef DEBUG_READ_FILE
                printf ("START_IP to %s\n", ptr + 7);
                #endif
            }
#endif

#if defined NETBONE || defined AGENT
            if ((! strncmp(ptr, "port=", 5)) && (! dynamic)) {
                start_port = atol(ptr+5);
            }
#endif

#if defined SMS
            if ((! strncmp(ptr, "port=", 5)) && (! dynamic)) {
                port_gw = atol(ptr+5);
            }
#endif


#if defined NETBONE
			/*
			 * network packet size
			 * currenlty only for sendd
			 */
			if (! strncmp(ptr, "net_size=", 9)) {
                net_size = atol(ptr + 9);
			    if (net_size > BUF) {
				    WLOG_NB("net_size %d bigger than %d, lower net_size to %d\n", net_size, BUF, BUF);
				    net_size = BUF;
			    }
            }
#endif
#if defined NETBONE || defined SMS	
            if ((! strncmp(ptr, "timeout=", 8)) && (! dynamic)) {
                timeout_client = atol(ptr + 8);
            }
#endif
#if defined NETBONE
            if ((! strncmp(ptr, "buffer_flush=", 13)) && (! dynamic)) {
                buffer_flush = atol(ptr + 13);                  
            }
#endif

#if defined NETBONE
			/*
			 * how many object we can manage
			 */
            if ((! strncmp(ptr,"objects=", 8)) && (! dynamic)) {
                ids_max = atol(ptr + 8);
            }
#endif

#if defined NETBONE
			/*
			 * backup path
			 */
            if ((! strncmp(ptr, "bpath=", 6)) && (! dynamic)) {
                memcpy(bpath, ptr + 6, strlen(ptr + 6));
            }
#endif

#if defined NETBONE

			/*
			 * load from bpath on request
			 */
		    if ((! strncmp(ptr, "bpath_load=", 11)) && (! dynamic)) {
                bpath_load = 1;
             }
#endif

#if defined NETBONE || defined AGENT

            if ((! strncmp(ptr, "name=", 5)) && (! dynamic)) {
                s = strlen(ptr + 5);
                if (s) {
			        /* when re-read cfg file */
					if (ids_name) free(ids_name);
							
                        ids_name = calloc(s + 1, sizeof(char));
                        if (ids_name)
                        memcpy(ids_name, ptr + 5, s);
                    }
            }
#endif

#if defined NETBONE || defined AGENT
			/*
			 * dynamic yes
			 * folder with logs
			 */
            if (! strncmp(ptr, "log_path=", 9)) {
                s = strlen(ptr + 9);
                /*
                 * not WLOG, becasue we recreate log handle
                 */
			    #ifndef AGENT
                pthread_mutex_lock(&wlog_lock);
				#endif
                if (fidlog > -1) {
                    /*
                     * not WLOG becasue we recreate log handle
                     * so, deadlock can occure
                     */
                    sprintf (log_buf, "creating new log file. End this one\n");
                    wlog(log_buf, 0, __func__);
                             
                    close(fidlog);
                    fidlog = -1;
                }
                memset (log_dir, 0, PATH_MAX);
                memcpy(log_dir, ptr + 9, s);
				#ifndef AGENT
                pthread_mutex_unlock(&wlog_lock);
                #endif
						
           }
#endif
#if defined AGENT
           /*
            * for agent
            * name of server in CMIT page
            */
            if (! strncmp(ptr, "agent_name=", 11)) {
                s = strlen(ptr + 11);
                memset (agent_name, 0, NAME_SIZE);
                memcpy(agent_name, ptr + 11, s);
            }
#endif

#if defined AGENT
			if (! strncmp(ptr, "monitor=", 8)) {
                s = strlen(ptr + 8);
                memset (monitor_id, 0, MONITOR_ID_SIZE);
                memcpy(monitor_id, ptr + 8, s);
            }
#endif

#if defined AGENT

            /*
             * for agent, where script is
             */
            if ((! strncmp(ptr, "script=", 7)) && (! dynamic)) {
                memcpy(bpath, ptr + 7, strlen(ptr + 7));
            }
#endif
#if defined NETBONE
			/*
			 * folder with pid files
			 */ 
            if ((! strncmp(ptr, "pid_path=", 9)) && (! dynamic)) {
                s = strlen(ptr + 9);
                memset (pid_file, 0, PATH_MAX);
                memcpy(pid_file, ptr + 9, s);
            }
#endif

#if defined NETBONE
            /*
             * for client, time cache for IDS ask
             */
            if (! strncmp(ptr, "cache=", 6)) {                        
                cache_valid = atol(ptr + 6);
                      
            }
#endif
#if defined NETBONE
		    if (! strncmp(ptr, "crc=on", 6)) {
                net_crc = 1;
            }
#endif
#if defined NETBONE

			/*
			 * for server, switch immediate to active
			 */
    		if ((! strncmp(ptr, "ids_mode=on", 11)) || (! strncmp(ptr, "ids_mode=1", 10)) || (! strncmp(ptr, "idsmode=1", 9)))  {
                ids_mode = 1;
            }
#endif
#if defined NETBONE

            if (! strncmp(ptr, "code_trans=off", 14)) {
                code_trans = 0;
            }
#endif
#if defined NETBONE
		    if ((! strncmp(ptr, "debug=on", 8)) || (! strncmp(ptr, "debug=1", 7)))  {
			    debug = 1;
            }
            if ((debug) && (! strncmp(ptr, "debug=calc_crc", 6 + 8))) {
			    debug_calc_crc = 1;
		    }
            if ((debug) && (! strncmp(ptr, "debug=memory", 6 + 6))) {
                debug_memory = 1;
            }

            if ((debug) && (! strncmp(ptr, "debug=get_list_meta_data", 6 + 18))) {
                debug_get_list_meta_data = 1;
            }
            if ((debug) && (! strncmp(ptr, "debug=client_request_get", 6 + 18))) {
                debug_client_request_get = 1;
            }
            if ((debug) && (! strncmp(ptr, "debug=client_request", 6 + 14))) {
                debug_client_request = 1;
            }

		    if ((debug) && (! strncmp(ptr, "debug=xml_parse", 6 + 9))) {
                debug_xml_parse = 1;
            }
            if ((debug) && (! strncmp(ptr, "debug=request_put", 6 + 11))) {
                debug_request_put = 1;
            }
            if ((debug) && (! strncmp(ptr, "debug=tcp_server", 6 + 10))) {
                debug_tcp_server = 1;
            }

		    if ((debug) && (! strncmp(ptr, "debug=request_get", 6 + 11))) { 
                debug_request_get = 1;
            }

		    if ((debug) && (! strncmp(ptr, "debug=sendd_name_version", 6 + 24))) {
                debug_sendd_name_version = 1;
            }
            if ((debug) && (! strncmp(ptr, "debug=send_packet", 6 + 11))) {
                debug_send_packet = 1;
            }
		if ((debug) && (! strncmp(ptr, "debug=send_request", 6 + 12))) {
                debug_send_request = 1;
            }
		    if ((debug) && (! strncmp(ptr, "debug=code_encode", 6 + 11))) {
			    debug_code_encode = 1;
            }

		    if ((debug) && (! strncmp(ptr, "debug=checker_func", 6 + 12))) {
                debug_checker = 1;
            }
		    if ((debug) && (! strncmp(ptr, "debug=checker_buffer", 6 + 14))) {
                debug_checker_buffer = 1;
            }
		    if ((debug) && (! strncmp(ptr, "debug=get_object", 6 + 10))) {
                debug_get_object = 1;
            }
		    if ((debug) && (! strncmp(ptr, "debug=request_list", 6 + 12))) {
                debug_request_list = 1;
            }
		    if ((debug) && (! strncmp(ptr, "debug=get_list_meta_data", 6 + 18))) {
                debug_get_list_meta_data = 1;
            }
		    if ((debug) && (! strncmp(ptr, "debug=main_loop", 6 + 9))) {
                debug_main_loop = 1;
            }
#endif

#if defined NETBONE

			/*
			 * rpath - relative path in IDS, used by fuse
			 * as we don't like to present whole IDS to FUSE, we can use rpath to show only branch
			 */
            if ((!strncmp(ptr,"rpath=",6)) && (! dynamic)) {
                s = strlen(ptr + 6);
                /*
                 * rpath should be ended without trailer slash /
                 * check, if rpath ends with /
                 * if yes, s--
                 */
                for (;ptr[6 + s] == 47;s--)
                    memcpy(rpath, ptr + 6, s);
                }
#endif
#if defined NETBONE || defined AGENT

			/*
			 * IP address for other IDSes
			 */
             if (! strncmp(ptr, "ip=", 3)) {
                char *buf1;
                s = strlen(ptr + 3);
                buf1 = calloc(s + 1, sizeof(char));
                if (!buf1) {
				    WLOG("malloc error\n");
				    return 0;
			    }

                memcpy(buf1, ptr + 3, s);
                        
			    ser_num = load_ip(buf, ser_num, buf1);
            }
#endif
#if defined SMS
            /*
             * for SMS is connection to server require SSL connection
             */
            if (!strncmp(ptr,"ssl=1",5)) {
                ssl_req = 1;
            }
#endif

#if defined SMS
            /*
             * for SMS is connection to server require SSL connection
             */
            if (!strncmp(ptr,"convert_txt=1",13)) {
                convert_txt = 1;
            }
#endif


#if defined SMS
            if (!strncmp(ptr,"hostname=", 9))  {
                s = strlen(ptr + 9);
                if (s) {
                    hostname_gw = calloc(s + 1, sizeof(char));
                    if (hostname_gw)
                    memcpy(hostname_gw, ptr + 9, s);
                }
            }
#endif


#if defined SMS
            if (!strncmp(ptr,"confirm=", 8))  {
                s = strlen(ptr + 8);
                if (s) {
                    confirm = calloc(s + 1, sizeof(char));
                    if (confirm) memcpy(confirm, ptr + 8, s);
                }
            }
#endif
#if defined SMS
            if (!strncmp(ptr,"pem_key=", 8))  {
                s = strlen(ptr + 8);
                if (s) {
                    pem_key = calloc(s + 1, sizeof(char));
                    if (pem_key) memcpy(pem_key, ptr + 8, s);
                }
            }
#endif

#if defined SMS
            if (!strncmp(ptr,"url=", 4))  {
                s = strlen(ptr + 4);
                if (s) {
                    url = calloc(s + 1, sizeof(char));
                    if (url) memcpy(url, ptr + 4, s);
                }
            }
#endif

		} /* if (! '#') */
		nl = 1;
	}
	free(cfg);
	return 1;
}
