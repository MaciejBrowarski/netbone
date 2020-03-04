/* 
 * IDS - Independent Data Storage
 * 
 * File:   datad.c
 * Author: BROWARSKI
 *
 * Version: 4.11
 *
 * History:
 * Created on 29 may 2009, 22:01
 * 4.10 - tcp_server as separate obj file
 * 4.11 2016 September - add lisv
 */

#include "tcp_server.h"
#include "common.h"

/*
 * function run as pthread
 * shouldn't be exit
 */
void tcp_server()
{
    uint32_t port = start_port;
    int32_t serverSocket; /* socket descriptors  */
    struct sockaddr_in sad; /* structure to hold server's address  */
    struct sockaddr_in null_ad;
    /*
     * create separate log file for this thread
     * as log for this thread should go to separate file
     * so, WLOG logging to main log file, file
     * to logb goes to seperate file (please use it for this function)
     */
    char logb[4096];
    int16_t flog = wlog_create_log();
    struct comm *request;

    serverSocket = socket(PF_INET, SOCK_STREAM, 0); /* CREATE SOCKET */
    if (serverSocket < 0) blad("socket creation failed\n");

    /*
     * listen for request
     */
    memset((char *) & sad, 0, sizeof (sad)); /* clear sockaddr structure   */
    memset((char *) & null_ad, 0, sizeof (null_ad)); /* clear sockaddr structure   */

    sad.sin_family = AF_INET; /* set family to Internet     */
    sad.sin_addr.s_addr = start_ip; /* set the local IP address   */
    sad.sin_port = htons((u_short) port); /* set the port number        */
    /*
     * loop for bind to port
     */
    for (;;) {
        int r;
	    r = bind(serverSocket, (struct sockaddr *) & sad, sizeof (sad));
        if (r  == -1) {
		    sprintf(logb, "bind failed: %s\n", strerror(errno));
		    wlog_fid(logb, 0, flog, __func__);
		    if (errno == 98) {
                sprintf(logb,"can't bind to %d TCP port, sleep 1s.\n", port);
			    wlog_fid(logb, 0, flog, __func__);

    			sleep(1); 
	    		continue;
		    }
		    blad("exiting ..\n");
        }
        break;
    } /* for (;;) */
    for (;;) {
	    if (listen(serverSocket, 50) < 0 ) {
	        sprintf(logb, "listen error: %s\n", strerror(errno));
	        wlog_fid(logb, 0, flog, __func__);
	        sleep (5);
        } else {
            break;
        }
    }

    request = calloc(1, sizeof(struct comm));

    if (!request) blad ("main: calloc request error\n");

    if (UNLIKE(debug_tcp_server)) {
        sprintf(logb,"tcp_server: start listen on port: %d and desc: %d\n", port, serverSocket);
        wlog_fid(logb, 1, flog, __func__);
    }
     /*
      * loop for accept
      */
    while(1) {
        int32_t cliSocket, i, n;
        socklen_t	alen;
        uint32_t r;
        char buff[BUF];
	    struct sockaddr_in cad;
	    alen = sizeof (struct sockaddr);
        fd_set rs;
        struct timeval czas;
        int ret;
        char jest = 0;
         /*
         * clear received buffer
         */
        memset(buff, 0, BUF);
        if ((cliSocket = accept(serverSocket, (struct sockaddr *) & cad, &alen)) < 0) {
            sprintf(logb, "accept error %s\n", strerror(errno));
		    wlog_fid(logb, 1, flog, __func__);
		    continue;
        }

        FD_ZERO(&rs);
        FD_SET(cliSocket, &rs);
        czas.tv_sec = 1;
        czas.tv_usec = 0;

        ret = select (cliSocket + 1, &rs, NULL, NULL, &czas);
        if (ret > 0) {
            for(i = 0;i < 3;i++) {
                n = read(cliSocket, buff, BUF);
                
                if (n > 0) goto next_go;

                /* EAGAIN - give chance to get read */
                if (errno == 11) continue;
                /* for other errors just break */
                sprintf(logb, "read error %s\n", strerror(errno));
                break;
            }
        } else if (ret == 0) {
            sprintf(logb, "read timeout\n");
        } else {
            sprintf(logb, "internal select error: %s\n", strerror(errno));
        }
        /*
         * this is because continue should be for while (1)
         * not for for() loop
         */        
        wlog_fid(logb, 1, flog, __func__);
        close (cliSocket);
        continue;
/* 
 * jump from above when n > 0
 */    
 next_go:
        memset(request, 0, sizeof(struct comm));
        /*
         * check is packet has valid header
         */
        r = xml_parse(buff, request, n);
      	if ((! r)  || (request->good < 1)) {
             sprintf(logb, "xml_parse error: %s\n", strerror(errno));        
             wlog_fid(logb, 1, flog, __func__);
             close (cliSocket);
             continue;
	    }
     
	     jest = 0;
         if ((!strcasecmp(request->command, "LIST")) || (!strcasecmp(request->command, "LISV"))) {
             char ret[BUF_HEAD_R];
              char head[] = "<r%s/r><i%d/i>";

             char *list = 0; 
              uint32_t size = 0, n;
              /* 
               * if we have only first element, don't make any list
               */
              if (ptr_data->next) {
                  if (!strcasecmp(request->command, "LISV")) { 
                        list = get_list_meta_data(ptr_data, request->name, 0, 1);
			sprintf(ret, head,"LISV - OK", request->id);
                   } else {
                        list = get_list_meta_data(ptr_data, request->name, 0, 0);
			sprintf(ret, head,"LIST - OK", request->id);
		   }
                if (list) {
                    size = strlen(list);
                }
              }
              /*
               * create header
               */

              n = send_packet(ret, list, size , cliSocket, null_ad);

              jest = 1;
                if (list) free(list);

        }
	     if (!strcasecmp(request->command, "GET")) { 
	         char ret[BUF_HEAD_R];
	         struct data *s;
	
		     #ifdef IDS_FOR_FILE
		     char head[] = "<r%s/r><n%s/n><i%d/i><v%d.%d/v><s0/s><e%d/e><u%d/u><o%d %d/o>";
		     #else
		     char head[] = "<r%s/r><n%s/n><i%d/i><v%d.%d/v><s0/s><e%d/e>";
		     #endif
		     s = search_name(request->name);
		
		     if ((!s) || (s->deleted) || (s->need_check)) {
				#ifdef IDS_FOR_FILE
		        sprintf(ret, head,"GET - Not found", s->name,  request->id, s->t_sec,s->t_msec,  0, s->mode, s->owner, s->group);
		        #else
		        sprintf(ret, head,"GET - Not found", s->name,  request->id, s->t_sec,s->t_msec, 0);
		        #endif	
		        n = send_packet(ret, 0,0, cliSocket, null_ad);
                goto tcp_server_out;

		     }
             if (UNLIKE(debug_tcp_server)) {
                sprintf(logb,"GET %s SIZE %d FROM %s\n", s->name, s->size, inet_ntoa(cad.sin_addr));
                wlog_fid(logb, 1, flog, __func__);
             }
		
		     if (s->size) {
		        /*
		         * create header
		         */
		        #ifdef IDS_FOR_FILE
		        sprintf(ret, head,"GET - OK", s->name,  request->id, s->t_sec,s->t_msec,  s->size, s->mode, s->owner, s->group);
		        #else
		        sprintf(ret, head,"GET - OK", s->name,  request->id, s->t_sec,s->t_msec, s->size);
		        #endif

		        n = send_packet(ret, s->buf, s->size , cliSocket, null_ad);
		     } else {
		        #ifdef IDS_FOR_FILE
		        sprintf(ret, head,"GET - OK", s->name,  request->id, s->t_sec,s->t_msec,  0, s->mode, s->owner, s->group);
		        #else
		        sprintf(ret, head,"GET - OK", s->name,  request->id, s->t_sec,s->t_msec, 0);
		        #endif
		        /*
		         * just send ok with 0 size buffer
		         */
		        n = send_packet(ret, 0, 0 , cliSocket, null_ad);
		     } /* end of size > 0 */
		     jest = 1;
	     } /* end of GET */
	
	     if (!jest) {
	        char buff_d[BUF_HEAD_R];
	        sprintf(buff_d, "<r>ERROR: unknown request</r><i%d/i>",  request->id);
	        n = send_packet(buff_d, 0, 0 , cliSocket, null_ad);
	     }
tcp_server_out:
         close (cliSocket);

    } /* while */
}

