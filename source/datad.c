/* 
 * IDS - Independent Data Storage
 * 
 * File:   datad.c
 * Author: BROWARSKI
 *
 * Version: 4.14
 *
 * History:
 * Created on 29 may 2009, 22:01
 *
 * 0.0.1 2009 Jun - created
 * 0.0.2 2009 Sep
 * 0.0.3 2009 Nov
 * 0.0.5 2010 Jan - add compression header in packet
 * 0.0.6 2010 Feb   - daemonize
 *                  - pong unknown packet (for UDP port monitoring)
 *                  - add new function: TRUNZ - TRUNC + create file
 *                  - compresion packets between IDSes
 * 0.0.7 2010  Mar - lput_rec - load data from disk to memory using bpath parameter
 *                  - lget_rec - write data from memory to disk using bpath parameter
 *                  - add var_comp variable (if compress packet exceed max value) var_comp_packet is decressed
 *                  - add name_pid variable where pid are stored
 * 0.0.8 2010 Jul   - review request_put - each command has separate operation on delete object flag
 *                  - add request_check to check on all loaded object on demand
 * 0.0.9 2010 Jun   - add size parameter to send between IDSes, if storage object is smaller, than download bigger
 * 0.1.0 2010 Sep   - delete files from bpath when flag in object is set to 1
 * 0.1.1 2010 Nov   - fix checker to don't accept data from unknown servers (which are not in config file)
 * 0.1.2 2010 Nov   - add SIGHUP for reload option: IP and WLOG
 * 0.1.3 2011 Mar   - add DATAD_VERSION variable to / statistic
 * 0.1.3 2011 April - get_list in checker with time out (thread)
 * 0.1.4 2011 May   - fix request_list with .
 *                      float compresion ratio
 * 0.1.5 2011 June  - add COMPRession function
 * 0.1.6 2011 August - add trune (create object and put there data, if object exist don't do action)
 * 0.1.7 2011 September - add QUIT command, add mhost (modify host) into info command
 * 0.1.8 2011 October - add more statistic for objects (count and memory for all deleted statuses)
 * 0.1.9 2011 October - request for list and rlist on fork
 * 0.2.0 2011 November - shared memory for meta data, send_name_version is seperate process now
 * 0.2.1 2011 December - mutex lock in request_put for metadata
 * 0.2.2 2012 January - partial in request_put (not separate function)
 * 0.2.3 2012 February - delete in request_put (not separete function)
 * 0.2.4 2012 April - request_put: move data (instead of copy) from request to object in 6,7,9 request
 * 0.2.5 2012 May - replace pthread_creat by fork in checker function to get data from external IDS to prevent memory leak
 * 0.2.6 2013 January - accept / for sendd as timestamp for whole packet  in checker
 * 0.2.7 2013 January - create tcp_server for accept TCP connection (big GET)
 * 0.2.8 2013 January - add passive/active mode, in passive mode UDP port is open and add request are accepted only
 * 0.2.9 2013 February - add TOUCH function, to change version for object
 * 0.2.10 2013 July - fix atol() procedure to prevent memory corruption - potencial
 * 2.11 2013 September - add syslog for critical issue
 * 2.12 2013 November - create separate wlog for tcp_server and add it to reload_cfg to also restart tcp_server
 * 3.0 2014 February - add BUFFER command
 * 3.1 2014 March - fix TCP server
 * 3.1.1 2014 June - fix TCP server prevent read function lock
 * 3.2 2014 June - all signal function with WLOG_NB logging method
 * 3.2.1 2014 November - add active on configuration parameter (to start IDS directly in active mode) - new func: void ids_active_on ()
 * 4.0 2014 November - encode incoming packets for checker
 * 4.1 2015 January - rewrite debug code to use dediated debug_* variables
 * 4.2 2015 April - checker_get_object - more verbose
 * 4.3 2016 January - load from bpath on request from cfg file - new parameter bpath_load=
 * 4.4 2016 July - more verbose in checker_get_object
 * 4.5 2016 August - checker_get_object add dedicated buffer to get whole file, only when data are good then copy it to share buffer for checker
 * 4.6 2016 August - add dedicated buffer for meta data in checker_get_object
 * 4.7 2016 August - remove syslog, tcp_server not fork(), because we are unable to copy data to fork process (we shouldn't relay on fork data address)
 * 4.8 2016 August - make launch_sendd as pthread which guard sendd fork process
 * 4.9 2016 Sep - add LGET (put file to local disk by mmap)
 * 4.10 2016 Sep - tcp-server as separate file (add LIST to tcp_server)
 * 4.11 2016 Sep - add  listv and ristv for UDP&TCP
 * 4.12 2016 Sep - add function which, at start get all objects from other IDS by listv command
 * 4.13 2016 Sep - checker_get_object rename to get_object and moved to common-client.c file
 * 4.14 2017 Dec - request_put, only phtread_lock_timed is in use
 */
//#define DEBUG_BIND_PORT
// #define DEBUG_MAIN
//#define DEBUG_MULTIPLY
//#define DEBUG_FINISH_IP
//#define DEBUG_REGISTER1
#define DEBUG_RELOAD_CFG
//#define DEBUG_READ_FILE
#define DEBUG_READ_FILE_DATA
// #define DEBUG_REQUEST_GET
// #define DEBUG_REQUEST_LIST
// #define DEBUG_REQUEST_PUT
//#define DEBUG_QSORT_R
//#define DEBUG_CLIENT_REGISTER
//#define DEBUG_QSORT_CMP
//#define CLEAR_DELETED_DEBUG
//#define DEBUG_SEARCH_NAME
//#define DEBUG_STRFIND
//#define DEBUG_UNREGISTER_ALL_IP
// #define DEBUG_CHECKER
//#define DEBUG_CHECKER_GET_OBJECT
#define DEBUG_LPUT_REC

#include "common.h"
#include "tcp_server.h"

/*
 * prototypes
 */
int client_register();
void lget_rec();
void unregister_all_ip();
uint16_t request_list(struct comm *, uint32_t , uint8_t, int8_t );
void launch_sendd();

/*
 * GLOBAL VARIABLES
 */
int checker_sockfd;


pthread_t checker_pt;

pthread_mutex_t request_put_lock;

/*
 * for thread
 * 0 -client register
 * 1 - checker
 * 2 - tcp server
 * 3 - write data to bpath on demond (USR1 signal)
 * 4 - checker other IDS to switch from passive into active mode after gather all objects
 * 5 - sendd guard
 */
pthread_t  thread[6];
/*
 * to comunicate with Sendd
 */
uint32_t sendd_pid = 0;
/*
 * global pointer to argv pointer
 * required for launch_sendd (as pthread, we can only pass only one parameters)
 * so I choose global variable instead of structure of two parameters (which also needs to be defined globally)
 * main never end, so this global_argv will always point to proper data
 */
char **global_argv;

struct request_list_st {
	struct comm *request;
	uint32_t serverSocket;
	uint8_t sf;
};
/*
 * FUNCTIONS
*/

/*
 * function count, how many objects are not deleted and checked
 */
inline uint32_t good_objects()
{
    uint32_t good = 0;
    if (ptr_data->next) {
        struct data *s  = PTR(ptr_data->next);

        for (;;) {
            if ((s) && (s->need_check == 0) && (s->deleted == 0)) good++;
            if (s->next)
                s = PTR(s->next);
            else
                break;
        }
    }
    return good;
}


/*
 * function mark object as deleted
 * after some time clear_deleted should be running
 * des - pointer
 * sec, msec when object is deleled (if 0 current time is taken )
 */
void delete_data(struct data *des, uint32_t sec, uint32_t msec)
{
    // TODO: lock object

    if ((sec == 0) && (msec == 0)) {
        struct timeval cz;
        gettimeofday(&cz, NULL);

        des->t_sec = cz.tv_sec;
        des->t_msec = cz.tv_usec;
    } else {
        des->t_sec = sec;
        des->t_msec = msec;
    }
    WLOG("delete_data: %s\n", des->name);
    des->deleted = 1;

    if ((des->buf) && (des->size))
        free (des->buf);

    des->buf = 0;
    des->size = 0;
    /*
     * delete file also from disk
     */
/*
	* comment: currently not used
    if (strlen(bpath)) {
#ifdef IDS_FOR_FILE
        if (!(S_ISDIR(des->mode))) {
#endif
            char file_name[PATH_MAX];
            sprintf (file_name, "%s%s", bpath, des->name);
            if (unlink(file_name)) {
                WLOG_NB( "unable to delete %s with error %s\n", file_name,strerror(errno));
            }
#ifdef IDS_FOR_FILE
        }
#endif
    } 
*/
 
}

/*
 * function return data, when using GET request
 * IN:
 * 1 - ptr to request structure
 * 2 - form output (0 - wszystko - GET, 1 - tylko naglowek - HEAD)
 * 3 - socket handle
 * OUT:
 * wskaznik do odpowiedzi
 */
uint16_t request_get(struct comm *request, int form, uint32_t serverSocket)
{   
    struct data *s;
    int n = 0;
    char ret[BUF_HEAD_R];
#ifdef IDS_FOR_FILE
    char head[] = "<r%s/r><n%s/n><p%d %d/p><i%d/i><v%d.%d/v><s%d/s><e%d/e><u%d/u><o%d %d/o>";
#else
    char head[] = "<r%s/r><n%s/n><p%d %d/p><i%d/i><v%d.%d/v><s%d/s><e%d/e>";
#endif
    memset(ret, 0, BUF_HEAD_R);
    s = search_name(request->name);

	if (UNLIKE(debug_request_get)) {
    		WLOG_NB("wyszukiwanie danych dla %s form %d\n", request->name, form);
    		if (s)  WLOG_NB("znaleziono %s\n", s->name);
	}

    if ((!s) || (s->deleted) || (s->need_check)) {
        if (form == 0)
            sprintf(ret, "<rGET - name not found/r><n%s/n><i%d/i>", request->name, request->id);
        if (form == 1)
            sprintf(ret, "<rINFO - name not found/r><n%s/n><i%d/i>", request->name, request->id);
        if (form == 2)
            sprintf(ret, "<rTAIL - name not found/r><n%s/n><i%d/i>", request->name,request->id);
     
        n = send_packet(ret, 0,0, serverSocket, request->client);

        if (UNLIKE(debug_request_get)) {
            WLOG_NB ("nie znaleziono\n");
        }
        return 0;
    }
	/* TODO: need test
    if ((request->t_sec) && ((request->t_sec != s->t_sec) || (request->t_msec != s->t_msec))) {
        if (form == 0)
            sprintf(ret, "<rGET - version mismatch/r><n%s/n><i%d/i>", request->name, request->id);
        if (form == 1)
            sprintf(ret, "<rINFO - version mismatch/r><n%s/n><i%d/i>", request->name, request->id);
        if (form == 2)
            sprintf(ret, "<rTAIL - version mismatch/r><n%s/n><i%d/i>", request->name,request->id);
	if (UNLIKE(debug_request_get)) {
		WLOG_NB("version missmatch for %s we have %d/%d ask for %d/%d\n", request->name, request->t_sec, request->t_msec, s->t_sec, s->t_msec);
	}
        n = send_packet(ret, 0,0, serverSocket, request->client);
	return 0;
    } */

    /*
     * if we ask about statistics, put in buffer 
     */
    if ((form == 0) && (request->name[0] == 47) && (strlen(request->name) == 1)) {
        uint16_t o, i;
        struct client *s;
        struct reg_ser *t;
        time_t czas = time(0);        
        /*
         * 4 mean status of objects
         * 0 - good
         * 1 - deleted
         * 2 - partial
         * 3 - not know - error/ not checked
         */
        uint32_t mem[4];
        uint32_t obj[4];

        for (o = 0;o < 4;o++)
            mem[o] = obj[o] = 0;

        if (ptr_data->next) {
            struct data *p = PTR(ptr_data->next);
            for (;;) {
                uint8_t d = p->deleted;

		if (UNLIKE(debug_request_get)) WLOG_NB("name %s delete %d check %d\n", p->name, d, p->need_check);

                if ((p->need_check) || (p->name[0] != '/') || (! strlen(p->name))) {
                    WLOG_NB("del: %d check %d\n", d, p->need_check);
                    if (p) {
                        WLOG_NB("name %s size %d\n",  p->name, p->size);
                    }
                    d = 3;
                }
                if (d > 3)
                    d = 3;
               
                mem[d] += p->size;
                obj[d]++;
           //     if (!(obj[0] % 50)) WLOG("request_get: good %d deleted %d partial %d for %s\n", obj[0], obj[1], obj[2], p->name);
                if (p->next)
                    p = PTR(p->next);
                else
                    break;
            }
        }
        for (o = 0;o < 4;o++)
            if (mem[o]) mem[o] /= 1024;
        /*
         * first stats: name, compile time, number of objects
         */

       sprintf(ptr_data->buf,"IDS name: %s (compile date: %s)\ncur_time: %d\n", ids_name, VERSION,  (uint32_t) czas);

       o = strlen(ptr_data->buf);
       sprintf(ptr_data->buf + o,"objects: %u/%u/%u/%u (mem: %d/%d/%d/%d kB)\n",obj[0], obj[1], obj[2], obj[3], mem[0], mem[1], mem[2], mem[3]);
                                        
       /*
        * to whom we send information
        */
       o = strlen(ptr_data->buf);
        sprintf(ptr_data->buf + o, "send data to (registered IDS): ");

       for (i = 0; i < MAX_IP;i++) {
           s = ptr_client + i;
           if (s->czas) {
                o = strlen(ptr_data->buf);
                sprintf(ptr_data->buf + o, "%s:%d ", inet_ntoa(s->client.sin_addr), ntohs(s->client.sin_port));
           }
       }
       /*
        * from whom we receive data
        */
       o = strlen(ptr_data->buf);
       sprintf(ptr_data->buf + o, "\nregistering to (from cfg file): ");
       for (t = ptr_check; t; t = t->next) {
           struct tm *cz;
           o = strlen(ptr_data->buf);
           cz = localtime(&t->last);
           sprintf(ptr_data->buf + o, "%s (%04d-%02d-%02d %02d:%02d:%02d) ", inet_ntoa(t->ip.sin_addr),
           cz->tm_year + 1900, cz->tm_mon + 1, cz->tm_mday, cz->tm_hour, cz->tm_min, cz->tm_sec);
       }
       o = strlen(ptr_data->buf);
       sprintf(ptr_data->buf + o, "\n\n");
        ptr_data->size = strlen(ptr_data->buf) + 1;
    }
    /*
     * form - czyli pelny GET, dziala tylko w active mode
     */     

    if ((form == 0) && (ids_mode)) {
        /*
         * a - begin of cping
         * b - end of coping
         */
        uint32_t a = 0;
        uint32_t b = s->size;
  
        /*
         * which:
         * p1 - part we start
         * p2 - part we stop
         */
        uint32_t p1 = 0, p2 = 0, p_max = (s->size + BUF_DATA) / BUF_DATA;
        /*
         * w b do jakiego indeksu mamy kopiowac dane         
         */
        // jezeli zadamy wiecej niz jest w buforze, b wskazuje na ostatni element w buforze
        if ((request->stop) && (request->stop < s->size)) b = request->stop;
        /*
         * ustawienie poczatku kopiowania danych        
         */
        if (request->start > 0) a = request->start;
        /*
         * jezeli start wiekszy od bufora ktory juz posiadamy, to zaczynamy czytac dane od poczatku
         * !!? A nie lepiej nie zwracac danych ?!!
         */
        if (a > s->size) a = 0;
        /*
         * oblczenie ile czesci trzeba bedzie wyslac
         * jezeli w zadaniu juz jakies czesci byly, to trzymajmy sie ich
         */
        if (request->part_1)  
            p1 = request->part_1;

        if (request->part_2) {
            p2 = request->part_2;
        } else {
            if ((a == 0) && (b == 0))
                p2 = 0;
            else
                p2 = ((b - a - 1) / BUF_DATA) + p1;
        }    
	/*
	 * check p1 or p2 is not bigger than size
	 */
         if (p1 > p_max) {
            sprintf(ret, "<rGET - p1 out of p_max %d/r><n%s/n><i%d/i>", p_max, request->name,request->id);
            n = send_packet(ret, 0,0, serverSocket, request->client);
            return 0;
         }
	if (p2 > p_max) {
            sprintf(ret, "<rGET - p1 out of p_max %d/r><n%s/n><i%d/i>", p_max, request->name,request->id);
            n = send_packet(ret, 0,0, serverSocket, request->client);
            return 0;
        }

        for (;(a + BUF_DATA) < b;a += BUF_DATA, p1++) {         
           #ifdef DEBUG_REQUEST_GET
            WLOG ("pakiet a %d b %d part1 %d part2 %d\n",a, b, p1, p2);
            #endif

#ifdef IDS_FOR_FILE
            sprintf(ret, head,"GET - OK", s->name, p1, p2, request->id, s->t_sec,s->t_msec,  a, BUF_DATA + a, s->mode, s->owner, s->group);
#else
            sprintf(ret, head,"GET - OK", s->name, p1, p2, request->id, s->t_sec,s->t_msec,  a, BUF_DATA + a);
#endif
            #ifdef DEBUG_REQUEST_GET
            WLOG("zawartosc naglowka %s\n", ret);
            #endif
            /*
            * wkopiowanie danych za naglowek
            */
            
            #ifdef DEBUG_REQUEST_GET
            WLOG( "z danymi\n");
            #endif
            /*
            * check if sendto proper send data !!!!
            */
            n = send_packet(ret, s->buf + a,BUF_DATA, serverSocket, request->client);
          if (n < 0) WLOG("send packet return %d with %s\n", n, ret);
            /*
             * clear buffer for next
             */
            memset(ret, 0, BUF_HEAD_R);
        }
        /*
         * last packet
         */
#ifdef IDS_FOR_FILE
        sprintf(ret, head,"GET - OK", s->name, p1, p2, request->id, s->t_sec,s->t_msec,  a, b, s->mode, s->owner, s->group);
#else
        sprintf(ret, head,"GET - OK", s->name, p1, p2, request->id, s->t_sec,s->t_msec,  a, b);
#endif
        #ifdef DEBUG_REQUEST_GET
        WLOG( "ostatni GET %s wysylamy %d bajtow\n", ret, b - a);
        #endif
        /*
         * check if sendto proper send data !!!!
         */
        
        n = send_packet(ret, s->buf + a,b - a, serverSocket, request->client);
        if (n < 0) WLOG("send packet return %d with %s\n", n, ret);
    }
    /*
     * If this INFO
     * object need exists and be correct
     * these are prerequiste to be here
     */
    if ((form == 1) && (ids_mode)) {

	// if ((!s->deleted)  && (!s->need_check)) {
          char mdata[BUF];
#ifdef IDS_FOR_FILE
        	sprintf(ret,head,"INFO - OK", s->name, 0, 0, request->id, s->t_sec,s->t_msec, 0, s->size, s->mode, s->owner, s->group);
#else
                sprintf(ret,head,"INFO - OK", s->name, 0, 0, request->id, s->t_sec,s->t_msec, 0, s->size);
#endif
 
        sprintf(mdata, "mhost=%s\n", inet_ntoa(s->modify_ip.sin_addr));

        n = send_packet(ret,mdata ,strlen(mdata) , serverSocket, request->client);
        if (n < 0) WLOG("request_get: send packet return %d with %s\n", n, ret);
        #ifdef DEBUG_REQUEST_GET
         WLOG( "INFO %s\n", ret);
        #endif
        // }
    }
    /*
     * TAIL
     */
    if ((form == 2) && (ids_mode)) {
        uint32_t u = 0;
        uint32_t w = 0; 

        if (s->size > BUF_DATA) { w = BUF_DATA; u = s->size - BUF_DATA; }
        else w = s->size;
#ifdef IDS_FOR_FILE
        sprintf(ret,head,"TAIL - OK", s->name, 0, 0, request->id, s->t_sec,s->t_msec, u, u + w, s->mode, s->owner, s->group);
#else
        sprintf(ret,head,"TAIL - OK", s->name, 0, 0, request->id, s->t_sec,s->t_msec, u, u + w);
#endif
        n = send_packet(ret,s->buf + u ,w , serverSocket, request->client);
        if (n < 0) WLOG("request_get: send packet return %d with %s\n", n, ret);
        #ifdef DEBUG_REQUEST_GET
         WLOG( "request_get: INFO %s\n", ret);        
        #endif
    } 
    /*
     * LGET
     */
    if ((form == 3) && (ids_mode)) {
        int f;
        void *target;
        int flags = O_RDWR | O_TRUNC | O_CREAT;

        if (!request->size) {
            sprintf(ret, "<rLGET - no file provided/r><n%s/n><i%d/i>", request->name,request->id);
            n = send_packet(ret, 0,0, serverSocket, request->client);
            return 0;
        }
        if (!s->size) {
            sprintf(ret, "<rLGET - empty object/r><n%s/n><i%d/i>", request->name,request->id);
            n = send_packet(ret, 0,0, serverSocket, request->client);
            return 0;
        }
        request->buf[request->size] = 0;
        f = open(request->buf, flags, 0755);

        if (f == -1) {
            WLOG_NB( "error open file with error: %s\n", strerror(errno) );
            return 0;        
        }

        if((target = mmap(0, s->size, PROT_WRITE, MAP_SHARED, f, 0)) == (void *) -1) {
            WLOG_NB("error mmap memory size %d with error :%s\n", s->size, strerror(errno) );
            close (f);
            return 0;
        }
        if (ftruncate(f, s->size)) {
            WLOG_NB("truncate file to %d size with error :%s\n", s->size, strerror(errno) );
            close (f);
            return 0;
        }
        /*
         * write new data
         */
        if (! memcpy(target, s->buf, s->size)) {
            WLOG_NB("memcpy error: %s\n", strerror(errno));
            close (f);
            return 0;
        }
        munmap(target, s->size);
        close (f);

#ifdef IDS_FOR_FILE
        sprintf(ret,head,"LGET - OK", s->name, 0, 0, request->id, s->t_sec,s->t_msec, 0, 0, s->mode, s->owner, s->group);
#else
        sprintf(ret,head,"LGET - OK", s->name, 0, 0, request->id, s->t_sec,s->t_msec, 0, 0);
#endif
        n = send_packet(ret,0,0 , serverSocket, request->client);

        if (n < 0) WLOG_NB("request_get: send packet return %d with %s\n", n, ret);
        #ifdef DEBUG_REQUEST_GET
         WLOG_NB( "request_get: LGET %s\n", ret);
        #endif
    }
    return 0;
};

/*
 * function list elements from data
 * in:
 * request - where
 * serverSocket - socket, where sent answer
 * sf - serach form, 0 - pattern search from left side (for directory) , 1 pattern search from right side (for files)
 */

uint16_t request_list(struct comm *request, uint32_t serverSocket, uint8_t sf, int8_t verbose)
{
    char buff_d[BUF];
    char *list = 0;
    uint32_t size = 0, n;            
    /*
     * if we have only first element, don't make any list
     */
    if (ptr_data->next) {
        list = get_list_meta_data(ptr_data, request->name, sf, verbose);
        if (list) {
            size = strlen(list);
        }
    }
    /*
     * przygotowanie naglowka
     */
    // #ifdef DEBUG_REQUEST_LIST
	if (UNLIKE(debug_request_list)) WLOG_NB("wyslanie do klienta %d ilosc danych\n", size);
   // #endif
    /*
     * zaalokowanie miejsca dla odpowiedzi
     */

    if (size) {
        uint32_t p1 = 0, p2 = 0, i = 0;
        /*
         * calculate, how many parts we need
         */    
        p2 = size / BUF_DATA;
        for(p1 = 0; p1 <= p2; p1++) {      

            memset(buff_d, 0 , BUF);
            if (p1 == p2)
                i = size - (p1 * BUF_DATA);
             else
                 /*
                  * not last packet, so put max data as we can
                  */
                i = BUF_DATA;

            sprintf(buff_d, "<rLIST - OK/r><i%d/i><s%d/s><e%d/e><p%d %d/p>", request->id, (p1 * BUF_DATA), i + (p1 * BUF_DATA), p1, p2);
       
            /*
            * jezeli jest to ostatni pakiet, to do ostatniego przegraj tyle danych ile zostalo
            */            
		if (UNLIKE(debug_request_list)) WLOG_NB("wyslanie %s wielkosc danych %d\n", buff_d, i);       
            n = send_packet(buff_d, list + (p1 * BUF_DATA), i , serverSocket, request->client);           

           if (UNLIKE(debug_request_list))	WLOG_NB( "DATA p1: %d p2: %d i %d\n",p1,p2, i);            
        }

        if (list) free(list);
    } else {        
        memset(buff_d, 0 , BUF);
        sprintf(buff_d, "<rLIST - OK/r><i%d/i><s%d/s><e%d/e><p%d %d/p>", request->id, 0, 0, 0, 0);
       
        n = send_packet(buff_d, 0, 0 , serverSocket, request->client);        
    }

    return 0;
};
/*
 * UNUSED FUNCTION
 */
uint16_t request_block(struct comm *request, uint32_t serverSocket)
{
    struct data *des;
    char *res;
  
    #ifdef DEBUG_BLOCK
        sprintf(log_buf,"Block:\n");
        wlog(log_buf);
    #endif
    /*
     * Szukanie w nazwach
     */
    des = search_name(request->name);
  /*  if (des) {
        if (des->readonly)

            res =  xml_return_i("<rBLOCK - FAILED/r>", request->id);
            des->readonly = 1;
    } else {*/
        /*
         * sprawdzenie w kolejce requestow
         */
    //}
    res = xml_return_i ("<rBLOCK - OK/r>", request->id);
   // n = sendto(serverSocket, res, strlen(res), 0, (struct sockaddr *) & request->client, sizeof(request->client));

    return 0;
};
/*
 * change data to be checked
 * function check object
 * manually check file, to be visible
 */
uint16_t request_check(struct comm *request, int32_t serverSocket)
{
    char buff_d[BUF_HEAD_R];
    int n;    

    uint16_t res = 1;
    sprintf(buff_d, "<rCHECK - FAILED/r><n%s/n><i%d/i>", request->name,request->id);
    if (ptr_data->next) {
        struct data *cur = PTR(ptr_data->next);

        for (;;) {
            cur->need_check = 0;
            if (!cur->next) break;
            else
                cur = PTR(cur->next);
        }
    }
    sprintf(buff_d, "<rCHECK - OK/r><n%s/n><i%d/i>", request->name,request->id);
    res = 0;

    WLOG( "request_check: dla %s oddaje %s\n",  request->name, buff_d);
    
    if (serverSocket != -1) {
            n = send_packet(buff_d, 0, 0 , serverSocket, request->client);
    }
    return res;

};

/*
 * DESC:
 * IN:
 * 1 - wskaznik na strukture zadania
 * 2 -  command:
 *      0 - PUT - zamiana danych
 *      1 - ADD - dopisanie danych
 *      2 - LPUT - dodanie danych z pliku
 *      3 - RENAME - zmiana nazwy pliku
 *      4 - LINK - skopiowanie danych
 *      5 - MODE - for chown and chmod,
 *      6 - TRUNCATE (object must exist),
 *      7 - TRUNZ (TRUNC + create file)
 *      8 - COMPR - compress - skopiowanie danych + kompresja
 *      9 - TRUNE - create object and put there data, if object exist, no action
 *      10 - PARTIAL - make object partial
 *      11 - DELETE - delete object
 *      12 - TOUCH - change date to current
 *
 * 3 - id socket - gdzie mamy wyslac odpowiedz (-1 internal without answer)
 * OUT:
 * 0 - data inserted
 * 1 - common error
 * 2 - error with timeslot (request to old or from future)
 * 3 - add data to partial object
 * 4 - internal problem with lock
 * 5 - wrong object name
 * 6 - object not found
 * 7 - name exist for command which create object
 */
char commands[][8] = {"PUT", "ADD", "LPUT", "RENAME", "LINK","MODE", "TRUNC", "TRUNZ","COMPR","TRUNE","PARTIAL", "DELETE", "TOUCH"};

uint16_t request_put(struct comm *request, uint16_t add, int32_t serverSocket)
{
    struct data *des = 0;
    int n, r;
	int ret_err = 1;	
    struct timespec abs_time;
    char buff_d[BUF_HEAD_R];
    uint32_t w = 0, dod_obj = 0;

    if (UNLIKE(debug_request_put)) {
        WLOG_NB( "func %d nazwa %s start %d stop %d size %d od %s:%d\n", add, request->name, request->start, request->stop, request->size, inet_ntoa(request->client.sin_addr),  ntohs(request->client.sin_port));
    }
   /*
    * if any write action for / (statistic)
    * then always sucesfull
    */
    if ((request->name[0] == '/') && (request->name[1] < 33)) goto out_good;
    /*
     * timed lock globally for function
     */

           
    clock_gettime(CLOCK_REALTIME, &abs_time);
    if (abs_time.tv_nsec >= 550000000) {
        abs_time.tv_nsec -= 450000000;
        abs_time.tv_sec++;
    } else
        abs_time.tv_nsec += 440000000;

    r = pthread_mutex_timedlock (&request_put_lock, &abs_time);

    if (r) {
        WLOG("TRYLOCK GLOBAL ERROR for %s func %d with %s\n", request->name, add, strerror(r));
        sprintf(buff_d, "<r%s - INTERNAL GLOCK ERROR/r><n%s/n><i%d/i>", request->command, request->name, request->id);
		ret_err = 4;
        goto out2;
    }
    if (UNLIKE(debug_request_put)) {
        WLOG_NB( "global locked\n");
    }
    /*
     * wyszukanie nazwy     
     */
    w = qsort_search(request->name);    

    n = qsort_cmp(qsort_data[w]->name, request->name);
    #ifdef DEBUG_REQUEST_PUT
     WLOG ("qsort_search dla %s oddalo %d qsort_cmp %d\n", request->name, w, n);
     #endif
    /*
    * jezeli nie ma nazwy to dodanie
    */
    if (n) {
        int32_t ui = 0;

    /*
     * name need to be atleast 2 chars length and start with /
     * this is for sure that requset name isn't smaller than '/' (statistic),
     * which need to be always first
     */
        if ((request->name[0] != '/') || (request->name[1] < 33)) {
            sprintf(buff_d, "<r%s - Name not in convention/r><n%s/n><i%d/i>", request->command, request->name, request->id);
            WLOG_NB("0 %d 1 %d %s\n", request->name[0], request->name[1], buff_d);
		ret_err = 5;
            goto out1;
        }
        /*
         * for MODE, COMP, TRUNCate, PARTIAL and DELETE name needs to exist
         */
        if ((add == 5) || (add == 6) || (add == 8) || (add == 10) || (add == 11)) {
            sprintf(buff_d, "<r%s - NAME NOT EXIST/r><n%s/n><i%d/i>", commands[add], request->name,request->id);
		ret_err = 6;
            goto out1;
        }
     
        #ifdef DEBUG_REQUEST_PUT
        WLOG("CREATE name >%s<\n", request->name);        
        #endif
        /*
         * zaalokowanie pamieci pod nazwe
         */      
  
        ui = get_free_data(request->name);
        /*
         * can't change data from 0 and less indexes
         */
        if (ui < 1) {
            sprintf(buff_d, "<r%s - INTERNAL GET_FREE_DATA ERROR/r><n%s/n><i%d/i>", request->command, request->name, request->id);
		ret_err = 4;
            goto out2;
        }
        des = PTR(ui);

        dod_obj = 1;              
        /*
         * Insert into qsort array after w index
         */
         #ifdef DEBUG_REQUEST_PUT
        WLOG_NB("des %p qsort_data %p w %d ui %d\n", des, qsort_data[w], w, ui);
        #endif
        /*
         * if we use place from or almost equal
         * pointer, then we need to search again new
         * near left pointer, if not then object will be not added
         * ( deleted next will be point to this object but deleted
         * is unbind from queue
         */
        if (des == qsort_data[w]) {
            qsort_refresh();
            w = qsort_search(request->name);
#ifdef DEBUG_REQUEST_PUT
            WLOG_NB("new w is %d\n", w);
#endif
        }

        if (qsort_data[w]->next) 
            des->next = qsort_data[w]->next;
         else
            des->next = 0;

        qsort_data[w]->next = ui;
        /*
         * refresh qsort array
         */            
        qsort_refresh();
    } else {
        /*
         * when name exists
         */
        des = qsort_data[w];
        /*
         * if request has version
         */
        if  (request->t_sec)  {
		if ((request->t_sec - 60) > time(0)) {
			ret_err = 2;
			 WLOG_NB("request for %s is from future %d\n", request->name, request->t_sec);
			sprintf(buff_d, "<r%s - FUTURE %d, NOT ACCEPT/r><n%s/n><i%d/i>", request->command, request->t_sec , request->name, request->id);
			 goto out1;
		}
                // version in reqeust is smaller than version in data
                if ((des->t_sec > request->t_sec) || ((des->t_sec == request->t_sec) && (des->t_msec > request->t_msec))) {
        	//    #ifdef DEBUG_REQUEST_PUT
            	WLOG_NB("request for %s older that data in memory\n", request->name);
            	// #endif
            	/*
             	* discard request
             	*/
            	sprintf(buff_d, "<r%s - REQUEST HAS OLD DATA/r><n%s/n><i%d/i>", request->command , request->name, request->id);
		ret_err = 2;
            	goto out1;
        	}
	}
        
        /*
         * Partial mean, someone mark this as partial object
         * to prevent break consisty of object we denied ADD to partial object
         */
        if ((des->deleted == 2) && (add == 1)) {
            WLOG_NB("can not add data to partial file %s\n",  des->name);
            sprintf(buff_d, "<rADD - PARTIAL OBJECT/r><n%s/n><i%d/i>", request->name, request->id);
		ret_err = 3;
            goto out1;
        }
        /*
         * if this is LINK and new name exist (not deleted), don't go later
         */
        if (des->deleted == 0) {
            if ((add == 4) && (add == 9)) {
                sprintf(buff_d, "<r%s - NAME EXIST/r><n%s/n><i%d/i>", commands[add], request->name, request->id);
		ret_err = 7;
                goto out1;
            }     
        }
 
    }
    /*
     * Now LOCK just object      
     */

    clock_gettime(CLOCK_REALTIME, &abs_time);
    if (abs_time.tv_nsec >= 550000000) {
        abs_time.tv_nsec -= 450000000;
        abs_time.tv_sec++ ;
    } else
        abs_time.tv_nsec += 440000000;

    r = pthread_mutex_timedlock (&des->block, &abs_time);

    if (r) {
        WLOG("TRYLOCK LOCAL ERROR for %s func %d with %s\n", request->name, add, strerror(r));

        sprintf(buff_d, "<r%s - LOCK ERROR/r><n%s/n><i%d/i>", request->command, request->name, request->id);
        goto out2;
    }
    /*
     * unlock global LOCK
     */
    pthread_mutex_unlock(&request_put_lock);

    if (UNLIKE(debug_request_put)) {
        WLOG_NB( "LOCAL locked\n");
    }

#ifdef DEBUG_REQUEST_PUT
    WLOG ("qsort_search dla %s oddalo %d des->lock %p qsort_cmp %d\n", request->name, w, &des->block, n);
#endif
    /*
     * w des wskaznik na nazwe z request     
     *  dodanie danych do juz istniejacych
     */
#ifdef DEBUG_REQUEST_PUT
    WLOG ("BEFORE ADDING DATA\n");    
#endif
    /*
     * przy add = 0 dodanie nowych danych do starych od offset = 0 lub zadeklarowanych w zadaniu
     */
    if (add == 0) {
        if (request->stop) {
            char *new;
            unsigned int wie;
            /*
            * zaalokowanie nowego bufora
            * czy wielkosc bufora w systemie jest wieksza od wielkosc bufora w requescie
            */
            if (des->size > request->stop)
                wie = des->size;
            else
                wie = request->stop;

            #ifdef DEBUG_REQUEST_PUT
            WLOG( "COPY DATA new buf size %d\n", wie);            
            #endif
     
            new = realloc(des->buf, wie);
            if (!new) {
                WLOG( "error in realloc(0) memory to size %d\n",  wie);                
               // blad("request_put: unable to realloc(0) memory\n");
                goto out;
            }
            /*

            *   * wkopiowanie nowych danych
            */
            #ifdef DEBUG_REQUEST_PUT
            WLOG( "new ptr for buf %p\n", new);
            WLOG ("copied new data into new buffer\n");
            #endif
            if ((request->buf)&&(request->start >= 0)) {
                memcpy(new + request->start, request->buf, request->size);
            }
            des->buf = new;
            des->size = wie;
        }
        if (request->part_1 == request->part_2)    des->deleted = 0;
    }
    /*
     * ADD DATA to data tail
     */
    if (add == 1) {
         char *new;
	if (UNLIKE(debug_request_put)) {
        	WLOG( "ADD DATA: des->buf %p des->size %d request->size %d\n", des->buf, des->size, request->size);        
        }
        new = realloc(des->buf, des->size + request->size);
        if (!new) {
            WLOG( "error in realloc(1) memory old size %d size to add %d\n",  des->size, request->size);
            
            sprintf(buff_d, "<rADD - REALLOC ERROR/r><n%s/n><i%d/i>", request->name, request->id);
            goto out;
        }
        if (des->buf != new) {
		if (UNLIKE(debug_request_put)) {
            		WLOG("new ptr %p old %p size %d + request %d for %s\n", new, des->buf, des->size, request->size, des->name);
		}
            des->buf = new;
        }
        memcpy(des->buf + des->size, request->buf, request->size);
        des->size += request->size;
        
        /*
         * if was delete (so old buffer should be free),
         * recreate with data from request
         */
        if (des->deleted == 1) des->deleted = 0;
        /*
         * if new object, make visible
         */
        if ((dod_obj) && (des->deleted)) des->deleted = 0;
    }
    /*
     * Load data from file
     */
    if (add == 2) {
        int fid;
        struct stat st;
        
        char file_name[255];
        void *source;
        if (! request->size) {
            WLOG("LPUT - no filename given\n");
            sprintf(buff_d, "<rLPUT - NO FILENAME GIVEN/r><n%s/n><i%d/i>", request->name, request->id);
            goto out;
        }
        /*
         * copy request->buf into new_name
         */
        memset(file_name, 0,255);
        memcpy(file_name, request->buf, request->size);
        //#ifdef DEBUG_REQUEST_PUT
        WLOG_NB ("ADD DATA FROM FILE %s to name %s\n", file_name, request->name);        
        //#endif
        fid = open(file_name, O_RDONLY);
        if (fid == -1) {
            WLOG_NB( "error open file %s with %s\n",  file_name, strerror(errno));
            
            sprintf(buff_d, "<rLPUT - ERROR IN OPEN FILE/r><n%s/n><i%d/i>", request->name, request->id);            
            goto out;
        }
        if (fstat(fid, &st)) {
            WLOG( "fstat error for %s with %s\n",  file_name, strerror(errno));
            
            sprintf(buff_d, "<rLPUT - FSTAT ERROR/r><n%s/n><i%d/i>", request->name, request->id);
            close(fid);

            goto out;
        }
        #ifdef DEBUG_REQUEST_PUT
        WLOG_NB("stat size %u\n", (uint32_t) st.st_size);        
        #endif
        des->size = st.st_size;
        if (st.st_size > 0) {
            char *new = realloc(des->buf, st.st_size);
            if (!new) {
                WLOG( "error malloc memory for %s with %s\n",  request->name, strerror(errno));

                sprintf(buff_d, "<rLPUT - ERROR MALLOC MEMORY/r><n%s/n><i%d/i>", request->name, request->id);
                
                close(fid);
                goto out;
            }

            if (new != des->buf) {
                #ifdef DEBUG_REQUEST_PUT
                WLOG("new ptr %p old %p size %d + request %d for %s\n", new, des->buf, des->size, request->size, des->name);
                #endif
                des->buf = new;
                des->size = st.st_size;
            }
            
            if ((source = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fid, 0)) == (void *) -1) {
                    WLOG("error mmap memory for %s with error %s\n",  request->name, strerror(errno));

                    sprintf(buff_d, "<rLPUT - ERROR MMAP MEMORY/r><n%s/n><i%d/i>", request->name, request->id);

                    close(fid);
                    free(des->buf);
                    des->size = 0;
                    des->buf = 0;
                    goto out;
             }
            
             memcpy(des->buf, source, st.st_size);
             munmap(source, st.st_size);            
        }
        close(fid);
#ifdef IDS_FOR_FILE
        des->mode = st.st_mode;
#endif       
       /*
        * load data into request not in cur
        * because below in common section
        * is checking is this value is good or not
        * from request data
        */
        request->t_sec = st.st_mtim.tv_sec;
        request->t_msec = st.st_mtim.tv_nsec;
  
        if  (des->deleted) des->deleted = 0;
        /*
         * ping sendd to that new data are available
         */

        if (sendd_pid) {
            fid = open(sendd_pid_file, O_RDONLY);
            if (fid > -1) {
                char pid_i[32];
		int r = 0;
		memset(pid_i, 0, 32);
		r = read(fid, pid_i, 32);
		if (r > 0) {
                    int16_t sendd_pid = atol(pid_i);
                    WLOG("LPUT SIGUSR1 to %d\n", sendd_pid);
                    if (kill(sendd_pid, SIGUSR1)) {
                        WLOG("LPUT kill return error: %s\n", strerror(errno));
                    }
                } else {
			WLOG("LPUT read status %d\n", r);
		}
                close(fid);
            } else {
                WLOG("LPUT error to open file %s: %s\n", file_name, strerror(errno));
            }
        }
    }
    /*
     * RENAME (3) and LINK (4) and COMPR (8)
     * request->name - new name (des - point to new name) - for link prohibited, rename allow to overwritten exist file
     * request->buf - old name (should be existing file)
     */
    if ((add == 3) || (add == 4) || (add == 8)) {
        char old_name[NAME_SIZE];
        struct data *old;
        /*
         * copy request->buf into old_name
         */
        memset(old_name, 0,NAME_SIZE);
        memcpy(old_name, request->buf, request->size);
        /*
         * search old name
         */        
        old = search_name(old_name);
        /*
         * if name doesn't exits
         * or obbject is deleted or partial, so don't copy from partial or deleted object
         * only copy from existing and good object
         */
        if ((!old) || (old->deleted)) {
            /*
             * old name not exist
             */
             #ifdef DEBUG_REQUEST_PUT
            if (! old) {
                WLOG("RENAME request old >%s< not found\n", old_name);
            } else {
                WLOG("RENAME file %s status %d (1 - deleted, 2 - partial)", old->name, old->deleted);
            }
        #endif
            if ((add == 3) || (add == 4) || (add == 8)) {
                sprintf(buff_d, "<r%s - NAME NOT FOUND/r><n%s/n><i%d/i>", commands[add], request->name, request->id);
             
                goto out;
            }
         
        }
        #ifdef DEBUG_REQUEST_PUT
        WLOG("RENAME/LINK/COMPRESS request old >%s< new >%s<\n", old->name, des->name);        
        #endif
        /*
        * if we have object in new name (FOR RENAME)         
        */
        if (add == 3) {
            /*
            * delete buffer in new object, if this exist
            */
            if (!dod_obj) {
                if (des->size) free(des->buf);
                des->buf = 0;
                des->size = 0;
            }
            /*
            * copy data between old and new
            */
            if ((old->size) && (old->buf)) {
               des->buf = old->buf;
                des->size = old->size;
            }
            /*
            * delete old name
            */
            old->buf = 0;
            old->size = 0;
            delete_data(old, request->t_sec, request->t_msec);
        }
        /*
         * If this is LINK
         */
        if (add == 4) {
            if ((old->size)&& (old->buf)) {
                des->size = old->size;
                /*
                 * CHECK: realloc?
                 */
                des->buf = malloc(des->size);
                if (!des->buf) {
                    WLOG("LINK malloc error\n");
                    des->size = 0;
                    sprintf(buff_d, "<rLINK - ALLOC MEMORY ERROR/r><n%s/n><i%d/i>", request->name, request->id);

                    goto out;
                }
                memcpy (des->buf, old->buf, old->size);
            }
        }
        /*
         * compression
         */
        if (add == 8) {
            /*
            * delete buffer in new object, if this exist
            */
            if (!dod_obj) {
                if (des->size) free(des->buf);
                des->buf = 0;
                des->size = 0;
            }
            if ((old->size)&& (old->buf)) {
                  uLongf buf_s = old->size;
                  int c;

                  des->buf = MALLOC_S(old->size);
                  if (!des->buf) {
                      WLOG("COMPR malloc error\n");
                      sprintf(buff_d, "<rCOMPR - ALLOC ERROR/r><n%s/n><i%d/i>", request->name, request->id);
                      goto out;
                  }

                c = compress2 ((Bytef *)des->buf,  &buf_s, (Bytef *)old->buf, old->size, 9);
                if (c != Z_OK) {
                    if (c == Z_BUF_ERROR)  WLOG("compress buffer error\n");
                    if (c == Z_MEM_ERROR) WLOG("compress memory\n");
                    if (c == Z_DATA_ERROR) WLOG("compress input data stream error\n");
                sprintf(buff_d, "<rCOMPR - COMPRESSION ERROR/r><n%s/n><i%d/i>", request->name, request->id);
                    goto out;
                }
                /*
                 * corecting size and buf after compression
                 */
                des->size = buf_s;
                des->buf = REALLOC_S(des->buf, des->size);
            }

        }
#ifdef IDS_FOR_FILE
        des->mode = old->mode;
        des->owner = old->owner;
        des->group = old->group;
#endif
        if  (des->deleted) des->deleted = 0;
    }
    /*
     * copy all data from request to object, there are some requiments:
     * TRUNCate (name must exist, so dod_obj = 0)
     * TRUNexist (name must not-exist, so dod_obj = 1)
     * for TRUNZate can create object
     */
    if ((add == 6) || (add == 7) || (add == 9)) {        
	if (UNLIKE(debug_request_put)) {
	 WLOG_NB( "request->buf %p des->buf %p\n", request->buf, des->buf);
      //  WLOG_NB( "des->deleted %d request->size %d des->size %d\n", des->deleted, request->size, des->size);
    }
        /*
         * change whole buffer with data from request
         */
         if (request->size == 0) {
             if (des->size) { 
                 FREE_S(des->buf);
                 des->buf = 0;
                 des->size = 0;
             }
        } else {
            char *old = des->buf;
            des->buf = request->buf;
            des->size = request->size;
            request->buf = 0;
            request->size = 0;
            if (old) FREE_S(old);
        }

        /*
         * if was delete or partial, make good
         */
        if  (des->deleted) des->deleted = 0;
    }
    if (add == 10)  {
        des->deleted = 2;
    }
    if (add == 11) {
        des->deleted = 1;
        if ((des->buf) && (des->size))
            free (des->buf);

        des->buf = 0;
        des->size = 0;
    }
    /*
     * TOUCH object
     * mean change time to current
     * I think, nothing to do separetly
     * currently this is just for information
     */
    if (add == 12) {

    }
    /*
     * common operations for sucesfull changes
     */
#ifdef IDS_FOR_FILE
    /*
     * copy permission, if any
     * they can be mode, from previous request, so mode are only set when they need to be set
     */
    if (request->mode) {
        des->mode = request->mode;
    }
    if (!(request->owner == -1)) {
        des->owner = request->owner;
    }
    if (!(request->group == -1)) {
        des->group = request->group;
    }
#endif
    /*
     * wpisanie wersji
     * jezeli jest w requescie to przepisz, jezeli nie to wygeneruj     
     */

    if (request->t_sec) {     
        des->t_sec = request->t_sec;
        des->t_msec = request->t_msec;

        #ifdef DEBUG_REQUEST_PUT
        WLOG( "Wpisano dla %s wersje %d %d\n", des->name, des->t_sec, des->t_msec);
        #endif
    } else {
        struct timeval cz;
        gettimeofday(&cz, NULL);
        #ifdef DEBUG_REQUEST_PUT
        WLOG ("Wygenerowanie wersji %ld %ld\n", cz.tv_sec, cz.tv_usec);        
        #endif
        des->t_sec = cz.tv_sec;
        des->t_msec = cz.tv_usec;
    }
 /*
  * copy modify host
  */
    des->modify_ip = request->client;
    /*
     * czy jest to wkladanie danych przez jakiegos klienta
     */

    if (pthread_mutex_unlock(&des->block)) 
        WLOG("unlock local lock for %s with error %s", des->name, strerror(errno));

out_good:
	if (UNLIKE(debug_request_put)) {
		WLOG("func %d successfully end\n", add);
	}
    if (serverSocket != -1) {
        sprintf(buff_d, "<r%s - OK/r><n%s/n><i%d/i>", commands[add], request->name, request->id);

        n = send_packet(buff_d, 0, 0 , serverSocket, request->client);
        #ifdef DEBUG_REQUEST_PUT
        WLOG("odpowiedz size %d %s\n", n, buff_d);        
        #endif 
    }        
    return 0;
    /*
     * In case of any error
     * common place
     */
out:
    /*
     * unlock mutex
     */
    if (pthread_mutex_unlock(&des->block))
        WLOG("unlock local lock for %s with error %s", des->name, strerror(errno));

    /*
     * if we created object, delete it
     */
out2:    
    if (dod_obj) {
        des->deleted = 2;
        if ((des->size) && (des->buf)) {
            free(des->buf);
            des->buf = 0;
            des->size = 0;
        }
    }
  
out1:
    if (request_put_lock.__align) {
        if (pthread_mutex_unlock(&request_put_lock)) {
             WLOG_NB("unlock local lock for %s with error %s", des->name, strerror(errno));
        }
    }
    if (serverSocket != -1) 
        n = send_packet(buff_d, 0, 0 , serverSocket, request->client);
     if (UNLIKE(debug_request_put)) { 
        WLOG_NB("error ret: %d\n", ret_err);
     }
    return ret_err;
};


/*
 * funkcja nasluchuje na porcie start_port + 1
 * Na ten port zapisuja sie klienci, ktorzy chca otrzymywac informacje, o nazwie i wersji przechowywanych danych
 *za wysylanie odpowiada osobny proces sendd
 *
 */
int client_register()
{
    unsigned int alen;
    struct sockaddr_in sad; /* structure to hold server's address  */
    int n, client_Sockfd;
    
    client_Sockfd = socket(PF_INET, SOCK_DGRAM, 0); /* CREATE SOCKET */

    if (client_Sockfd < 0) blad("socket creation failed\n");

    memset((char *) & sad, 0, sizeof (sad)); /* clear sockaddr structure   */
    sad.sin_family = AF_INET; /* set family to Internet     */
    sad.sin_addr.s_addr = start_ip; /* set the local IP address   */
    sad.sin_port = htons((u_short) start_port + 1); /* set the port number        */

    if (bind(client_Sockfd, (struct sockaddr *) & sad, sizeof (sad)) < 0) {
        WLOG("bind failed\n");
        blad("client_register: exit...");
    }

    alen = sizeof (struct sockaddr);
    /*
     * Main Loop for receive data from other IDSes
     * infinitive loop
     */
    while (1) {     
        char buff[BUF];
        uint8_t i = 0;
        struct client *ptr = ptr_client;
        struct sockaddr_in cad; /* structure to hold client's address  */ 
        /*
         * Wyczyszczenie bufora
         */
        memset(buff, 0, BUF);

        n = recvfrom(client_Sockfd, buff, BUF, 0, (struct sockaddr *) & cad, &alen);

        #ifdef DEBUG_CLIENT_REGISTER
        WLOG("Server from %s:%d received %s\n",inet_ntoa(cad.sin_addr), ntohs(cad.sin_port), buff);            
        #endif
        /*
         * dodanie go do klientow
         */
        if ((buff[0] == 'A') && (n == 1)) {        
            uint8_t jest = 0;
            #ifdef DEBUG_CLIENT_REGISTER
            WLOG( "Try add from %s:%d\n",inet_ntoa(cad.sin_addr), ntohs(cad.sin_port));
            #endif
            /*
             * dopisanie nowego klienta na koniec kolejki
             */
            for(;i < MAX_IP;i++) {
                ptr = ptr_client + i;
            /*
             * sprawdzenie, czy juz nie mamy takiego klienta (sprawdzamy tylko IP, port zmieniamy )
             */
                #ifdef DEBUG_CLIENT_REGISTER
                WLOG("i %d s %p  to %s:%d \n",i, ptr,  inet_ntoa(ptr->client.sin_addr), ntohs(ptr->client.sin_port));
                #endif                
        
                if (ptr->client.sin_addr.s_addr == cad.sin_addr.s_addr) {
                    /*
                    * below if port also should be same - no always true
                    */
                    // && (new->client.sin_port == s->client.sin_port)) {
                    #ifdef DEBUG_CLIENT_REGISTER
                    WLOG("Client from %s:%d EXIST\n",inet_ntoa(ptr->client.sin_addr), ntohs(ptr->client.sin_port));
                    #endif
                    /*
                    * register new port
                    */
                    ptr->client.sin_port = cad.sin_port;
                    break;
                }                 
            }
            /*
             * jak jest sam koniec, to dopisz tego klienta
             */
            if (i == MAX_IP) {
                for (i = 0; i < MAX_IP; i++) {
                    ptr = ptr_client + i;
                    if (! ptr->czas) {
                          //  #ifdef DEBUG_CLIENT_REGISTER
                          WLOG("ADD client from %s:%d\n", inet_ntoa(cad.sin_addr), ntohs(cad.sin_port));
                        //#endif
                          ptr->czas = time(0);
                          ptr->client = cad;
                          // memcpy(&ptr->client, &cad, sizeof(struct sockaddr_in));
                           jest = 1;
                            break;
                        }
                    }
                }
                /*
                 * if no new client installed
                 * don't go further - (don't send unnessesary flood to other
                 */
                if (!jest) continue;
            }
            /*
             * usuniecie go z kolejki
             */
            if ((buff[0] == 'R') && (n == 1)) {
                struct client *s;
                for (s = ptr_client;i < MAX_IP;i++) {
                    #ifdef DEBUG_CLIENT_REGISTER
                    WLOG ("%d ptr %p\n", i, s);
                    #endif
                    /*
                     * znalezienie adresu IP
                     */
                    if (s->client.sin_addr.s_addr == cad.sin_addr.s_addr) {
                       //     && (s->client.sin_port == cad.sin_port)) {                    
                        memset(&s->client, 0, sizeof(struct sockaddr_in));
                        s->czas = 0;
                        break;
                    }
                }
            }           
        #ifdef DEBUG_CLIENT_REGISTER
            WLOG( "END LOOP\n");            
            #endif        
    }
}

/*
 * funkcja rejestrowuje i wyrejstrowuje z serwerow
 * in:
 * A - add
 * R - remove
 * out:
 * ilosc wyslanych bajtow
 */
int register1(char *buff, int Clifd, char *ip)
{
    struct sockaddr_in cad;
    int alen, n;

    alen = sizeof(cad);
       
    cad.sin_family = AF_INET; /* set family to Internet     */
    cad.sin_addr.s_addr = inet_addr(ip); /* set the local IP address   */
    cad.sin_port = htons((u_short) start_port + 1); /* set the port number        */
    #ifdef DEBUG_REGISTER1
    WLOG( "register1: wyslanie do %s %s\n", ip, buff);    
    #endif
    n = sendto(Clifd, buff, strlen(buff), 0, (struct sockaddr *) & cad, alen);    
    return n;
}


/*
 * function finish - launch by CTR-C or QUIT command - safe close IDS
 * ungregister in external IDS
 * kill thread
 * free alloc memeory
 * exit
 * MB: 2010.01
 */
void finish()
{   
    uint64_t i;
    uint32_t ui = 0;
    /*
     * unregister us from servers
     */
    WLOG("finish: unregister from servers\n");

    if (pthread_mutex_trylock(&ip_block)) {
         WLOG( "finish: unable to lock ip  %s\n", strerror(errno));
    } else {
        unregister_all_ip();
    }        

	if (sendd_pid > 0) {
		WLOG("finish: kill sendd %d\n", sendd_pid);
		kill(sendd_pid, SIGTERM);
	}
	if (get_object_pid > 0) {
		 WLOG("finish: kill checker process %d\n", get_object_pid);
		kill(get_object_pid, SIGTERM);
	}
    /*
     * free alloc memory for valign :)
     */    
    /*
     * free addresses using qsort table
     * because qsort should have valid data
     * (not deleted)
     * TODO: check is partial data free too
     */ 

    WLOG( "finish: unalloc data memory...\n");
       
    for (i = 0; i < qsort_c; i++) {
        struct data *c = qsort_data[i];
        pthread_mutex_unlock(&c->block);
        
        if (c->buf) {
            FREE_S(c->buf);
            c->buf = 0;
        }     

       if ((! (i % 200)) || ((i + 1) == qsort_c)){
           #ifdef __x86_64
                WLOG("finish: free'd %ld of %ld\n", (uint64_t)i,  (uint64_t)qsort_c);
#else
                WLOG("finish: free'd %d of %d\n", (uint32_t)i,  (uint32_t)qsort_c);
#endif
       }
    }
    
    if (qsort_data) free(qsort_data);
    /*
     * clean and free share memory
     */
    if (debug) WLOG("finish: clear shared memory\n");
    for (ui = 0; ui < ids_max; ui++) {
        struct data *ptr = PTR(ui);
     //   WLOG("initializing... %d %p\n", ui, ptr);
        memset(ptr, 0, sizeof(struct data));

        ptr->deleted = 2;
        #ifdef IDS_FOR_FILE
        ptr->mode = 00100755;
        #endif
    }
    if (debug) WLOG("finish: detach share segment\n");

 //   if (! shmdt(ptr_data)) WLOG("finish: unable to detach %s\n", strerror(errno));
//    if (! shmdt(shmid_server)) WLOG("finish: unable to detach %s\n", strerror(errno));
    
    if (ids_name) free(ids_name);
    /*
     * free ip addresses
     */
    WLOG("finish: unalloc data memory DONE\n");
    finish_ip(ip);

   
    if (unlink(pid_file)) {
            WLOG("finish: unable to delete %s with error %s\n", pid_file,strerror(errno));
         
    }
    WLOG( "finish: EXISTING... nice day\n");
    
    exit(0);
}
/*
 * function free IP memory and unregister from other IDSes
 *
 */

void unregister_all_ip()
{
    struct reg_ser *ret;
    int a;

    if ((!ptr_check) || (!ip[0])) return;
    ret = ptr_check;

    for (a = 0; ip[a]; a++) {
        struct reg_ser *n = ret;

         WLOG("unregister: %s\n", ip[a]);

        register1("R", checker_sockfd, ip[a]);
        free(ip[a]);
        ip[a] = 0;
        ret = ret->next;
  
        free(n);
    }

    ptr_check = 0;

}

struct reg_ser *register_all_ip()
{
    struct reg_ser *ret = 0;
    struct reg_ser *n, *p = 0;
    int a;
    /*
     * register us in to other IDSes
     */    
    for (a = 0; ip[a]; a++) {
        n = calloc(1, sizeof(struct reg_ser));
        if (!n) blad("register_all_ip: calloc error\n");
        if (!ret) 
            ret = n;
        else
            p->next = n;
        
        n->next = 0;
        /*
         * register to other IDSes
         */
        register1("A", checker_sockfd, ip[a]);
    //    #ifdef DEBUG_REGISTER_ALL_IP
        WLOG( "register: ser %s\n",ip[a]);       
     //   #endif
        n->ip.sin_addr.s_addr = inet_addr(ip[a]);
        /*
         * zaalakowanie nastepnego do kolejki
         */
        p = n;
    }
    return ret;
}

/*
 * funkcja sprawdzajaca wersje na innych serwerach
 * najpierw rejestruj sie u nich, a potem nasluchuje informacji o wersjach
 * jak nie dostaniemy odpowiedzi w odpowiednim czasie, wysylamy do serwera ponowna prosbe o rejestracje
 *
 */
int checker ()
{
    unsigned int alen;
    struct sockaddr_in cad;    
   
    int sockfd;
    alen = sizeof(cad);
    
    /*
     * otwarcie portu do nasluchu komunikatow
     */
    checker_sockfd = bind_port();
    /*
     * otwarcie portu do pobierania nowszych wersji
     */
    sockfd = bind_port();
     pthread_mutex_init(&ip_block, NULL);

    ptr_check = register_all_ip();    
 
    /*
     * nasluchuj odpowiedzi, timeout, jak nie dostaniemy od kogos response, co oznacza, ze trzeba ponownie wyslac do niego ADD
     */
     while (1) {
         char *pt;     
        fd_set rfds;
        struct timeval tv;
        int retval;
        time_t czas;        
        
        /*
         * ilosc sekund pomiedzy ktorymi czekamy na jakikolwiek pakiet z wersja
         */
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
        
        FD_ZERO(&rfds);
        FD_SET(checker_sockfd, &rfds);

        if (UNLIKE(debug_checker)) {
		    WLOG("before select serverSocket %d\n",checker_sockfd);
	    }

        retval = select (checker_sockfd + 1, &rfds, NULL, NULL, &tv);

        if (retval < 0) blad ("checker: blad select\n");

	    if (UNLIKE(debug_checker)) {
		    WLOG("after select retval %d\n", retval);
	    }

        if (retval) {
            int n;
            char buff[BUF * COMP_PACKET];
            char b_recv[BUF];
	    	uint32_t cur_time = time(0);
            uLongf buff_s = BUF * COMP_PACKET;
            struct reg_ser *c;
            struct reg_ser ids;
            int uc;
            /*
             * Wyczyszczenie bufora
             */
            memset(buff, 0, BUF * COMP_PACKET);
            memset(b_recv, 0, BUF);
    
            n = recvfrom(checker_sockfd, b_recv, BUF, 0, (struct sockaddr *) & cad, &alen);
		    if (n < 1) continue;

		    #ifdef CODE_DUMP
			DUMP_BUF_DEC(b_recv,n);
		    #endif
		    /*
		     * encode packet
		    */
            if (code_trans) {     
		        code_encode(b_recv, n);
            }

            uc = uncompress((Bytef *)buff,&buff_s,(Bytef *)b_recv,  n);
            /*
             * uncompress packet
             */
             if (uc != Z_OK) {
                if (uc == Z_BUF_ERROR)  WLOG_NB("uncompress buffer error\n");
                if (uc == Z_MEM_ERROR) WLOG_NB("uncompress memory\n");
                if (uc == Z_DATA_ERROR) WLOG_NB("uncompress input data stream error\n");
                WLOG(" from %s:%d size %d\n", inet_ntoa(cad.sin_addr), ntohs(cad.sin_port), n);
                DUMP_BUF_RAW(b_recv, n);
                continue;
             }

		if (UNLIKE(debug_checker)) {
            		WLOG("otrzymano %d od %s:%d\n", n, inet_ntoa(cad.sin_addr), ntohs(cad.sin_port));            
		}
            /*
             * wpisz serwerowi aktualny czas
             */

            if (pthread_mutex_trylock(&ip_block)) {
                WLOG("error to lock IP %s\n", strerror(errno));
                
                continue;
            }
            for(c = ptr_check;c;c = c->next) {
                if (cad.sin_addr.s_addr == c->ip.sin_addr.s_addr) {
                    c->last = cur_time;
                    break;
                }
            }
            if (! c) {
                WLOG("server not register %s:%d, aborting data\n", inet_ntoa(cad.sin_addr), ntohs(cad.sin_port));
                pthread_mutex_unlock(&ip_block);
                continue;
            }
            #ifdef DEBUG_CHECKER
            /*
             * LOG_FLOOD_WARNING:
             * becasue, each reveiced packet will print below
             * there are 10 packets from one server (5 servers make 50 linies logs in each minute
             */
            WLOG("serverowi %s wpisano czas aktualizacji %ld\n", inet_ntoa(c->ip.sin_addr), c->last);
            #endif
            /*
             * copy data needed to connection to local variable
             * because global struct is dynamic and can change
             * when we get data from other IDSes
             */
            memcpy(&ids.ip, &c->ip, sizeof(c->ip));

            pthread_mutex_unlock(&ip_block);
            
            /*
             * parse data
             */

            for (pt = buff;;) {
                struct data *s;
                uint32_t t1,t2, size = 0;
                int i = 0;
                int j = 0;                
                int k = 0;
                int w = 0;

                   /*
                 * point interesting sequences
                 * i - name
                 * j - version
                 * k - deleted
                 * w - size
                 */
                i = strfind(pt,"<n>");
                j = strfind(pt, "</n><v>");
                k = strfind(pt, "</v><d>");
                w = strfind(pt, "</d><s>");

                /*
                 * don't find version for object mean end
                 */
                if (j < 4) break;

		/*
                 * write  t1 & t2 objects version
                 */
                sscanf (pt + j + 7, "%u.%u", &t1, &t2);
		/*
		 * check timestamp of / which point to whole package age
		 * if this is too old (60 minutes) then ommit whole packet
		 * if is new then just omit data about / object
		 */
		if (!strncmp(pt + i, "<n>/</n>", 8)) {
//			WLOG("packet time %d curr time %d (math: %d)\n", t1, cur_time, cur_time - 180);
			if  (t1 < (cur_time - 180)) {
				WLOG_NB("packet time %d current time %d, packet from %s is to old...omit\n", t1, cur_time, inet_ntoa(c->ip.sin_addr));
				break;
			}
			 goto nastepny;
		}
		 /*
                 * add \0 to correct name - we can destroy buffer, because it isn't in use anymore
                 */
                pt[j] = 0;

                /*
                 * s - point to name
                 */
                s = search_name(pt + i + 3);

                /*
                 * write size of object     
                 */                     
                sscanf (pt + w + 7, "%u", &size);                
                /*
                 * jezeli posiadamy obiekt, a zdalny jest nowszy i skasowany (deleted == 1)
                 * to u nas tez skasuj
                 */
		if (UNLIKE(debug_checker)) {
                	WLOG("obj %s size %d delete %c ptr u nas (nil nie posiadamy): %p \n",pt + i + 3, size, pt[k + 7], s);
		}

                if ((s) && ((t1 > s->t_sec) || ((t1 == s->t_sec) && (t2 > s->t_msec))) && (pt[k + 7] == '1')) {
                    struct comm res;
                    memset(&res,0, sizeof(struct comm));
                    memcpy(res.name, s->name, strlen(s->name ));
                    res.t_sec = t1;
                    res.t_msec = t2;
                     memcpy(&res.client,&ids.ip, sizeof(ids.ip));
 // #ifdef DEBUG_CHECKER
                        WLOG("kasujemy %s czas u nas %d %d czas zdalny %d %d\n", s->name, s->t_sec, s->t_msec, t1, t2);
   //                 #endif
                    request_put(&res, 11, 0);
                     
                    goto nastepny;
                }            
                
                 /*
                  * if object need to be checked
                  */
                 if ((s) && (s->need_check)) {
                     // mark as checked
                     s->need_check = 0;
                     // need only correct version
                     if ((s->t_sec == t1) && (s->t_msec == 0)) {
                           s->t_msec = t2;
                           WLOG("%s checked\n", s->name);
                           goto nastepny;
                     } else
                     // no, make partial
                         s->deleted = 2;
                     s->t_sec = 0;
                     s->t_msec = 0;
                     WLOG("%s not same (is %d should be %d) - getting new version\n", s->name, s->t_sec, t1);
                 }
                /*
                 * if remote object is good
                 */
                if ((pt[k + 7] == '0') &&
                        // we don't have it
                     ((!s) ||
                        // or we have, but we have older
                        ((s) && ((t1 > s->t_sec) || ((t1 == s->t_sec) && (t2 > s->t_msec)))) ||
                        // or we have, but we have partial
                        ((s) && (t1 == s->t_sec) && (t2 == s->t_msec) && (s->deleted == '2')) ||
                        // or we have same, but smaller
                        ((s) && (t1 == s->t_sec) && (t2 == s->t_msec) && (s->size < size))
                        )) {
                    // try to download             
                    char comm[BUF];

                    if (s) {
                        WLOG_NB("%s have v1/v2/size %d/%d/%d ask for v1/v2/size: %d/%d/%d : %s\n", pt + i + 3, s->t_sec, s->t_msec, s->size,t1, t2, size, inet_ntoa(ids.ip.sin_addr) );
                    } else {
                        WLOG_NB("%s DONT have and ask for v1/v2/size: %d/%d/%d : %s\n", pt + i + 3, t1, t2, size, inet_ntoa(ids.ip.sin_addr));
                    }
                    memset(comm, 0, BUF);
                    sprintf(comm, "<rget/r><n%s/n>",pt + i + 3);

                    if (get_object(comm, size, sockfd, inet_ntoa(ids.ip.sin_addr))) {
			            uint16_t ret;
                        struct comm *res;
			            res = checker_sh_meta_data;                        
  #ifdef DEBUG_CHECKER
                        if (s) {                             
                            WLOG("pobrano GET dla %s wersja %d %d size %d (u nas %d %d size %d)\n", res->name, res->t_sec, res->t_msec, res->size, s->t_sec, s->t_msec, s->size );
                        }
                           #endif
                        /*
                         * check, if we get same version same size or smaller as we requested
                         * or we get newer and bigger
                         */
			            if (! strcmp(res->name, pt + i + 3)) { 			
	                        if (((t1 == res->t_sec) && (t2 == res->t_msec) && (size <= res->size)) || ((t1 < res->t_sec) && (size < res->size))) {
	                            res->client = ids.ip;
	                            res->part_1 = 0;
	                            res->part_2 = 0;
	                            /*
	                             * TRUNZate new object internal
	                             */
				                WLOG_NB("name %s size %d\n", res->name, res->size);
	                            if (res->size) {
                                /*
                                 * copy out from shared memory area
                                 */
	                                res->buf =  malloc(res->size);
					                if (! res->buf) {
						                WLOG("can not alloc memory for request size %d error: %s\n", res->size, strerror(errno));
						                goto nastepny;
					                }
					                memcpy(res->buf, checker_sh_data, res->size);
	                            } else
	                                res->buf = 0;

					            
	                            ret = request_put(res, 7, -1);
	
					if (UNLIKE(debug_checker)) {
	                                	WLOG("TRUNZ error for %s ret %d\n",  res->name, ret);                          
					}
	                        } else { // if (((t1 == res->t_sec) && (t2 == res->t_msec) && (size <= res->size)) || ((t1 < res->t_sec) && (size < res->size)))
	                            WLOG("error for %s expect v1/v2/size: %d/%d/%d but get %d/%d/%d\n", res->name, t1, t2, size, res->t_sec, res->t_msec, res->size);
	                        } 
			        } else {  // if (! strcmp(res->name, pt + i + 3)) {
				        WLOG("error name: ask for %s get %s\n", pt + i + 3, res->name);			
			        }
                } // if (get_object)
            } // download good object
                /*
                 *  go to next objects in packet
                 */                   
nastepny:  
                    pt += w + 1;  
            } //   for (pt = buff;;) {
        }            
        /*
         * szukanie niezarejstrowanych/starych serwerow
         */
        if (pthread_mutex_trylock(&ip_block)) {
                WLOG( "error to lock IP %s\n", strerror(errno));
        } else {                       
            if (ptr_check) {
                 struct reg_ser *c;
                  czas = time(0);
                for (c = ptr_check;;) {
			time_t czas1 = czas - (5 * TIMEOUT);
                    #ifdef DEBUG_CHECKER
                    WLOG("aktualny czas %ld dla servera %p, ktory ma czas %ld\n", czas, c, c->last);
                    #endif
                    if ((czas1 > c->last) && (czas1 > c->reg)) {
                        char *ip = inet_ntoa(c->ip.sin_addr);
                        //#ifdef DEBUG_CHECKER
                        WLOG("wyslanie A do %s bo: czas: %d czas1 %d a server ma %d \n", ip, (uint32_t) czas, (uint32_t) czas1, (uint32_t) c->last);
                        // #endif
                        register1("A", checker_sockfd, ip);
                        c->reg = czas;
                    }
                    if (!c->next) break;
                    c = c->next;
                }
            }
            if ( pthread_mutex_unlock(&ip_block)) {
                WLOG ("can not unlock unregister ip_block: %s\n", strerror(errno));
            }
                  
        }
     }
}
/*
 * function on start system load objects from bpath, which must be set in config file for IDS
 * in:
 * 1 - recursive directory (start with bpath)
 * out:
 */
void lput_rec(const char *directory)
{
    DIR *kat;
    struct dirent *k;
    char fname[PATH_MAX];
    memset(fname, 0, PATH_MAX);

    kat = opendir(directory);
    if (!kat) {
        WLOG("error open dir %s error:%s\n", directory, strerror(errno) );
       
        return;
    }
    for(k = readdir(kat);k!= NULL; k = readdir(kat)) {
        struct comm r;
        memset (&r, 0, sizeof(r));
        if ((strlen(directory) + strlen(k->d_name)) >= PATH_MAX) {
            WLOG("lenght directory %d and name %d greater than PATH_MAX %d\n", (int)strlen(directory), (int)strlen(k->d_name), PATH_MAX);
            continue;
        }
        sprintf(fname, "%s/%s", directory,k->d_name);

        if ((k->d_name[0] == '.') && (strlen(k->d_name) == 1)) continue;
        if ((k->d_name[0] == '.') && (k->d_name[1] == '.') && (strlen(k->d_name) == 2)) continue;
       if (k->d_type == DT_DIR) {
#ifdef IDS_FOR_FILE
           struct stat st;
#endif
           lput_rec(fname);
#ifdef IDS_FOR_FILE
           /*
            * INTERNAL PUT directory
            */
           sprintf(r.name, "%s", fname + 1);
           r.mode = 0040755;
           if (stat(fname, &st)) {
                WLOG( "lput_rec: fstat error for %s with %s\n",  fname, strerror(errno));
           } else {
                r.t_sec = st.st_mtim.tv_sec;
                r.t_msec = st.st_mtim.tv_nsec;
                #ifdef DEBUG_LPUT_REC
                WLOG( "lput_rec: dir name %s\n", r.name);
                #endif
                request_put(&r, 0, -1);            
            }
#endif
           continue;
       }
       if (k->d_type == DT_REG) {
            sprintf(r.name, "%s", fname + 1);
            /*
             * calculate size of file name
             * long version
             * strlen(bpath) strlen(fname - 1) + strlen('0');
             */
            r.size = strlen(bpath) + strlen(fname) + 1;
            r.buf = calloc(1,r.size);
            if (!r.buf) { blad("lput_rec: unable to alloc memory"); }
       
           sprintf(r.buf,"%s%s", bpath, fname + 1);
           #ifdef DEBUG_LPUT_REC
            WLOG("bpath %s name %s file %s buf %s\n", bpath, r.name, fname, r.buf);
            #endif
            /*
             * internal LPUT
             */
            request_put(&r,2,-1);
       
            free(r.buf);
            continue;
       }

    }
    closedir(kat);
}
/*
 * recursive function for lget_rec to recursive make directory in bpath
 */
int mkdir_rec(const char *dir)
{
	int r, a;
	struct stat s;

	char dname[PATH_MAX];
	
	memset(dname, 0,PATH_MAX);
	a = strlen(dir);
	if ((a == 0)|| (a > PATH_MAX)) return 1;
	memcpy(dname, dir, a);
        /*
         * find where is last /, which divide path and file name
         */
	for (;a > 0; a--) {
		if (dname[a] == 47) { dname[a] = 0; break; }
	}
        /*
         * not found / in path
         */
	if (a == 0) return 1;

	r = stat(dname, &s);
        /*
         * directory exist ?
         */
	if (r == 0)  {        
            return 0;
	} else {
		if (mkdir_rec(dname) == 0) {
			if (mkdir (dname, 00755) == 0) {
                                #ifdef DEBUG_MKDIR_REC
				printf("mkdir_rec: mkdir %s succesful\n", dname);
                                #endif
				return 0;
			} else {
                                WLOG( "mkdir_rec: mkdir failed %s with error %d: %s\n", dname, errno, strerror(errno));                                
			}
		}
	}
	return 1;
}

/*
 * function  save all objects to bpath, which must be set on config file
 */
void lget_rec()
{
    struct data *p = ptr_data;

    char fname[PATH_MAX];
    WLOG_NB("start dumping data\n");

    for (;;) {
        int f;
        struct stat s;
        int flags = 0;
 
        struct timeval czas[2];

        if ((!p) || (! p->next)) break;
        p = PTR(p->next);        
        /*
         * don't save directories, direcotires will be created when they will be any file
         */
#ifdef IDS_FOR_FILE
        if (S_ISDIR(p->mode)) continue;
#endif
        memset(fname,0, PATH_MAX);
        if ((strlen(bpath) + strlen(p->name)) >= PATH_MAX) {
            WLOG_NB("lenght bpath %d and name %d greater than PATH_MAX %d\n", (int)strlen(bpath), (int)strlen(p->name), PATH_MAX);
            continue;
        }
        sprintf(fname, "%s%s", bpath, p->name);

        flags = O_RDWR | O_TRUNC;        

        if (!stat (fname, &s)) {
            /* 
             * file exist, check date & time
             */
            /*
             * if directory, omit
             */
            if (S_ISDIR(s.st_mode)) continue;

            // equal, don't action
            if ((p->t_sec < s.st_mtim.tv_sec) || ((p->t_sec == s.st_mtim.tv_sec) && (p->t_msec <= s.st_mtim.tv_nsec) )) {
                #ifdef DEBUG_LGET_REC
                WLOG( "lget_rec: %s not write - file on disk same\n", fname);
                
                #endif
                continue;
            }   
            /*
             * if object in memory is deleted
             * delete also on disk
             */
            if (p->deleted == 1) {
                /*
                 * determine, is this a directory or file
                 */
                /*if (p->mode & 0040000) {
                    if (rmdir(fname) ) {
                        sprintf(log_buf, "lget_rec: delete %s failed with error %s\n",fname, strerror(errno));
                        wlog(log_buf);
                    }
                }*/
                if (unlink(fname)) {
                    WLOG("lget_rec: delete %s failed with error %s\n",fname, strerror(errno));
                    
                }
                #ifdef DEBUG_LGET_REC
                WLOG("lget_rec: %s deleted - object in memory not exist\n", fname);                
                #endif

                continue;
            }
        } else  {
        /*
         * if file not exist and error: no such file or directory
         */
            if (errno == 2) {
                /*
                 * if object is delete don't go later
                 */
                if ((p->deleted) || (p->need_check))
                    continue;
                /*
                * check directory and make recursive directories
                */
                if (mkdir_rec(fname)) {
		    WLOG( "lget_rec: error executing mkdir_rec\n");
                    
                    continue;
		}
            /*
             * create file
             */
                flags |= O_CREAT;
            } else {
            /*
             * if any other error
             */
                WLOG( "lget_rec: error stat to %s error: %d %s\n",  fname, errno, strerror(errno) );
                continue;
            }
        }
#ifdef DEBUG_LGET_REC
        WLOG ("lget_rec:  backuping %s...\n", fname);
#endif

#ifdef IDS_FOR_FILE
        f = open(fname, flags, p->mode);
#else
        f = open(fname, flags, 0755);
#endif
        if (f == -1) {
                WLOG( "lget_rec: error open file with error: %s\n", strerror(errno) );
                 continue;
        }
        /*
         * if object has size
         */
        
        if (p->size) {
            void *target;
            if((target = mmap(0, p->size, PROT_WRITE, MAP_SHARED, f, 0)) == (void *) -1) {
                WLOG( "lget_rec: error mmap memory size %d with error :%s\n", p->size, strerror(errno) );
                 close (f);
                continue;
            }
            if (ftruncate(f, p->size)) {
                WLOG( "lget_rec: truncate file to %d size with error :%s\n", p->size, strerror(errno) );
                close (f);
                continue;
            }
            /*
            * write new data
            */
            if (! memcpy(target, p->buf, p->size)) {
                WLOG("lget_rec: memcpy error: %s\n", strerror(errno));
                close (f);
                continue;
            }
            munmap(target, p->size);
        }
        close (f);
        czas[0].tv_sec = p->t_sec;
        czas[0].tv_usec = p->t_msec;
        czas[1].tv_sec = p->t_sec;
        czas[1].tv_usec = p->t_msec;

        if (utimes(fname, czas)) {
            WLOG_NB( "utimes for %s  with error :%s\n", fname, strerror(errno) );
            continue;
        }
#ifdef DEBUG_LGET_REC
        WLOG( "lget_rec: %s backup done.\n", fname);
             
#endif
    }
    WLOG( "lget_rec: stop dumping data\n");
}
/*
 * handle for USR1 signal used to backup data
 * copy all objects into bpath
 */
void signal_usr1 () {
    int iret1;
    iret1 = pthread_create( &thread[3], NULL, (void *) lget_rec, (void*)NULL);
    
    signal(SIGUSR1, (void *)signal_usr1);
}

void reload_cfg()
{
    if (pthread_mutex_trylock(&ip_block)) {
        WLOG_NB("unable to lock ip  %s\n", strerror(errno));
        
    } else {
	
	/*
	 * reload without www server
	 *
	 if (! pthread_cancel(thread[2])) {
		WLOG_NB("error to cancel tcp_server: %s\n", strerror(errno));
		
	} else {
		 WLOG_NB("create new tcp server\n"); 
	 	pthread_create( &thread[2], NULL, (void *) tcp_server, (void*)NULL);
	} */
        if (ptr_check) unregister_all_ip();
        read_file(cfg_file, ip, 1);
        ptr_check = register_all_ip();

        if (pthread_mutex_unlock(&ip_block)) {
            WLOG_NB( "unable to unlock ip  %s\n", strerror(errno));
        }
       
    }
	WLOG_NB("debug is %d\n", debug);
    signal (SIGHUP, (void *)reload_cfg);
}
/*
 *  switch IDS to actve mode
 * this can be done by two ways
 * - ids_mode set to 1 in server.cfg file
 * - checker_remote do it work
 */
void ids_active_on () 
{
    WLOG("enable active mode for IDS\n");
	ptr_data->need_check = 0;
    /*
     * switch mode to active as all objects are load and checked
     */
    ids_mode = 1;
}
/*
 * name: check_remote
 * in:
 * NONE
 * out:
 * NONE
 * return only when we are in synch with other IDSes
 * with mode active switch to on
 */
void check_remote()
{    
    char comma[NAME_SIZE];
    int Clifd; 
	if (! ip[0]) goto check_remote_out;
	Clifd = bind_port();
    sprintf(comma, "<rget/r><n//n>");
     /*
      * get number of objects from other IDS
      */   
    for (;;) {
        int32_t max = 0, good = -1;
        uint16_t a = 0;
        for (;ip[a];a++) {
            struct comm *res;
            res = send_request(comma, 0,0, Clifd, ip[a],0);

            if (res) {
                  /*
                   * 9 = strlen ("objects: ");
                   */
                if ((res->buf) && (res->size > 9)) {
                    uint32_t m = 0;
                    int32_t idx = strfind(res->buf, "objects: ");
                                        
                    if (idx == -1) {
                        WLOG("od %s objects number not found, data %s\n", ip[a], res->buf);
                        goto out;
                    } else {
                        sscanf (res->buf + idx + 9, "%u", &m);
                    }

                    if (max < m) max = m;

                    good = good_objects();
                    WLOG("%s has %d objects, max: %d, load: %d\n", ip[a], m, max, good);
                }
out:
                if (res->buf) free(res->buf);
                free(res);
            }
       }
	/*
	 * -2 becuase sometimes are problems to get all remote objects
 	 * so '-2' it's margin
	 */
       if (good >= max - 2) break;
       sleep(10);
    }
    close (Clifd);

check_remote_out:
	WLOG("IN SYNC, so end my task\n");
	ids_active_on();
}
/*
 * load data for backup dir
 */

void load_file_from_bpath()
{
    uint32_t n = 0;
   
    if (chdir (bpath)) {
        WLOG("unable to chdir to %s with error %s \n", bpath, strerror(errno));
    } else {
        struct data *s;
        lput_rec(".");
        /*
         * mark all objects, as need to be checked         
         */
        s = OFF_TO_PTR(ptr_data->next);

        for (;s;n++) {
                s->need_check = 1;
            if (s->next)
                s = PTR (s->next);
            else
                break;
        }
    }
    WLOG("loaded %d objects\n", n);

}
/*
 * desc: initialize share memory for IDS
 * out:
 * 0 - false
 * 1 - true
 */

int init_share_data()
{
      key_t key = CMIT_SHARED_KEY;
    int shmid;
    uint32_t ui;
/*
     * create share memory for servers, which like to receive data
     */
    shmid = shmget(key + 1, MAX_IP * sizeof(struct client), IPC_CREAT | 0644);
    if (shmid < 0) {
        WLOG("init_share_data: error to create shared memory: %s\n", strerror(errno));
        return 0;
    }
    ptr_client = shmat(shmid, NULL, 0);

    if (ptr_client == (void *) -1) {
        WLOG("init_share_data: error to attach shared memory: %s\n", strerror(errno));
        return 0;
    }
    /*
     * clear share memory
     */
    for (ui = 0; ui < MAX_IP; ui++) {
        struct client *ptr = ptr_client + ui;
     //   WLOG("init_share_data: initializing share memory for register server ... %d %p\n", ui, ptr);
        memset(ptr, 0, sizeof(struct client));
    }

    /*
     * create share memory for meta data
     */
    shmid = shmget(key, ids_max * sizeof(struct data), IPC_CREAT | 0644);
    if (shmid < 0) {
        WLOG("error to create shared memory for %d entries: %s\n", ids_max, strerror(errno));
        return 0;
    }
    ptr_data = shmat(shmid, NULL, 0);

    /*
     * create share memory for meta data
     */
    shmid = shmget(key + 3, sizeof(struct comm), IPC_CREAT | 0600);
    if (shmid < 0) {
        WLOG("error to create shared memory: %s\n", strerror(errno));
        return 0;
    }
    checker_sh_meta_data = shmat(shmid, NULL, 0);

    if (checker_sh_meta_data == (void *) -1) {
        WLOG("error to attach shared memory: %s\n", strerror(errno));
        return 0;
    }

    shmid = shmget(key + 4, DATA_MAX, IPC_CREAT | 0600);
    if (shmid < 0) {
        WLOG("error to create shared memory: %s\n", strerror(errno));
        return 0;
    }
    checker_sh_data = shmat(shmid, NULL, 0);

    if (checker_sh_data == (void *) -1) {
        WLOG("error to attach shared memory: %s\n", strerror(errno));
        return 0;
    }

    /*
     * clear share memory
     */
    for (ui = 0; ui < ids_max; ui++) {
        struct data *ptr = PTR(ui);
     //   WLOG("init_share_data: initializing... %d %p\n", ui, ptr);
        memset(ptr, 0, sizeof(struct data));
        ptr->deleted = 2;
        #ifdef IDS_FOR_FILE
        ptr->mode = 00100755;
        #endif
    }

    qsort_data = calloc(ids_max, sizeof(struct data*));
    if (!qsort_data) {
        WLOG ("can't alloc memory %s\n", strerror(errno));
        blad("qsort_refresh: exiting...\n");
    }
    WLOG("initializing %d objects\n", ids_max);
    return 1;
}

void launch_sendd()
{
    char *bin = global_argv[0];
    char *cfg = global_argv[1];
    int b,a = strlen (bin);
    char e[NAME_SIZE];

    b = a;

    memset(e, 0, NAME_SIZE);

    for (;a > 0;a--) {
        if (bin[a] == '/') break;
    }
    /*
     * 6 = sizeof('sendd')
     */
    if (a + 6 < NAME_SIZE) {
        char *p = getcwd(0,0);
        memcpy (e, bin, a);
        sprintf(e, "%s/sendd", e);
        WLOG("exec: %s cfg %s pwd: %s\n", e, cfg, p);
        if (p) free(p);
    }
    /*
     * waiting for signal, that all data are in place
     */
    while (! ids_mode) {
        WLOG_NB("IDS mode off - %d already load\n", good_objects());
        sleep (2);
    }
    WLOG("active mode ON\n");

    for (;;) {
        int status;
	    int pid = fork();

	    if (! pid) {
	        /*
	         * initialise logging
	         */
	        fidlog = -1;
	        pthread_mutex_init(&wlog_lock, NULL);

		  	WLOG_NB("created new sendd\n");
	
	        execlp(e, e, cfg, NULL);
	        WLOG("exec error: %s\n", strerror(errno));
	        exit(0);
	    } 
	    WLOG_NB("created %d for sendd\n", pid);
	    
	    /*
	     * just global information that we start sendd process
	     * after once checker sendd_pid should have correct pid number
		* use for ping by check_other_ids then
	     * this follow is false pid, don't trust it
	     */
	    sendd_pid = pid;
        for (;;) {
            waitpid(pid, &status, 0);
            /*
             *  check if PID stil exist
             */
            if (kill (pid,0)) break;
        }
        WLOG_NB("pid %d finished with %d status %d raw status %d\n", pid, WIFEXITED(status), WEXITSTATUS(status), status);
        sleep(2);
    }
}


int main_loop(char *bin, char *cfg)
{
    struct sockaddr_in sad; /* structure to hold server's address  */
    uint32_t port; /* protocol port number                */

    struct sockaddr_in cad; /* structure to hold client's address  */
    unsigned int alen; /* length of address                   */
    int32_t serverSocket; /* socket descriptors  */  
    
    int iret, iret1, iret2, iret3, iret5;
    struct timeval cz;
    struct comm *request;
    
    if (! init_share_data()) return 0;

    pthread_mutex_init(&request_put_lock, NULL);

    // #ifdef DEBUG_MAIN
    WLOG_NB("lock addresses: request_put_lock %p wlog_lock %p ip_block %p\n", &request_put_lock, &wlog_lock, &ip_block);
    //#endif
    
    /*
     * create first data, which is for statistic
     */  
    /*
     * initializing data
     */     
    qsort_refresh();
        
    gettimeofday(&cz, NULL);

    ptr_data->t_sec = cz.tv_sec;
    ptr_data->t_msec = cz.tv_usec;

#ifdef IDS_FOR_FILE
    ptr_data->owner = getuid();
    ptr_data->group = getgid();
    ptr_data->mode = 0040777;
#endif
    /*
     * alloc space for statistics
     */
    ptr_data->buf = malloc(BUF);
    ptr_data->size = BUF;
    sprintf(ptr_data->name, "/");
    ptr_data->deleted = 0;
    ptr_data->need_check = 1;
    if ((bpath_load) && (bpath[0] == 47))  {
         char *p = getcwd(0,0);
        load_file_from_bpath();
        chdir(p);
        free (p);
    }
 
    /*
     * listen client to register
     */
    iret = pthread_create( &thread[0], NULL, (void *)client_register, (void*)NULL);
    /*
     * run sendd as separate process
     */

	 iret5 = pthread_create( &thread[5], NULL, (void *) launch_sendd, ( void *) NULL);

	/*
	* if there is any other IDS and we are in passive mode
        * sync and run sendd daemon
        * also ids_mode is switch in check_remote function
	*/
	// WLOG("ids_mode %d\n", ids_mode);
	 /*
         * switch IDS to active mode if parameter is set in cfg file
         * and don't check or get on other IDSes 
         */
    
   if (ids_mode)  {
		ids_active_on();
    } else {
        /*
         *  when passive, try to get list from other IDS
         */
        int32_t count = 1;
        if (ip[0]) {
            int32_t a;
            port = bind_port();
            for (a = 0; ip[a]; a++) {
                char *b;
                WLOG_NB("get from %s\n", ip[a]);
                char *pt;

                get_object("<rlisv/r>", 0, port, ip[a]);
                WLOG_NB("get size %d\n", checker_sh_meta_data->size);
                b = malloc(checker_sh_meta_data->size);
                if (! b) { 
                    WLOG_NB("malloc error\n"); 
                    continue;
                }
                memcpy(b, checker_sh_data, checker_sh_meta_data->size);
                for (pt = b;;) {
                    struct data *s;
                    uint32_t t1,t2, size = 0;
                    int i = 0;
                    int j = 0;                
                    int k = 0;

                    /*
                     * point interesting sequences
                     * pt - name
                     * i - size 
                     * j - version
                     */
                    i = strfind(pt,"<s");
                    j = strfind(pt, "/s><v");
                    k = strfind(pt, "/v>");

                    /*
                     * don't find version for object mean end
                     */
                   if (j < 4) break;
                    /*
                     * write  t1 & t2 objects version
                     */
                    sscanf (pt + j + 6, "%u.%u", &t1, &t2);

                   /* 
                    * put null at end of string
                    */
                   pt[i - 1] = 0;

                    /*
                     * write size of object     
                     */                     
                    sscanf (pt + i + 2, "%u", &size); 
                    /*
                     * s - point to name
                     */
                    s = search_name(pt);
                    if (! s) {
                        char comm[BUF];
                        memset(comm, 0, BUF);
                        sprintf(comm, "<rget/r><n%s/n>",pt);
                        if (UNLIKE(debug_main_loop)) {
                            WLOG_NB("ASK name %s to get size %d\n", pt, size);
                        }
                        if (get_object(comm, size, port, ip[a])) {
                            uint16_t ret;
                            struct comm *res;

                            res = checker_sh_meta_data;
                            res->part_1 = 0;
                            res->part_2 = 0;
                            /*
                             * TRUNZate new object internal
                             */
                            if (UNLIKE(debug_main_loop)) {
                                WLOG_NB("GET (%d) name %s size %d\n", count, res->name, res->size);
                            }
                            if (res->size) {
                                /*
                                * copy out from shared memory area
                                */
                                res->buf =  malloc(res->size);
                                if (! res->buf) {
                                    WLOG_NB("can not alloc memory for request size %d error: %s\n", res->size, strerror(errno));
                                    goto nastepny;
                                }
                                memcpy(res->buf, checker_sh_data, res->size);
                            } else
                                res->buf = 0;

                            ret = request_put(res, 7, -1);
                           
                            if (ret) {
                                WLOG("TRUNZ error for %s ret %d\n",  res->name, ret);                          
                            }
                            count++;

                        } // if (get_object)
                    } else {
                        WLOG_NB("EXIST name %s\n", pt);
                    }
nastepny:
                    pt += k + 4;  
                }
                free(b);

            }
            close (port);
        }
		iret3 = pthread_create( &thread[4], NULL, (void *)check_remote, (void*)NULL);
    }
    /*
     * register to other
     */
    iret1 = pthread_create( &thread[1], NULL, (void *) checker, (void*)NULL);
    /*
     * run as thread TCP server
     */
    iret2 = pthread_create( &thread[2], NULL, (void *) tcp_server, (void*)NULL);

    
    /*
     * open UDP port
     */
    port = start_port; 

    serverSocket = socket(PF_INET, SOCK_DGRAM, 0); /* CREATE SOCKET */
    if (serverSocket < 0) blad("socket creation failed\n");

    /*
     * listen for request
     */
    memset((char *) & sad, 0, sizeof (sad)); /* clear sockaddr structure   */
    sad.sin_family = AF_INET; /* set family to Internet     */
    sad.sin_addr.s_addr = start_ip; /* set the local IP address   */
    sad.sin_port = htons((u_short) port); /* set the port number        */    

    if (bind(serverSocket, (struct sockaddr *) & sad, sizeof (sad)) < 0)
        blad("main: bind failed\n");
    alen = sizeof (struct sockaddr);

     request = calloc(1, sizeof(struct comm));
     if (!request) blad ("main: calloc request error\n");
    /*
     * MAIN LOOP server UDP
     */
    while (1) {       
        uint32_t ret;
        int n;
        char buff[BUF];
        //struct comm request;
        
         /*
         * clear received buffer
         */
        memset(buff, 0, BUF);         
        /*
         * Waiting for UDP packet
         */
         #ifdef DEBUG_MAIN
        WLOG("Waiting for packets \n");
        #endif
        n = recvfrom(serverSocket, buff, BUF, 0, (struct sockaddr *) & cad, &alen);       
        
        #ifdef DEBUG_MAIN
        WLOG("server n %d\n", n);
        #endif
        /*
         * is something wrong
         */
        if (n < 1) continue;        
    
        memset(request, 0, sizeof(struct comm));
        /*
         * check is packet has valid header
         */
        ret = xml_parse(buff, request, n);
        /*
         * if valid, ret point to valid request structure
         */
        if (ret) {
            /*
             * wpisanie skad jest zadanie
             */
            request->client = cad;
            /*
             * go > 0 oznacza pelne zadanie
             */
        //    if (request->good > 0) {
                char jest = 0;
		char buff_d[BUF_HEAD_R];
                if (UNLIKE(debug_main_loop)) {
                    WLOG_NB("command: %s\n", request->command);
                    if ((request->name) && (strlen(request->name))) { 
                        WLOG_NB("name %s\n",  request->name);               
                    }
                }

                if (!strcasecmp(request->command, "ADD")) {
                    if (!ids_mode) WLOG_NB("passive mode - ADD for %s from %s\n", request->name, inet_ntoa(cad.sin_addr));
                    ret = request_put(request, 1, serverSocket);
                    jest = 1;
                }

                if (!strcasecmp(request->command, "BUFFER")) {
                    int16_t s = 1;
                    int uc;
                    
                    char buf_d[BUF_DATA * 5];
                    uLongf size_d = BUF_DATA * 5;

                    memset(buf_d, 0, BUF_DATA * 5);

                    WLOG_NB("BUFFER from %s size %d\n", inet_ntoa(cad.sin_addr), request->size);
                    uc = uncompress((Bytef *)buf_d, &size_d ,(Bytef *)request->buf, request->size);
                    /*
                     * uncompress packet
                     */
                    if (uc != Z_OK) {
                        if (uc == Z_BUF_ERROR)  WLOG("BUFFER - uncompress buffer error\n");
                        if (uc == Z_MEM_ERROR) WLOG("BUFFER - uncompress memory\n");
                        if (uc == Z_DATA_ERROR) WLOG("BUFFER - uncompress input data stream error\n");
                        sprintf(buff_d, "<r>BUFFER - CORUPT DATA</r><i%d/i>",  request->id);
                         DUMP_BUF_RAW(request->buf, request->size);

                    } else {
                            for (;s < size_d;) {
				struct comm req;
				int32_t e = 0;
				/*
				 * line is:
				 * <char: offset to data><headaer><data>
				 *
				 * s - point to header of packet !!
				 * s - 1 = offset to data in packet !!
				 *
				 * border fo lines are:
				 * - next header (</radd/r>
				 * - end of packet (but data size need to be fixed + 1
				 */
				char *packet = buf_d + s;
				// from where data start
				uint8_t ptr_d = buf_d[s - 1];
				uint16_t data_size = 0;
				int16_t astart = 0, astop = 0;
				char t_buf[BUF];

				/*
				 * omit idx and add header
				 * strlen(<radd/r>) = 8
				 * <radd/r> is separator of each lines in this request
				 */
				e = strfind_l (&buf_d[s + 8], "<radd/r>", size_d - s - 8);
				// WLOG("idx %d ptr_data %d end %d\n", s, ptr_d, e);
				/*
				 * no more lines found in this packet
				 */
				if (e < 1) {
					e = size_d;
					data_size = e - s - ptr_d;
				} else {
					e += s + 8;
					data_size = e - s - ptr_d - 1;
				}
				/*
				 * name
				 */
				astart = strfind(packet, "<n");
				astop = strfind(packet, "/n>");
    				memset(req.name, 0, NAME_SIZE);
    				if ((astart >= 0) && (astop > 0)) {
        				astart += 2;

        				if (astop - astart < NAME_SIZE)
            					memcpy(req.name, packet + astart, astop - astart);
         				else
            					memcpy(req.name, packet + astart, NAME_SIZE);
    				}
				if (UNLIKE(debug_main_loop)) WLOG_NB("name is %s\n", req.name);
				/*
				 * version
     				 */
    				req.t_sec = 0;
    				req.t_msec = 0;
    				astart = strfind(packet, "<v");

				if (astart >= 0) {
        				astart += 2;
        				sscanf (packet+ astart, "%u.%u", &req.t_sec, &req.t_msec);
				}
				/*
				 * buffer
				 */
				 memset(t_buf, 0, BUF);
				
				req.size = data_size;
				memcpy(t_buf, buf_d + s + ptr_d, data_size);
				req.buf = t_buf;
				// WLOG("end at %d data size %d data %s", e, data_size, req.buf );
				ret = request_put(&req, 1, -1);
				/*
				 * if ret != 0 then write debug info
				 */
                if (UNLIKE(debug_main_loop)) {
                    WLOG("ADD return %d name %s for %s", ret, req.name, req.buf);
                }
				if (ret) WLOG("ADD return %d name %s for %s", ret, req.name, req.buf);
			
				if (e == size_d) break;
				s = e;
				
                            } // for (;s < size_d )
                            sprintf(buff_d, "<r>BUFFER - OK</r><i%d/i>",  request->id);
			} // else  compress
                        if (UNLIKE(debug_main_loop)) {
                               WLOG_NB("send: %s\n", buff_d);
                        }
                        n = send_packet(buff_d, 0, 0 , serverSocket, request->client);

                    jest = 1;
                }
		if (!strcasecmp(request->command, "CHECK")) {
                        ret = request_check(request, serverSocket);
                        jest = 1;
                }
                if (!strcasecmp(request->command, "RENAME")) {
                    ret = request_put(request,3, serverSocket);
                    jest = 1;
                }
		

                if (ids_mode) {
                    if (!strcasecmp(request->command, "TOUCH")) {
                        ret = request_put(request,12, serverSocket);
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "PUT")) {
                        ret = request_put(request, 0, serverSocket);
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "LPUT")) {

                        ret = request_put(request, 2, serverSocket);
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "MODE")) {
                        ret = request_put(request, 5, serverSocket);
                        jest = 1;
                    }

                    if (!strcasecmp(request->command, "TRUNC")) {
                        ret = request_put(request, 6, serverSocket);
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "TRUNZ")) {
                        ret = request_put(request, 7, serverSocket);
                        jest = 1;
                    }
                     if (!strcasecmp(request->command, "TRUNE")) {
                        ret = request_put(request, 9, serverSocket);
                        jest = 1;
                    }

                    if (!strcasecmp(request->command, "LINK")) {
                        ret = request_put(request,4, serverSocket);
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "COMPR")) {
                        ret = request_put(request,8, serverSocket);
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "GET")) {
                        ret = request_get(request,0, serverSocket);
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "LGET")) {
                        ret = request_get(request,3, serverSocket);
                        jest = 1;
                    }

                    if (!strcasecmp(request->command, "INFO")) {
                        ret = request_get(request,1, serverSocket);
                        jest = 1;
                    }

                    if (!strcasecmp(request->command, "TAIL")) {

                        ret = request_get(request,2, serverSocket);
                        jest = 1;
                    }

                    if (!strcasecmp(request->command, "DELETE")) {
                        ret = request_put(request, 11, serverSocket);
                        jest = 1;
                    }
                     if (!strcasecmp(request->command, "PARTIAL")) {
                        ret = request_put(request, 10, serverSocket);
                        jest = 1;
                    }
                    /*
                     * FUNCTION NOT USED
                     *  if (!strcasecmp(request->command, "BLOCK")) {
                    if ((!strcmp(request->command, "BLOCK")) || (!strcmp(request->command, "block"))) {
                        ret = request_block(request, serverSocket);
                        jest = 1;
                    }
                    */
                    if (!strcasecmp(request->command, "LIST")) {
                        int lpid = fork();
                        if (lpid == -1) {
                            WLOG_NB("error to create fork for list %s\n", strerror(errno));
                            request_list(request, serverSocket, 0, 0);
                        }
                        if (lpid == 0) {
                             FID_CLEAR;

                            request_list(request, serverSocket, 0, 0);
                            exit(0);
                        }
                        if (UNLIKE(debug_main_loop)) {      
                            WLOG_NB("list pid created: %d\n", lpid);
                        }
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "LISV")) {
                        int lpid = fork();
                        if (lpid == -1) {
                            WLOG_NB("error to create fork for list %s\n", strerror(errno));
                            request_list(request, serverSocket, 0, 1);
                        }
                        if (lpid == 0) {
                            FID_CLEAR;
                            
                            request_list(request, serverSocket, 0, 1);
                            exit(0);
                        }
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "RIST")) {
                        int lpid = fork();
                        if (lpid == -1) {
                            WLOG("error to create fork for rist %s\n", strerror(errno));
                            request_list(request, serverSocket, 1, 0);
                        }
                        if (lpid == 0) {
                             FID_CLEAR;

                            request_list(request, serverSocket, 1, 0);
                            exit(0);
                        }
                        if (UNLIKE(debug_main_loop)) {
                            WLOG("rist pid created: %d\n", lpid);
                        }
                        jest = 1;
                    }
                    if (!strcasecmp(request->command, "RISV")) {
                        int lpid = fork();
                        if (lpid == -1) {
                            WLOG("error to create fork for rist %s\n", strerror(errno));
                            request_list(request, serverSocket, 1, 1);
                        }   
                        if (lpid == 0) {
                            FID_CLEAR; 
                            request_list(request, serverSocket, 1, 1);
                            exit(0);                                                                                                
                        }
                        jest = 1;
                    }
                     if (!strcasecmp(request->command, "QUIT")) {
                        sprintf(buff_d, "<r>QUIT - OK</r><i%d/i>",  request->id);
                        n = send_packet(buff_d, 0, 0 , serverSocket, request->client);
                        WLOG("mail_loop: QUIT recevied from: %s\n", inet_ntoa(cad.sin_addr));
                        break;
                    }
                    if (!jest) {
                        sprintf(buff_d, "<r>ERROR: unknown request: %s</r><i%d/i>",  request->command, request->id);
                        n = send_packet(buff_d, 0, 0 , serverSocket, request->client);
                    }
                /*
                 * end of ids_name true
                 */
		}
           /*
            * end of good > 0
            */
          //  }
            
        } else {
            /*
             * if we don't know what it is, pong packet (this is for UDP port monitor)
             */
        if (code_trans) {
	        code_decode(buff, n);
        }

            sendto(serverSocket, buff, n, 0, (struct sockaddr *) & cad, sizeof(cad));            
        }

        if (request->buf) 
                free(request->buf);

        if (UNLIKE(debug_main_loop)) {
           WLOG_NB("End command\n");        
        }
    }
    return (EXIT_SUCCESS);
}

int main(int argc, char** argv) {
    pid_t pid;
    umask(0);   
    
    signal(SIGCHLD, SIG_IGN);

    if (argc < 2) {
        printf("Missing configuration file\n");
        exit (EXIT_FAILURE);
    }
   if (strlen(argv[1]) >  NAME_SIZE) {
            printf("cfg file to long, exceed %d chars\n", NAME_SIZE);
            exit (EXIT_FAILURE);
    } else {
           memcpy(cfg_file, argv[1], strlen(argv[1]));
    }
    global_argv = argv;
    /*
     * deamonize
     */
    pid = fork();    
    
    if (pid < 0) {
        printf ( "Can't fork\n");
        exit(EXIT_FAILURE);
    }    

    if (pid == 0) {    
        pid_t sid = setsid();
        int f,i;
        struct rlimit core_limit;
        struct sigaction back_trace_sig;

        if (sid < 0)
            exit(EXIT_FAILURE);
        /*
        * pobranie listy IP z pliku
        */
        start_port = 0;
        ip[0] = 0;

         if (!read_file(argv[1], ip, 0)) {
            printf("unable to open file %s\n", argv[1]);
        }
        /*
         * file descritor
         */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        /*
        * Control - C save exit - signals
        */
        signal(SIGINT, (void *)finish);
	/*
	 * USR  - dump data to bpath
	 */
        signal(SIGUSR1, (void *)signal_usr1);
        signal(SIGHUP, (void *)reload_cfg);
        /*
         * ignore sigpipe for tcp server (we handle error for tcp read/write)
         */
        signal(SIGPIPE, SIG_IGN);

	/*
	 * any signal which trigger dump which can be make us - like memory err
	 * try to do back_trace to try to find vicitm
	 */
        back_trace_sig.sa_handler = back_trace;
        sigemptyset (&back_trace_sig.sa_mask);
        back_trace_sig.sa_flags = 0;
        sigaction (SIGILL, &back_trace_sig, NULL);
        sigaction (SIGFPE, &back_trace_sig, NULL);
        sigaction (SIGSEGV, &back_trace_sig, NULL);
        sigaction (SIGBUS, &back_trace_sig, NULL);
        sigaction (SIGTRAP, &back_trace_sig, NULL);
        sigaction (SIGSYS, &back_trace_sig, NULL);


        /*
         * core dump
         */

        core_limit.rlim_cur = RLIM_INFINITY;
        core_limit.rlim_max = RLIM_INFINITY;

        if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
            printf( "Error for setrlimit: %s\n", strerror(errno));


	for (i = 0; i < 4096;i++) {
		log_buf_debug[i] = 0;
	}
        i = strlen(argv[0]);

        for (;i > 0;i--) 
            if (argv[0][i] == '/') break;
        
        sprintf(sendd_pid_file,"%s/sendd.pid", pid_file);
        sprintf(pid_file,"%s/%s.pid", pid_file, &argv[0][i]);

        f = creat(pid_file, 0755);
        if (f != -1) {
            char n[20];
            sprintf(n, "%d", getpid());
            if (write(f, n, strlen(n)) == -1) {
                WLOG("unable to write pid file in %s error: %s\n", pid_file, strerror(errno));
            } else {
                WLOG("file %s with pid save succesfully\n", pid_file);
            }
            close (f);
        } else  {
            WLOG("unable to create pid file %s error: %s\n", pid_file, strerror(errno));
        }

        if (!start_port) blad ("in configuration file doesn't find port= variable");

        main_loop(argv[0], argv[1]);
        finish();
        exit (0);
    }
    if (debug) printf("main: create child with pid %d\n", pid);
    
    return (EXIT_SUCCESS);
}
