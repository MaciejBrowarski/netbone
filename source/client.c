/*
 * File:   client.c
 * Author: BROWARSKI
 *
 * Native Client for IDS
 *
 * Version: 3.4
 *
 * History:
 * 0.0.1 2009 Jul - Created
 * 0.0.3 2009 Dec - configuration file (arguments, ip=, port=, rpath). Name based on argv[0]  (/etc/argv[0].cfg)
 * 0.0.4 2010 Jan - reviewed, fit to www client
 * 0.0.5 2010 Jan - write to stdout information about unknown command
 * 0.0.7 2010 Mar - new atomic funtion spart (special - add partial )
 * 0.0.8 2010 Jun - new function: check, send to server check on all files
 * 0.1.0 2010 Aug - more stat in info (mode)
 * 0.1.1 2010 Nov - for request for many IDS, create separate thread for each
 * 0.1.2 2010 Nov - add debug variable for dynamic debuging
 * 0.1.3 2011 April - add timeout for all operation (without put)
 * 0.1.4 2011 June - add COMPRession
 * 0.1.5 2011 August - add help and trune functions
 * 0.1.6 2011 Sep - add QUIT command
 * 0.2.0 2011 Nov - list and rist taken locally by shared memory
 * 0.2.1 2013 Feb - add touch command
 * 0.3 2013 Aug - add copy command
 * 3.1 2013 December - add addb command (add with buffer for successful results)
 * 3.2 2014 June - koniec_alarm with WLOG_NB
 * 3.3 2014 Nov - add -notimeout for bigger get request
 * 3.4 2016 Sep - get for large packet use TCP
 *
 */

//#define DEBUG_BIND_PORT
//#define DEBUG_MAIN
//#define DEBUG_GET_LIST
//#define DEBUG_READ_FILE
//#define DEBUG_XML_PARSE
//#define DEBUG_CLIENT_PUT
//#define SEND_PACKET
//#define DEBUG_MULTIPLY
//#define DEBUG_REQUEST

#define IDS_CLIENT
#include "common-client.h"

uint16_t ret = 0;
/*
 * funkcja wysyla informacje do serwera
 * name - nazwa zasobu
 * filename - nazwa pliku do odczytania
 * m - multiple (0 - tylko pierwszy serwer, n - ilosc serwerow)
 */

uint16_t client_put(char *name, char *filename, int m)
{
    int plik;
    struct stat s;
    char *buf;
    int res[m], a;
    struct timeval cz;
    uint32_t si,sf;
  //  uint16_t ret = 0;
   uint32_t sec, msec;

    #ifdef DEBUG_CLIENT_PUT
    WLOG("client_put: nazwa %s nazwa pliku %s ile serwerow %d\n", name, filename, m);
    #endif

    plik = open(filename, O_RDONLY);
    if (plik == -1) {
        blad("unable to open file\n");
    }

    fstat(plik,&s);
   /* if (s.st_size > BUF_DATA)
        si = BUF_DATA;
    else*/
    si = s.st_size;

    buf = malloc(si);
    if (!buf) blad("unable to alloc memory for buf\n");
    sf = read(plik, buf, si);
    if (sf != si) blad ("ilosc odczytanych bajtow nie rowna sie wielkosc pliku");
    close (plik);
    /*
     * wyslanie test - sprawdzenie jakie serwery mamy dostepne
     */
    /*
     * czy odpowiednia ilosc serwerow jest dostepna
     */
    /*
     * wyslanie juz danych do znanych IP
     */

    gettimeofday(&cz, NULL);
    #ifdef DEBUG_CLIENT_PUT
    WLOG("client_put: Wygenerowanie wersji %ld %ld\n", cz.tv_sec, cz.tv_usec);
    #endif
    sec = cz.tv_sec;
    msec = cz.tv_usec;

    while (1) {
        int jest = 0;
        for(a = 0; a < m;a++) {
            #ifdef DEBUG_CLIENT_PUT
            WLOG("client_put: wyslanie do IP %s wersja %d %d\n",ip[a], sec, msec);
            #endif
            res[a] = multiply_put(name, buf, si, 0, Clifd, ip[a], sec, msec);
            if (res[a]) ret++;
            #ifdef DEBUG_CLIENT_PUT
            WLOG("client_put: oddalo %d\n",res[a]);
            #endif
            if (res[a]) jest++;
        }
        if (jest > 0) break;
    }
    /*
     * sprawdzenie czy do wszystkich zostalo wyslane
     */
#ifdef DEBUG_CLIENT_PUT
	WLOG("client_put: koniec\n");
#endif
    free(buf);
    return ret;

}

void koniec()
{
    finish_ip(ip);
    exit(ret);
}
void koniec_alarm()
{
   // WLOG_NB("TIMEOUT reached - starting\n");
    finish_ip(ip);
   // WLOG_NB("TIMEOUT reached %d\n", timeout_client);
    exit(ret);
 //   koniec();
}
int main(int argc, char** argv)
{      
    char *command;

    /*
     * what to do with output
     * 0 - nothing for actions
     * 1 - output data (list, rist, get, tail)
     * 2 - output metadata (info, check)
     * 3 - partial for actions (for _c and for any actions: put/trunc/trunz/add)
     * 4 - ?
     */
    uint8_t r = 0;
   uint8_t force_debug = 0;
    uint8_t force_timeout = 0;
    uint8_t force_file = 0;
    char *buf;
    char cname[PATH_MAX];
    uint8_t rec = 0, argc_i = 2, to_buf = 0;
    char comma[BUF_HEAD];
    struct timeval cz;
    uint16_t a,s = 0;
    
    if (argc < 2) {
 //       command = com;
	printf("IDS license valid %d days\n", (uint32_t)(cm_check() / (60 * 60 * 24)));
	printf("Below arguments force variable from config file (optional)\n");
	printf("-debug - DEBUG=1 - force debug client output to log_path file\n");
	printf("-notimeout - force no timeout for client - e.g. to get bigger file\n");
        printf("One argument from below is required:\n");
        printf("add - add to end of object line (e.g. add /foo \"tree\")\n");
        
	printf("cache_info - show information from cache\n");
	printf("cache_remove - remove cache\n");
	printf("cache_refresh - send to IDS packet to check availabilty\n");
        printf("check - switch all files in memory as checked (use with caution !!)\n");
        printf("copy - copy object, old object still exist (e.g. copy old_name new_name)\n");
        printf("delete - delete object, (note: only one object can be delete, no masks for files)\n");
        printf("get - get data from object (note: for / as object IDS stats)\n");
        printf("gett - get data from object (note: for / as object IDS stats) using TCP - for large object\n");
        printf("info - get meta data from object (e.g. data creation, size)\n");
        printf("lget - get data from object to local file \n");
        printf("list - list objects, if argument given, then list object, which name start with argument\n");
        printf("lisv - list objects with meta data, if argument given, then list object, which name start with argument\n");
        printf("lput - write data from file into object, works only on one IDS\n");
        printf("partial - make object partial (note: object become corrupted on this IDS)\n");
        printf("put - write data from argument to object\n");
        printf("rename - rename object, old object is deleted (e.g. rename old_name new_name)\n");
        printf("rist - list objects, if argument given, then list object, which name end with argument\n");
        printf("risv - list objects with meta data, if argument given, then list object, which name end with argument\n");
        printf("spart - add data to object, but before it, check is two or more IDSes are available (like add_c) but,  if not available, make object partial\n");
        printf("spartb - same as spart but good results are buffered on client side and send when buffer is full or after buffer_flush time\n");
        printf("tail - get tail data from file (note: one network package, so last max %d bytes of object)\n", BUF);
        printf("touch - touch the file and change date for object to current\n");
        printf("trunc - truncate, if exist, object with data from argument, if object not exists, no action\n");
        printf("trune - truncate, for non-exit object, with data from argument, if object exists, no action\n");
        printf("trunz - truncate object with data from argument, if object not exists, it will be created\n");
        
        printf("\narguments end with below suffix has addtional functionality\n");
        printf("- _r - do action on all IDSes\n");
        printf("- _c - do actions on all available IDSes (before action, check how many are avaiable)\n");
        printf("\non exit, client, as return value, give numbers of actioned IDSes\n\n");
        return 0;
    } else {        
        if (!strncmp(argv[1], "-debug", 6)) {
            force_debug = 1;
            command = argv[2];
            argc_i = 3;
        } else if (! strncmp(argv[1], "-notimeout", 10)) {
		    force_timeout = 1;
		    command = argv[2];
		    argc_i = 3;	
        } else if (! strncmp(argv[1], "-file", 5)) {
            force_file = 1;
            command = argv[2];
            argc_i = 3;
	    } else {
            command = argv[1];
        }

        s = strlen(command);

        if (!strncmp(&command[s - 2],"_r",2)) {
            rec = 1;
        }
        if (!strncmp(&command[s - 2],"_c",2)) {
            rec = 1;
            r = 3;
        }
    }
    
    /*
     * pobranie nazwy pliku, ktory nas uruchomil
     * dzieki temu szukamy nazwy pliku konfiguracyjnego
     */
	if (get_cfg_filename(argv[0], cname)) {
		printf("full path without bin folder\n");
			blad ("no found bin in full path\n");
	}

    start_port = 0;
    if (!read_file (cname, ip, 0)) {
        printf("problem z %s\n", cname);
        blad ("blad pobrania serwerow\n");
    }
    if (!start_port) blad ("there isn't port= variable in configuration file\n");    

	if (force_debug) debug = force_debug;
	if (force_timeout) timeout_client = 0;
    if (debug) {
        WLOG_NB("cfg file: %s\ncounting %d arguments argc_i %d\n", cname, argc, argc_i);

        for (a = 0; a < argc; a++) {
            WLOG("ARGV[%d]: %s\n", a, argv[a]);
        }
    }
    /*
     * count, how many IDS we have
     */
    for (ser_nr = 0;ip[ser_nr];ser_nr++)
        if (debug)
               WLOG ("%d = %s\n", ser_nr, ip[ser_nr]);

    memset(comma, 0, BUF_HEAD);
    buf = 0;

    if (!strncmp(command, "put", 3)) {
        if ((argc < 3)  || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        if (argc < 4) blad ("brak nazwy pliku\n");
        if (rec) {
            ret = client_put(argv[argc_i], argv[argc_i + 1],ser_nr);
        } else 
            ret = client_put(argv[argc_i], argv[argc_i + 1],1);
        koniec(ret);
    }

    gettimeofday(&cz, NULL);
    if ( (!strncmp(command, "list", 4)) || (!strncmp(command, "rist", 4)) || (!strncmp(command, "lisv", 4)) || (!strncmp(command, "risv", 4))) {
        char *list;
        struct data *ptr;
        int shmid;
        key_t key;
        key = CMIT_SHARED_KEY;
        list = (char *)0;
        /*
         * if share data is defined
         */
        if ((ids_max) && (! force_file)) {
            /*
             * connect to share memory
             */
           shmid = shmget(key, ids_max * sizeof(struct data), 0600);
            if ((shmid) >= 0) {
                if ((ptr = shmat(shmid, NULL, 0)) != (struct data *) -1) {
                    /* 
                     * check is IDS in active mode
                     */
                    if (! ptr->need_check) {
                        uint8_t k = 0;
                        uint8_t verbose = 0;
                        /*
                         * for rist revers directon
                         */
                        if (! strncmp(command, "rist", 4)) k = 1;
                        /*
                         * if verbose ask
                         */ 
                        if (! strncmp(command, "risv", 4)) verbose = 1;
                        if (! strncmp(command, "lisv", 4)) verbose = 1;
                        if (argc < argc_i + 1) {
                            char req[1];
                            /*
                             * 0 to take all data - no filter
                             */
                            req[0] = '\0';

                            list = get_list_meta_data(ptr, req, k, verbose);
                        } else {
                            if (strlen(argv[argc_i]) > NAME_SIZE) blad ("przekroczona dlugosc\n");
                            if (debug) WLOG ("list: searching with: %s\n", argv[argc_i]);
                            list = get_list_meta_data(ptr, argv[argc_i], k, verbose);
                        }
                    } else {
                        if (debug) WLOG("IDS in passive mode: use network for data\n");
                    }
                } else {
                    if (debug) WLOG("error in shmat: %s\n", strerror(errno));
                }
            } else {
                if (debug) WLOG("ERROR IN SHMGET: %s\n", strerror(errno));
            }
        } else {
            if (debug) WLOG ("no objects - no shared memory will be used\n");
        }
         
        if (list) {
            printf ("%s",list);
            free(list);
            
            goto out;
        } else {
            /*
             * ommit first IP, as this should be local IDS
             * when it's no share memory access
             */
            if (! force_file) {
                free(ip[0]);
                ip[0] = 0;
                ser_nr--;
            }
            sprintf(comma, "<rlist/r>");
            if (! strncmp(command, "rist", 4)) sprintf(comma, "<rrist/r>");
            if (! strncmp(command, "risv", 4)) sprintf(comma, "<rrisv/r>");
            if (! strncmp(command, "lisv", 4)) sprintf(comma, "<rlisv/r>");
            if (argc >= argc_i + 1) {
                if (strlen(argv[argc_i]) > NAME_SIZE) blad ("przekroczona dlugosc\n");
                sprintf(comma, "%s<n%s/n>", comma, argv[argc_i]);
            }
            r = 1;       
        }
    }
   
    
    if (!strncmp(command, "info", 4)) {
        if ((argc < (argc_i + 1))  || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rinfo/r><n%s/n>",argv[argc_i]);
        r = 2;
    }

    if (!strncmp(command, "check", 5)) {
        sprintf(comma, "<rcheck/r>");
        r = 2;
    }

    if (!strncmp(command, "cache_info", 10)) {
	int shmid = 0;
	key_t key = CMIT_SHARED_KEY + 2;
	shmid = shmget(key, MAX_IP * sizeof(struct client_cache), 0600);

	if (shmid >= 0) {
		struct client_cache *ptr = 0;
	        struct client_cache *s = 0;

		if ((ptr = shmat(shmid, NULL, 0)) != (struct client_cache *) -1) {
                	int b;

	                for(b = 0; b < MAX_IP; b++) {
                           	s = ptr + b;
				if (! s->ip[0]) break;
				printf ("cache %d: %s last success: %s", b, s->ip, ctime(&s->last_success));
			}
		}
	} else {
                       printf("Error: %s\n", strerror(errno));
        }
        /* TODO: add CMIT_SHARE_KEY + 3 - client cache data */
	goto out;
    }
    if (!strncmp(command, "cache_remove", 12)) {
	int shmid = 0;
        key_t key = CMIT_SHARED_KEY + 2;
        shmid = shmget(key, MAX_IP * sizeof(struct client_cache), 0600);

        if (shmid >= 0) {
		if (shmctl (shmid , IPC_RMID , 0)) {
                	printf("error: %s\n", strerror(errno));
		} else {
			printf("client cache removed\n");
		}
	}
	goto out;
    }
	if (!strncmp(command, "cache_refresh", 13)) {
		refresh_client_cache(ser_nr);
		goto out;
	}
    if (!strncmp(command, "get", 3)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rget/r><n%s/n>",argv[argc_i]);
        r = 1;
    }
    if (!strncmp(command, "gett", 4)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rget/r><n%s/n>",argv[argc_i]);
        r = 1;
    }
     if (!strncmp(command, "delete", 6)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rdelete/r><n%s/n>",argv[argc_i]);
    }
    if (!strncmp(command, "partial", 7)) {
        if (argc < (argc_i + 1)) blad ("brak argumentu pliku\n");
        sprintf(comma, "<rpartial/r><n%s/n>",argv[argc_i]);
    }
    
    if (!strncmp(command, "mkdir", 5)) {
        mode_t mode = 0040755;
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rput/r><n%s/n><u%d/u>",argv[argc_i], mode);
    }
    /*
     * client spart_c argc_i: lfile  argc_i + 1: buf
     */
    if ((!strncmp(command,"spart",5)) ||(!strncmp(command,"spartb",6))) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku glownego lub przekroczona dlugosc\n");
      
        if (argc < (argc_i + 3)) {
            buf = argv[argc_i + 1];
        }     
        /*
         * zaladuj plik glowny
         */
        sprintf(comma, "<radd/r><n%s/n>", argv[argc_i]);
        /*
         * jak sie nie uda zaladowac pliku pomocniczego
         * to "spal" plik glowny
         */
        sprintf(part, "<rpartial/r><n%s/n>", argv[argc_i]);
        /*
         * for spartb try to buffer data
         */
        if (!strncmp(command,"spartb",6)) to_buf = 1;

        // r = 3;
    }

    if (!strncmp(command, "add", 3)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        if (argc < (argc_i + 2)) blad ("brak danych\n");
        sprintf(comma, "<radd/r><n%s/n>",argv[argc_i]);
        buf = argv[argc_i + 1];
    }
    if (!strncmp(command, "touch", 3)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        // if (argc < (argc_i + 2)) blad ("brak danych\n");
        sprintf(comma, "<rtouch/r><n%s/n>",argv[argc_i]);
        // buf = argv[argc_i + 1];
    }
    if (!strncmp(command, "trunc", 5)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rtrunc/r><n%s/n>",argv[argc_i]);
        if (argc == (argc_i + 2))  buf = argv[argc_i + 1];
    }
    if (!strncmp(command, "trune", 5)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rtrune/r><n%s/n>",argv[argc_i]);
        if (argc == (argc_i + 2))  buf = argv[argc_i + 1];
    }
    if (!strncmp(command, "trunz", 5)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rtrunz/r><n%s/n>",argv[argc_i]);
        if (argc == (argc_i + 2))  buf = argv[argc_i + 1];
    }

    if (!strncmp(command, "tail", 4)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak argumentu pliku lub przekroczona dlugosc\n");
        sprintf(comma, "<rtail/r><n%s/n>",argv[argc_i]);
        r = 1;
    }

    if (!strncmp(command, "lput", 4)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak nazwy obiektu w IDS lub przekroczona dlugosc\n");
        if (argc < (argc_i + 2)) blad ("brak nazwy pliku\n");
        sprintf(comma, "<rlput/r><n%s/n>",argv[argc_i]);
        buf = argv[argc_i + 1];
        /*
         * jezeli lput_r
         * to inna sekwencja
         */
        if (rec) rec = 0;
    }
    if (!strncmp(command, "lget", 4)) {
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak nazwy obiektu w IDS lub przekroczona dlugosc\n");
        if (argc < (argc_i + 2)) blad ("brak nazwy pliku\n");
        sprintf(comma, "<rlget/r><n%s/n>",argv[argc_i]);
        buf = argv[argc_i + 1];
        /*
         * jezeli lput_r
         * to inna sekwencja
         */
        if (rec) rec = 0;
    }
    if (!strncmp(command, "quit", 4)) {
        sprintf(comma, "<rquit/r><n%s/n>",argv[argc_i]);
        /*
         * quit tylko lokalnie
         */
        if (rec) rec = 0;

    }
    if (!strncmp(command,"rename",6)) {
        //char nn[NAME_SIZE];
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak nazwy pliku lub przekroczona dlugosc\n");
        if ((argc < (argc_i + 2)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak nowej nazwy pliku lub przekroczona dlugosc\n");

        sprintf(comma, "<rrename/r><n%s/n>",argv[argc_i + 1]);
        buf = argv[argc_i];

    }
	
	if (!strncmp(command,"copy",4)) {
        //char nn[NAME_SIZE];
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak nazwy pliku lub przekroczona dlugosc\n");
        if ((argc < (argc_i + 2)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak nowej nazwy pliku lub przekroczona dlugosc\n");

        sprintf(comma, "<rlink/r><n%s/n>",argv[argc_i + 1]);
        buf = argv[argc_i];

    }
    if (!strncmp(command,"compress",8)) {
        //char nn[NAME_SIZE];
        if ((argc < (argc_i + 1)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak nazwy pliku lub przekroczona dlugosc\n");
        if ((argc < (argc_i + 2)) || (strlen(argv[argc_i]) > NAME_SIZE)) blad ("brak nazwy skompresowanego pliku lub przekroczona dlugosc\n");

        sprintf(comma, "<rcompr/r><n%s/n>",argv[argc_i + 1]);
        buf = argv[argc_i];
    }
    if (strlen(comma)) {
        if (timeout_client) {
            if (debug) WLOG("set timeout to %d cache valid time %d buffer_flush %d\n", timeout_client, cache_valid, buffer_flush);
            signal(SIGALRM, (void *)koniec_alarm);
            alarm (timeout_client);
        }    else {
            if (debug) WLOG("no timeout set\n");
        }
        if (force_file) r = 5;
        sprintf(comma, "%s<v%d.%d/v>", comma, (uint32_t)cz.tv_sec,(uint32_t)cz.tv_usec);
        /*
         * rexc set mean recursive on many IDSes
         */
        if (rec)
            ret = client_request(r,comma,ser_nr, buf, to_buf);
         else
            ret = client_request(r,comma,1, buf, 0);

    } else {
        printf ("Unkown command %s\n", command);
    }

    /*
     * sprawdzenie odpowiedzi
     */
    
    if (debug) WLOG( "ret %d  ser_nr %d\n", ret,  ser_nr);
out:
    koniec();
    return ret;    
}
