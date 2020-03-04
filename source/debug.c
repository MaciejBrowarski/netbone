/*
 * File:   debug.c
 * Author: BROWARSKI
 *
 * Debug client  for meta data IDS
 *
 * Version: 0.2.1 created from client source
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
 * 0.2.0 2011 Nov - list and rist taken locally by shared memor
 * 0.2.1 2012 Jan - create debug
 * 0.2.2 2012 Feb - add rist option
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

#include "common-client.h"

uint16_t ret = 0;


void koniec()
{
    finish_ip(ip);
    exit(ret);
}
void koniec_alarm()
{
    WLOG("TIMEOUT reached - starting\n");
    finish_ip(ip);
    WLOG( "TIMEOUT reached %d\n", timeout_client);
    exit(ret);
 //   koniec();
}
int main(int argc, char** argv)
{

    int shmid, a, s = 0;
    key_t key;
    char cname[50];
    /*
     * pobranie nazwy pliku, ktory nas uruchomil
     * dzieki temu szukamy nazwy pliku konfiguracyjnego
     */
    for(a = 0;a < strlen(argv[0]); a++)
        if (argv[0][a] == '/') { s = a; break; }
    if (a) {
        strncpy(cname, argv[0], a);
        sprintf(cname,"%s%s.cfg",cname, &argv[0][s]);
    } else {
        sprintf(cname,"%s.cfg", argv[0]);
    }

    if (!read_file (cname, ip, 0)) {
        printf("problem z %s\n", cname);
        blad ("blad pobrania serwerow\n");
    }
    if (argc < 2) {
        printf("list - list objects in alphanumeric order\n");
        printf("rist - list objects are ther in memory\n");
        return 0;
    }   
    
    if ((!strncmp(argv[1], "list", 4)) || (!strncmp(argv[1], "rist", 4))) {
        if (ids_max) {
            key = CMIT_SHARED_KEY;
            shmid = shmget(key, ids_max * sizeof(struct data), 0600);
            if ((shmid) >= 0) {
                int k;
                k = 0;
                if (!strncmp(argv[1], "rist", 4)) k = 1;
                if ((ptr_data = shmat(shmid, NULL, 0)) != (struct data *) -1) {
                    uint16_t o;
                    uint32_t mem[4];
                    uint32_t obj[4];
			#if defined __x86_64 || __aarch64__
                    printf("GENERAL: ptr_data %p sizeof %ld max %d OBJECT IN ", ptr_data, sizeof(struct data), ids_max);
			#else
			printf("GENERAL: ptr_data %p sizeof %d max %d OBJECT IN ", ptr_data, sizeof(struct data), ids_max);
			#endif

                    if (k)
                        printf("AS THERE IN MEMORY (no aphanumeric order)\n");
                    else
                        printf(" ALPHA ORDER, NEXT VARIABLE POINT PLACE IN MEMORY\n");

                    for (o = 0;o < 4;o++)
                            mem[o] = obj[o] = 0;

                    if (ptr_data) {
                        struct data *p = ptr_data;
                        uint32_t c;
                        for (c = 0; c < ids_max;c++) {
                            uint8_t d = p->deleted;

                            if ((p->need_check) || (p->name[0] != '/') || (! strlen(p->name))) d = 3;

                            if (d > 3) d = 3;

                            mem[d] += p->size;
                            obj[d]++;
				#ifdef __x86_64
                            printf("%d: del: %d cur %p next %ld lock %d ", c, p->deleted, p, p->next, (int)(p->block).__align) ;
				#else
				printf("%d: del: %d cur %p next %d lock %d ", c, p->deleted, p, (int)p->next, (int)(p->block).__align) ;
				#endif
                            if (p->next) printf ("p_next %p", PTR(p->next));
                            printf("-> name %s size %d create %d data %p\n",
                                     p->name, p->size, p->t_sec, p->buf);
                            if (k) {
                                if (p + 1)
                                    p++;
                                else
                                    break;
                            } else {
                                if (p->next)
                                    p = PTR(p->next);
                                else
                                    break;
                            }
                        }
                    }

                } else {
                    if (debug) WLOG("error in shmat: %s\n", strerror(errno));
                }
            } else {
                if (debug) WLOG("ERROR IN SHMGET: %s\n", strerror(errno));
            }
        } else {
                printf("No IDS variable");
        }
    }
    
    ret = 0;
 
    return ret;    
}
