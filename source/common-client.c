/*
 * common library for clients
 *
 * Version: 5.1
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
 * 4.4 - 2015 May - send_packet and xml_parse as seperate source file
 * 4.5 - 2016 August - back_trace on dedicated file (can't write to WLOG as phtread using own log file)
 * 4.6 - 2016 September - move get_object from datad.c source file
 * 4.7 - 2017 May - don't kill process with pid 0 when it's block shared memory
 * 4.8 - 2017 June - optimatisation for more data
 * 5.0 - 2017 Dec - rewrite client_request (bind UDP port move to client_request_get function becuase not all request require UDP port - mostly it goes via memory cache) 
 * 5.1 - 2018 Mar - optimise get_object + add close before each exit 
 *
 * Copyright by BROWARSKI
 */
#include "common-client.h"
// #define DEBUG_READ_FILE
// #define DEBUG_GET_LIST
// #define DEBUG_GET_LIST_META_DATA

/*
 * global variables
 */
char backtrace_line[4096];

/* 
 * UDP network packet size
 * currently only for sendd
 */
uint32_t net_size = BUF;

pid_t get_object_pid = -1;
struct comm *checker_sh_meta_data;
char *checker_sh_data;

/* we remove all syslog entries
 * as this is not required
 * #ifndef AGENT
* int priority = LOG_ERR | LOG_USER;
* #endif
*/
/*
 * where put pid files
 * for files and sendd
 */
char pid_file[PATH_MAX] = "/tmp/";
char sendd_pid_file[PATH_MAX] = "/tmp";

/*
 * time out for all client action
 * default 120 second, can be overwritten by file paramter TIMEOUT=
 */
uint16_t timeout_client = 120;

/*
 * IDS mode:
 * 0 - passive mode, only ADD command is accept (and GET /)
 * 1 - active all works proper
 */
int ids_mode = 0;

uint16_t ser_nr = 0;
/*
 * CRC for packets
 */
uint8_t net_crc = 0;

uint8_t code_trans = 1;

// int shmid_server;

/*
 * how many objects will be held by IDS
 */
int32_t ids_max = 100000;
/*
 * poczatek kolejki z danymi
 */
struct data *ptr_data = 0;

/*
 * client, cache valid time
 */
unsigned int cache_valid = 10;

uint8_t buffer_flush = 0;

/*
 * critical error for application, exit from program with error
 * Please, use this function only in emergency case, when there are not possiblity to handle error
 * IN:
 * str: ptr to string, which will be printed
 */
int blad(char *str) {
    WLOG("CRITICAL ERROR: %s\n", str);
    
    exit(-1);
}
/*
inline int lock(pthread_mutex_t *mutex, char *name)
{
    int ret;
#ifdef DEBUG_LOCK
    WLOG("BEFORE LOCK: %s\n", name);
#endif
    ret = pthread_mutex_lock(mutex);
    #ifdef DEBUG_LOCK
    WLOG("AFTER LOCK: %s\n", name);
#endif
    return ret;
}

inline int unlock(pthread_mutex_t *mutex, char *name)
{
    int ret;
#ifdef DEBUG_LOCK
    WLOG("BEFORE UNLOCK: %s\n", name);
#endif
    ret = pthread_mutex_unlock(mutex);
 #ifdef DEBUG_LOCK
    WLOG("AFTER UNLOCK: %s\n", name);
#endif
    return ret;
}*/

/*
 * in:
 * char * - function name
 * int - line 
 * ptr - buffer to dump 
 * size - size of buffer
 * n - 0 - dump as is, 1 dump in decimal
 *
 * out:
 * -1 - unable to alloc memory for calculated data
 *  0 - good
 */
int dump_buf(const char *fun, int32_t line, char *buf, size_t size, int s) 
{
	char fname[PATH_MAX];
	int16_t fid, a, ret;
	struct timeval cz;
	pid_t pid = getpid();
	struct tm *czas;

	memset (fname, 0, PATH_MAX);
	
	gettimeofday(&cz, NULL);
	czas = localtime(&cz.tv_sec);
	sprintf(fname, "%s/%s-%d-%d-%04d%02d%02d-%02d%02d%02d.%06u", log_dir, fun, line, pid, czas->tm_year + 1900,czas->tm_mon + 1, czas->tm_mday, czas->tm_hour, czas->tm_min, czas->tm_sec, (uint32_t) cz.tv_usec);

	fid = open(fname, O_WRONLY|O_CREAT|O_TRUNC,0755);
	if (fid < 0) {
		WLOG("unable to create file %s\n", fname);
		goto out1;
	}
#if defined __x86_64 || defined __aarch64__
	WLOG_NB("dump to %s size %ld\n", fname, size);
#else
	WLOG_NB("dump to %s size %d\n", fname, size);
#endif
	/* dump as is */
	if (s == 0) {
		ret = write (fid, buf, size);
		if (! ret) {
                	WLOG("error to write data\n");
		}
	}
	/* convert each byte to integer */
	if (s == 1) {
		for (a = 0; a < size; a++) {
			char data[10];
			memset (data, 0, 10);
			sprintf(data, "%d,", (uint8_t) buf[a]);
			ret = write (fid, data, strlen(data));	
	
			if (! ret) {
				WLOG("error to write data\n");
				goto out;
			}

			if (! ((a + 1) % 30)) {
				ret = write (fid, "\n", 1);
			}
		}
	}
out:
	close (fid);
out1:
	return size;
}


/*
 * free space for IP addresses
 */
int finish_ip(char **ip)
{
    uint16_t a;

   if (debug) WLOG("finish_ip: starting..\n");

    for (a = 0; a < MAX_IP;a++) {
        if (ip[a]) {
            if (debug) WLOG("freeing %d of %d free\n", a, MAX_IP);
            free(ip[a]);
            ip[a] = 0;            
        } else
            break;
    }

    if (debug)   WLOG("DONE\n");

    return 0;
}

/*
 * Wyslanie informacji do klienta
 * IN:
 * str - ciag znakow, ktory chcemy opakowac do wyslania
 * id - id requestu
 * OUT:
 * wskaznik do odpowiedzi
 */
char *xml_return_i(char *str, unsigned int id) {
    char *ret;

    ret = calloc(BUF, sizeof(char));
    if (!ret) blad("parse_err: unable to alloc memory");

    sprintf(ret, "%s<i%d/i>", str, id);

    return ret;
}


/*
 * execute by thread
 */
void call_get_list (struct data_send *s)
{
    /*
     * zaalakowanie portu do wysylki
     */
    int cfd = bind_port();
        if (cfd >= 0) {

            if (s->buf)
                s->ret = send_request(s->comma, s->buf, s->buf_s, cfd, s->ip, 0);
            else
                s->ret = send_request(s->comma, 0, 0, cfd, s->ip,0);

            close(cfd);
        }

}

// int16_t client_request_get(struct comm **res, int Clifd, char *comma, char *buf, uint32_t buf_size, int m, char *ip_l)
int16_t client_request_get(struct comm **res,  char *comma, char *buf, uint32_t buf_size, int m, char *ip_l)

{
        /*
         * global variable:
         * - ip
         */
    int a;
    int16_t ok = 0, ret = 0;
    /*
     * send packet to IDSes
     * if we expect only one answer, don't threads
     */
	if (UNLIKE(debug_client_request_get)) { WLOG_NB("command: %s\n", comma); }

    if (m == 1) {
        /*
         * zaalakowanie portu do wysylki
         */
        int Clifd = bind_port();
        if (Clifd < 0) {
            WLOG("bind UDP failed\n");
            return -1;
        }

        for (a = 0;a < ser_nr;a++) {
            if (! ip_l[a]) continue;
        /*
         * if there any data to send
         */
            if (buf)
                res[a] = send_request(comma, buf, buf_size, Clifd, ip[a], 0);
            else
                res[a] = send_request(comma, 0, 0, Clifd, ip[a], 0);

    //       if (debug) WLOG( "single wyslanie do %s\n", ip[a]);
            /*
            * check answer
            */
            if (res[a]) {
                if (debug) WLOG("odpowiedz %d size name %s\n", res[a]->size, res[a]->command);

                if (strfind(res[a]->command, "- OK") > 0) {  ok = 1; break; }
            }
        }
        close (Clifd);
    } else {
        /*
         * we need more answers, thread each question
         */
        struct data_send **s;
        pthread_t  *th;
        /*
         * alloc dynamic structures
         */
        s = calloc(m, sizeof(struct data_send *));
        if (!s) {
            WLOG( "unable to malloc memory for %d buffers for threads error: %s\n", m, strerror(errno));
            return -1;

        }
        th = calloc(m, sizeof(pthread_t));
        if (!th) {
            WLOG( "unable to malloc memory for %d threads error: %s\n", m, strerror(errno));
            return -1;
        }
        /*
         * create threads
         */
        for (a = 0;(a < ser_nr);a++) {
            if (! ip_l[a]) continue;
            s[a] = calloc(1, sizeof(struct data_send));
            if (!s[a]) {
                WLOG("unable to malloc memory for %d buffers for threads error: %s\n", m, strerror(errno));
                return -1;
            }
            /*
             * fill structure with data - this is need because pthread_create can pass only one argument to function
             * but we need to pass 4 parameters
             */
            s[a]->ip = ip[a];
            s[a]->comma = comma;
		s[a]->buf = 0;
                s[a]->buf_s = 0;

            if (buf) {
		// s[a]->buf = buf;
		/*
		 * we need copy data for each thread
		 * as this is require for code function
		 * this prevent to decode same buffer for each thread
		 */
		s[a]->buf = malloc(buf_size);
		if (s[a]->buf) {
			memcpy(s[a]->buf, buf, buf_size);
                	s[a]->buf_s = buf_size;
		}
	} 
            /*
             * create pthread to send data
             */
            if (pthread_create(&th[a],0,(void *)call_get_list,(void *)s[a])) {
                /*
                 * if failed, write log and continue work
                 * TODO: maybe use some loop to try 5 times to create thread for same IP ?
                 * or use get_list (recursive) ?
                 */
                 WLOG("unable to create %d thread error: %s\n", a, strerror(errno));
                 free(s[a]);
                 s[a] = 0;

            } else {
                if (debug) WLOG("created %d thread send ip: %s\n", a, ip[a]);
            }
        }
        /*
         * now catch answers
         */
        for (a = 0;a < ser_nr;a++) {
            if (! ip_l[a]) continue;
            if (debug) WLOG( "waiting for %d thread\n", a);

            if (pthread_join(th[a], NULL)) {
                WLOG("unable to join to %d thread for exit error: %s\n", a, strerror(errno));
            } else {
                res[a] = s[a]->ret;
                if (res[a]) {
                    if (debug) WLOG("odpowiedz %d size name %s dla %s\n", res[a]->size, res[a]->command, res[a]->name);

                    if (strfind(res[a]->command, "- OK") > 0) {
                        ret++;
                        ok++;
                    }
                } else {
                    if (debug) WLOG("brak odpowiedz dla %d thread\n", a);
                }
            }
		/*
                 * now free all buffers
                 */
                if (s[a]->buf_s) {
                        free(s[a]->buf);  
                }

            free(s[a]);
        }
        /*
         * clear what we alloc
         * for valgrind check as this is only launched by client :)
         */
        if (th) free(th);
        if (s) free(s);
    }
    return ok;
}
/* 
 * try to attach to share memory which has client cache information
 * if segment doesn't exist, create it and initialize
 *
 * out: 
 * ptr to share memory which point to client cache (<0 error for shmat function)
 */
struct client_cache *attach_client_cache()
{
	int init = 0;
	struct client_cache *ptr = (struct client_cache *) 0;

	key_t key = CMIT_SHARED_KEY + 2;
        int shmid = shmget(key, MAX_IP * sizeof(struct client_cache), 0600);

        if ((shmid == -1) && (errno == ENOENT))  {
         	shmid = shmget(key, MAX_IP * sizeof(struct client_cache), IPC_CREAT | 0600);
                if (shmid >= 0) {
                    init = 1;
                } else {
                    WLOG("unable to create shared memory: %s\n", strerror(errno));
                }
	}

        if ((shmid) >= 0) {
                if ((ptr = shmat(shmid, NULL, 0)) != (struct client_cache *) -1) {
			if (init) {
				struct client_cache *s = 0;
				int b = 0;

                        	if (debug) WLOG("new cache, clear memory\n");
		                for(; b < MAX_IP; b++) {
               		        	s = ptr + b;
                       		        s->ip[0] = 0;
                        	}
                    	}

		}
	}
	return ptr;
}
/*
 * update entry in client_chache memory
 *
 * ptr - pointer to share cache memory (return from attach_client_cache)
 * a - idx in ip global array which we need to update
 * at - timestamp to update
 */
inline void update_client_cache( struct client_cache *ptr, int a, time_t at)
{
	uint8_t b, c = 0;
	struct client_cache *s = 0;
	
       	for (b = 0;b < MAX_IP; b++) {
        	s = ptr + b;

                if (! s->ip[b]) break;

                if (! strcmp(s->ip, ip[a])) {
                	if (debug) WLOG("found %s at %d update with: %ld\n", s->ip, b, at);
                        s->last_contact = at;
                        s->last_success = at;
                        c = 1;
                        break;
                }
        }
        /*
         * if not cache entry found
         * create one
         */
        if (! c) {
        	for (b = 0;b < MAX_IP; b++) {
                	s = ptr + b;
                        if (! s->ip[0]) {
                        	memcpy(s->ip, ip[a], strlen(ip[a]));
                                if (debug) WLOG("add to cache at %d: %s\n", b, s->ip);
                                s->last_contact = at;
                                s->last_success = at;
                                break;
                         } else {

                         }
                 }
                 if (b >= MAX_IP) {
                 	if (debug) WLOG("no left free space for new entry\n");
                 }
        }
}
void refresh_client_cache (int m)
{
	time_t at = time(0);
	struct client_cache *ptr = 0;
	int a = 0;

	if (cache_valid) {
		char ip_l[MAX_IP];
		struct comm **res;
		char check[] = "<radd/r><n//n>";

		/*
		 * alloc memory for answers
     		 */
    		res = calloc (ser_nr, sizeof (struct comm *));

		if (!res) {
        		WLOG ("unable to alloc memory for **res\n");
			return;
    		}

		memset(ip_l, 0, MAX_IP);
			
		for (a = 0; a < ser_nr; a++)
        		if (ip[a]) ip_l[a] = 1;

		// ok = client_request_get(res, Clifd, check,  0, m, ip_l);
		client_request_get(res, check,  0, 0, m, ip_l);

        if ((ptr = attach_client_cache()) != (struct client_cache *) -1) {
            if (debug) WLOG("cache at: %p\n", ptr);

            for (a = 0; a < ser_nr; a++) {
				/*
				 * is OK from ping
				 * params to update_client_cache function:
				 * ptr - ptr do cache
				 * a - index in ptr to update
				 * at - time to update
				 */
				 if ((res[a]) && (strfind(res[a]->command, "- OK") > 0))
					update_client_cache(ptr, a, at);
			}
		}

	}
}
/*
 * client_request:
 * send request to IDS
 * IN:
 * r - request type: 1 - print data from response, 2 - print info about objects, 3 - special partial (spart), 4 - print response, 5 - put data to file with IP name 
 * comma - ptr to command to send
 * m - how many servers to send request
 * buf - addtional buffer (e.g. for mkdir folder name), or can be NULL
 * OUT:
 * n - IDS numbers, where request was sent successfully
 *
 * used by:
 * client.c: main
 *
 */
int16_t client_request (uint8_t r, char *comma,int m, char *buf, uint8_t to_buf)
{
    struct comm **res;
    struct client_cache *ptr = 0;
    struct client_cache *s = 0;
    time_t at = 0;
    int a;
    uint16_t ret = 0;
    int16_t  ok = 0;
    char ip_l[MAX_IP];
    char loc_buf[BUF_DATA];
	char command[] = "<rbuffer/r>";
    /*
     * alloc memory for answers
     */
    res = calloc (ser_nr, sizeof (struct comm *));

    if (!res) {
        WLOG ("unable to alloc memory for **res\n");
        ok = -1;
        goto out;
    }
    if (UNLIKE(debug))  {
            WLOG_NB("command %s ilosc serwerow %d request nr %d \n", comma, m, r);
    }
    /*
     * select only active ip
     */
    memset(ip_l, 0, MAX_IP);
    for (a = 0; a < ser_nr; a++)
        if (ip[a]) ip_l[a] = 1;
    /*
     * if this is special partial, check first, how many IDS are accessable
     */	
    if (r == 3) {
        char check[] = "<radd/r><n//n>";   				    
        int b;
        char cache[MAX_IP];
        at = time(0);
        /*
         * check shared memory,
         * if exist, find is previous, younger than 5s, response was successful
         */
        ptr = 0;
        memset(cache, 0, MAX_IP);

        if (cache_valid) {
        	if ((ptr = attach_client_cache()) != (struct client_cache *) -1) {
        		if (debug) WLOG("cache at: %p\n", ptr);
               		for (a = 0; a < ser_nr; a++) {
                        for(b = 0; b < MAX_IP; b++) {
                            s = ptr + b;
                            /*
                             * ip should be at front of cache memory
                             * so, NULL mean no more entries
                             */
			
                            if (! s->ip[b]) break;

                            /* if exist in cache memory */
                            if (! strcmp(s->ip, ip[a])) {
                            // if (debug) WLOG("time (%ld) cache found for: %s:%ld\n", at, s->ip, s->last_success);
                            /* last success was less than 5 seconds */
                                if ((at - cache_valid) < s->last_success) {
                                /* don't ask, sucess */
                                    if (debug) WLOG("cache hit for: %s with %ld\n", s->ip, s->last_success);
                                    cache[a] = 1;
                                    ip_l[a] = 0;
				}
                                   //  continue;
				/*
                                * Not used
                                * TODO: maybe when more tested this will be used
				 *  don't ask, prevent from unsuccessful flood
				else if ((at - cache_valid) < s->last_contact) {
                                    ip_l[a] = 0;
                                }*/
				break;
                            }
                        }
                }
            } else {
                if (debug) WLOG ("error in shmget: %s\n", strerror(errno));
            }
        }
        /*
         * send checks packet to inactive IDSes
         */
        ok = client_request_get(res, check, 0, 0, m, ip_l);
		
    	if (debug)  WLOG("check ret %d\n", ok);
        /*
         * correct ip_l based on above response
         * and cache information
         */
        memset(ip_l, 0, MAX_IP);
        for (a = 0; a < ser_nr; a++) {
            if (debug) WLOG("result for %s cache %d\n", ip[a], cache[a]);
            if (cache[a]) { 
                ip_l[a] = 1;
                /* count + 1 to success IDS */
                ret++;
                /* to speed up, don't check below if statement */
                continue;
            }
            if ((res[a]) && (strfind(res[a]->command, "- OK") > 0)) {
                /* count + 1 to success IDS */
                ret++;
		ip_l[a] = 1;
            }
        }
    } /* end of cache check */

    /*
     * if we have special partial and only one test response
     * then send  set partial command to recipient
     */
    if ((r == 3) && (ok == 1) && (strlen(part))) {    
        ok = client_request_get(res, part, 0, 0, 1, ip_l);
    } else {
	uint32_t buf_size = 0;
        at = time(0);
        /*
         * otherwise send planned command
         */
        /*
         * check is this request ask to buffer this data
         */
        if (buf) buf_size = strlen(buf);

        if ((to_buf) && (buffer_flush)) {
            int seq_nr = 0;
            int init;
            key_t key;
            int shmid;
next_segment:
            /*
             * check is shared buffer is available
             */
            key = CMIT_SHARED_KEY + 10 + seq_nr;
            shmid = shmget(key, sizeof(struct client_cache_buf), 0600);

            init = 0;
            if ((shmid == -1) && (errno == ENOENT))  {
                shmid = shmget(key, sizeof(struct client_cache_buf), IPC_CREAT | 0600);
                if (shmid >= 0) {
                    WLOG ("created segment %d\n", seq_nr);
                    init = 1;
		} else {
                    WLOG ("unable to create share memory for cache: %s\n", strerror(errno));
                }
            }

            if ((shmid) >= 0) {
                struct client_cache_buf *ptr_data;

                if ((ptr_data = shmat(shmid, NULL, 0)) != (struct client_cache_buf *) -1) {
                    int16_t len = 0;
                    int r;
                       /*
                     * if we are first, then clear lock
                     */
                    if (init) {
                        if (debug) WLOG("new buffer cache, clear memory\n");
                        pthread_mutex_init(&ptr_data->lock,NULL);
                    }

                    r = pthread_mutex_trylock(&ptr_data->lock);

                    if (r) {
                        struct timespec abs_time;

                        clock_gettime(CLOCK_REALTIME, &abs_time);
                        if (abs_time.tv_nsec >= 550000000) {
                            abs_time.tv_nsec -= 450000000;
                            abs_time.tv_sec++;
                        } else
                            abs_time.tv_nsec += 440000000;

                        r = pthread_mutex_timedlock (&ptr_data->lock, &abs_time);
			/*
			 * value means error
			 */
                        if (r) {
                            WLOG_NB("TRYLOCK ERROR: error %s locked on %ld\n", strerror(r), ptr_data->data_lock);
                            WLOG_NB("by pid %d - ", ptr_data->pid_lock);
                            if ((ptr_data->pid_lock > 0) && (! kill(ptr_data->pid_lock, 0))) {
                                WLOG_NB("exist ");
                                /*
                                 * if process still exist and locked was done
                                 * 3 times buffer flush then try to kill this process
                                 */
                                if ((buffer_flush) && ((at - (3 * buffer_flush)) > ptr_data->data_lock)) {
                                    if (! kill(ptr_data->pid_lock, 15)) {
                                        WLOG("killed succesfully\n");
                                    } else {
                                        WLOG("killed with error %s\n", strerror(errno));
                                    }
                                } else {
                                    WLOG("to young to kill\n");
                                }
                            } else {
                                /*
                                 * TODO: maybe we should delete this share memory segment
                                 * to make it clear ?
                                 * if this error will be often, then we should do that
                                 */	
				WLOG("non exist, try to re-init\n");
                                 pthread_mutex_init(&ptr_data->lock,NULL);

                            }


                        }
                    }
                    if (! r) {
			/*
			 * check is buffer still valid
			 * so, data_lock isn't to old 
			 */
			if ((ptr_data->data_lock) && (ptr_data->data_lock < (at - (2 * buffer_flush)))) {
				WLOG_NB("data_lock is %ld which is younger that limits: %ld..checking pid %d...\n", ptr_data->data_lock, at - (2 * buffer_flush), ptr_data->pid_lock);
				if (! kill(ptr_data->pid_lock, 0)) {
                                	WLOG("exist ");
				} else {
					WLOG_NB("non exist, so buffer is orphant..cleaning\n");
					init = 1;
				}
			}
                        /*
                         * and clear buffer
                         */
                        if (init) {
                            memset(ptr_data->buf, 0, 5 * BUF_DATA);
                            ptr_data->buf_size = 0;
                        } else {
                            len =  ptr_data->buf_size;
                        }
                            /*
                             * count current size of buffer + size of data to add
                             * if larger than BUF_DATA then we can't add data to buffer
                             * so, send this data immediate without using buffer
                             * +1 - space for offset where data start
                             * we can strlen buf as this is taken from command line
                             * len need to be taken from buf_size as data size is binary digit
                             * <offset where data start><header><data>
                             */
                        if ((len + strlen(buf) + 1) < (5 * BUF_DATA)) {
                            uint8_t off = strlen(comma);
                            sprintf(ptr_data->buf + len, "%c%s%s", off, comma, buf);
                            /*
                             * new size is: old size + size of header + size of data + 1 (ptr to data)
                            */
                            ptr_data->buf_size = len + off + strlen(buf) + 1;
                            pthread_mutex_unlock(&ptr_data->lock);
				/*
				 * first data in buffer
				*/
                            if (! len)    {
				int c;
				uLongf destlen = BUF_DATA;
				struct timespec abs_time;

				 ptr_data->pid_lock = getpid();
                        	 ptr_data->data_lock = at;
                                for (a = 0; a < buffer_flush * 50; a++) {
                                    int16_t s = ptr_data->buf_size;
                                    if ((debug) && (! (a % 5))) WLOG("data in buffer %d\n", s);
                                    if (s > (BUF_DATA * 4)) break;
                                    /*
                                     * lock
                                     * check size and exit
                                     * unlock
                                     */
                                    usleep (10000);
                                }

	                        clock_gettime(CLOCK_REALTIME, &abs_time);
				/*
				 * 1 s. for lock
				 */
                            	abs_time.tv_sec++;

	                        r = pthread_mutex_timedlock (&ptr_data->lock, &abs_time);
				if (! r) {
	                                /*
	                                 * compress data to local buffer
	                                 */
	                                    memset(loc_buf, 0, BUF_DATA);
	                                    /* (where, size where, what, size what, compres ratio) */
					 c = compress2 ((Bytef *)loc_buf, &destlen, (Bytef *)ptr_data->buf, ptr_data->buf_size, 9);
	    				if (c == Z_OK) {
						/*
						 * when compress is good
						 * replace given parameters with compressed one
						 */
						buf_size = destlen;
						buf = loc_buf;
						comma = command;
	                                        if (debug) WLOG("size %d\n", buf_size);
	
					} else {	
						/*
						 * when compress failed
	                                         * write error and send only first line from buffer
	                                         * and clear whole buffer
						 */
	        				if (c == Z_BUF_ERROR)  WLOG("compress buffer error\n");
	        				if (c == Z_MEM_ERROR) WLOG("compress memory\n");
	        				if (c == Z_DATA_ERROR) WLOG("compress input data stream error\n");
					}
	
	                                /*
	                                 * clear shared buffer
	                                 */
	                                memset(ptr_data->buf, 0, 5 * BUF_DATA);
	                                ptr_data->buf_size = 0;
	                                ptr_data->pid_lock = 0;
	                                ptr_data->data_lock = 0;
	                                pthread_mutex_unlock(&ptr_data->lock);
				} else { // if (! r) {
					WLOG("can't again lock buffer to send final data\n");
				}
				

                            } else { /* if (! len) */
                                /*
                                * quit without any send to other IDSes
				* and return success to client (even we just write to buffer)
                                */
				ok = m;
                                    if (debug) WLOG ("add data to buffer owned by %d, quick quit\n", ptr_data->pid_lock);
                                goto out;
                            }
                        } else { // if ((len + strlen(buf) + 1) < (5 * BUF_DATA)) {
                            pthread_mutex_unlock(&ptr_data->lock);
                            if (seq_nr > 6) {
                                WLOG ("reached 6 cache buffer, quit\n");
                            } else {
                               if (UNLIKE(debug))  {         
				#if defined __x86_64 || __aarch64__
                                WLOG("can't add data to current buffer (seq_nr: %d)  current size is %d buffer (we like add %ld) owned by %d created %ld\n", seq_nr, len, strlen(buf), ptr_data->pid_lock, ptr_data->data_lock);
				#else 
				WLOG("can't add data to current buffer (seq_nr: %d)  current size is %d buffer (we like add %d) owned by %d created %ld\n", seq_nr, len, strlen(buf), ptr_data->pid_lock, ptr_data->data_lock);
				#endif
                                }

                                seq_nr++;
                                goto next_segment;
                            }
                        }
                    } /* if (!r) */
                } /* shmat */
            } else  WLOG ("unable to join memory key %d: %s\n", key,strerror(errno)); 
        } /* if (to buf && buffer_flush) */

	
	ok = client_request_get(res, comma,  buf, buf_size, m, ip_l);		
    }
    
    /*
     * zwalnianie pamieci odpowiedzi i wypisywanie zawartosci bufora
     */
    ret = 0;

    for (a = 0;((a < ser_nr) && (ret < m));a++) {
        if (! ip[a]) continue;
        /*
         if there is answer
         */
        if (res[a]) {
                 /*
                  * update cache
                  */
		if (ptr > 0) {
                    /* update cache based on responses */
			update_client_cache(ptr, a, at);
		}
            /*
             * buffer has data
             */
            if ((res[a]->size) && (res[a]->buf)) {
                /*
                 * and there is parameter to
                 * write data
                 */
                if ((r == 1) || (r == 2)) {
                    if ((write(1, res[a]->buf, res[a]->size)) != (res[a]->size))
                        blad("write error\n");
                }
                if (r == 5) {
                    int file;
                    char fname[PATH_MAX];
                    sprintf (fname, "/tmp/%s", ip[a]);
                    file = open (fname, O_WRONLY|O_CREAT|O_TRUNC, 0755);
                    if (file > -1) {
                        write(file, res[a]->buf, res[a]->size);
                        close (file);
                    }
                }
                free(res[a]->buf);
            }
            /*
             * if we ask about meta data
             */
            if (r == 2) {
               printf("ctime=%d,%d\n", res[a]->t_sec, res[a]->t_msec);
               printf("size=%d\n", res[a]->stop);
#ifdef IDS_FOR_FILE
               printf("mode=%d\n", res[a]->mode);
#endif
            }
            if (r == 4) 
               printf("command=%s\n", res[a]->command);
            
            free(res[a]);
            ret++;
        }
    }
    free(res);

out:
    if (debug)  WLOG("ret %d\n", ok);

    return ok;

}
/*
 * out
 * ilosc wyslanych danych
 */
int64_t multiply_put(const char *path, const char *buf, size_t size, off_t offset, int Clifd, char *ip, uint32_t v1, uint32_t v2)
{
    off_t start;
    char comm[BUF_HEAD];
    char buff[BUF_DATA];
    struct comm *res;
#ifdef IDS_FOR_FILE
    uid_t uid = getuid();
    gid_t gid = getgid();
#endif
    start = 0;
  
#ifdef DEBUG_MULTIPLY
#ifdef __x86_64
    sprintf (log_buf,"multiply_put: START write dla %s size %ld offset %ld\n", path, (uint64_t) size, (uint64_t) offset);
#else
    sprintf (log_buf,"multiply_put: START write dla %s size %d offset %d\n", path, (uint32_t) size, (uint32_t)offset);
#endif
    wlog(log_buf);
#endif

   for (;(size - start) > BUF_DATA;start += BUF_DATA) {
       /*
        * jezeli tu jestesmy, tzn. ze mamy wiecej danych do wyslania nich wielkosc pakietu
        */
        memset(comm, 0, BUF_HEAD);
        memset(buff, 0, BUF_DATA);
#ifdef IDS_FOR_FILE
        #ifdef __x86_64
            sprintf(comm, "<rput/r><n%s/n><s%ld/s><e%ld/e><v%d.%d/v><p0 1/p><o%d %d/o>",path, start + offset, start + offset + (off_t)BUF_DATA, v1, v2, uid, gid);
	#else
            sprintf(comm, "<rput/r><n%s/n><s%d/s><e%d/e><v%d.%d/v><p0 1/p><o%d %d/o>",path, (uint32_t)start + (uint32_t) offset, (uint32_t)start +(uint32_t) offset + BUF_DATA, v1, v2, uid, gid);
	#endif
     
#else
        #ifdef __x86_64
            sprintf(comm, "<rput/r><n%s/n><s%ld/s><e%ld/e><v%d.%d/v><p0 1/p>",path, start + offset, start + offset + (off_t)BUF_DATA, v1, v2);
	#else
            sprintf(comm, "<rput/r><n%s/n><s%d/s><e%d/e><v%d.%d/v><p0 1/p>",path, (uint32_t)start + (uint32_t) offset, (uint32_t)start +(uint32_t) offset + BUF_DATA, v1, v2);
	#endif
     
#endif
   #ifdef DEBUG_MULTIPLY
            WLOG( "PART %s\n", comm);
        #endif
        /*
         * skopiowanie danych do naglowka
         */
        memcpy(buff, buf + start, BUF_DATA);
        /*
         * wyslanie
         */
        res = get_list(comm, buff, BUF_DATA, Clifd, ip);
        if (!res) return -1;
        /*
         * porzadki z pamiecia
         */
        FREE_GET_LIST(res);
   }
   /*
    * wyczyszczenie buforow
    */
    memset(comm, 0, BUF_HEAD);
    memset(buff, 0, BUF_DATA);

    /*
     * i wyslanie ostatniego PUTa
     */
#ifdef IDS_FOR_FILE
    #ifdef __x86_64
        sprintf(comm, "<rput/r><n%s/n><s%ld/s><e%ld/e><v%d.%d/v><o %d %d/o>",path, (uint64_t) start + (uint64_t) offset, (uint64_t) size + (uint64_t) offset, v1,v2, uid, gid);
    #else
        sprintf(comm, "<rput/r><n%s/n><s%d/s><e%d/e><v%d.%d/v><o %d %d/o>",path, (uint32_t)start + (uint32_t)offset,(uint32_t)size + (uint32_t)offset,v1,v2, uid, gid);
    #endif        
#else
    #ifdef __x86_64
        sprintf(comm, "<rput/r><n%s/n><s%ld/s><e%ld/e><v%d.%d/v>",path, (uint64_t) start + (uint64_t) offset, (uint64_t) size + (uint64_t) offset, v1,v2);
    #else
        sprintf(comm, "<rput/r><n%s/n><s%d/s><e%d/e><v%d.%d/v>",path, (uint32_t)start + (uint32_t)offset,(uint32_t)size + (uint32_t)offset,v1,v2);
    #endif
#endif
    #ifdef DEBUG_MULTIPLY
            WLOG("LAST %s\n", comm);
        #endif
    memcpy(buff, buf + start, size - start);
    res = get_list(comm, buff, size - start, Clifd, ip);
        #ifdef DEBUG_MULTIPLY
            WLOG("odpowiedz %p zwalnianie pamieci\n", res);
        #endif
    if (res) {
        FREE_GET_LIST(res);
        return size;
  }
  return -1;
}
/*
 * ptr - ptr to meta_data structure
 * name - narrow list to this name (for list, from left side, for rist, from right side)
 * sf - direction, sf - 0 - left side (LIST) , 1 - right side (RIST)
 * verbose - 0 - pure list, 1 - with size and version
 * OUT:
 * ptr - buffer with data (IT'S NEEDS TO FREE AFTER USE)
 *
 */
char *get_list_meta_data(struct data *ptr, char *name, int sf, int8_t verbose)
{
    char **blist;
    uint32_t size = 0;
    uint32_t p;
    char *list;
    /*
     * omit first element
     */
    struct data *c;
   uint32_t lname = strlen(name);
    uint64_t i, j;
    
    if (! ptr) return 0;
    if (ptr->next) 
        c = ptr + ptr->next;
    else
        return 0;
    
    blist = calloc(1, sizeof(char *));
    if (!blist) blad("list: unable to calloc memory");
    #ifdef DEBUG_GET_LIST_META_DATA
    WLOG("args %d >%s<\n", (int)strlen(name), name);
    WLOG("0 ptr %p next %p list %p\n", ptr, c,  blist);
    WLOG("0->name %s 1->name %s\n", ptr->name, c->name);
    
#endif
     for(i = 0;;) {
        /*
         * lname - size of request taken from client
         * slen - size of objects name
         */
     
        uint32_t slen = strlen(c->name);
        if (UNLIKE(debug_get_list_meta_data)) WLOG_NB("sf %d size %d name %s deleted %d searching name >%s< lname %d\n", sf, size, c->name, c->deleted, name, lname);
        /*
         * we list only completed object
         */
        if ((!c->deleted) && (!c->need_check) &&
                // request name are smaller than searching name
                (slen > lname) &&
                ( // and
                // request name are equal to searching name on length of left side of request name or
                ((sf == 0) && (!strncmp(name, c->name,lname))) ||
                // request name are equal to searching name on length of right side of request name
                ((sf == 1) && (!strncmp(name, c->name + slen - lname,lname)))
                )) {
            int32_t s = slen;
            uint8_t jest;
            /*
             * if we search subcatalog for list
             */
            if (!sf) {
                s = -1;
                if (lname > 0) {
                    /*
                   * check if request->name end with /
                     * if yes, add +1
                     */
                    #ifdef DEBUG_GET_LIST_META_DATA
                    WLOG("lname %d znak %c \n", lname, name[lname - 1]);
                    #endif
                    /*
                     * if this from FUSE client or Native client with lists arguments
                     */
                    s = strfind (c->name + lname,"/");
                }
                if (s == -1)
                // size to copy is all string
                    s = slen - lname;
            }

            #ifdef DEBUG_GET_LIST_META_DATA
                WLOG("s %d lname %d\n", s, lname);
                WLOG("after counting strlen c->name %d s %d\n", slen, s);
                #endif
                /*
                 *  check, if we can this element already
                 */
                jest = 0;
                for(j = 0; j < i; j++) {
                    /*
                     * same size and same name
                     */
                     if ((strlen(blist[j]) == s) &&  (!strncmp(blist[j], c->name + lname,s))) {
                        jest = 1;
                        break;
                    }
                }
            /*
             * we haven't this element
             */
            if (!jest) {
                /*
                *   alloc new array, copy data, realloc our list and push to top of blist
                */
                char *new;
                /*
                 * s with tail (e.g. for verbose data
                 */
                uint32_t ss = s;
                /*
                 * +1 trail space
                 * addtion 50 bytes for size + version
                 */ 
                if (verbose) {
                    ss += 51;
                } else {
                    ss += 1;
                }

                new = malloc(ss);
                if (!new) blad("get_list_meta_data: unable to calloc new\n");

                memset(new, 0, ss);

                if (!sf)
                    memcpy(new, c->name + lname,s);
                else
                    memcpy(new, c->name,s);

                if (verbose) {
                    sprintf(new, "%s <s%d/s><v%d.%d/v>", new, c->size, c->t_sec, c->t_msec);
                }
                blist[i] = new;
                blist = realloc(blist, (i + 2) * sizeof(char *));
                if (!blist) blad("get_list_meta_data: unable to realloc list\n");

                #ifdef DEBUG_GET_LIST_META_DATA
                WLOG("new %s\n", new);
                #endif
                size += ss;
                i++;
            }
        }
        /*
         * try search next elements
         */
        if (!c->next) break;
        c = ptr + c->next;
    }
    if (UNLIKE(debug_get_list_meta_data)) { 
        WLOG_NB("after gathering data\nsize %d\n",size);
    }
    /*
     * malloc memory for whole data
     * free at bottom function
     */
    list = malloc (size + 1);

    if (!list) {
        size = 0;
        WLOG(": unable to malloc memory for list\n");
    }
    memset(list, 0, size + 1); 

    p = 0;
        /*
         * copy each array to linear memory
         */
    for (j = 0; j < i;j++) {
        uint32_t k;
        /*
         * what for this if?
         */
        if (size) {
            k = strlen(blist[j]);
         //   #ifdef DEBUG_GET_LIST_META_DATA
         //   WLOG( "request_list: copy i %ld k %d str %s\n", i, k, blist[j]);
         //   #endif
            memcpy(list + p, blist[j], k);
            p += (k + 1);
            list[p - 1] = '\n';
        }
        free(blist[j]);
    }
    free(blist);
        
    return list;
}

struct data *OFF_TO_PTR(off_t x) {
    if (x)
        return ptr_data + x;
    else
        return 0;
}

char *back_trace_line (const char *func)
{
	void *stack[SIZE];
    char **str;
    int i;
    int frames = backtrace (stack, SIZE);
    str = backtrace_symbols (stack, frames);
	memset(backtrace_line, 0, 4096);
	sprintf(backtrace_line, "START %d frames ", frames); 
    for (i = 0; i < frames; ++i) { 
        sprintf(backtrace_line, "%s -> %s\n", backtrace_line, str[i]); 
    } 
	sprintf(backtrace_line, "%s %s ", backtrace_line, func);
    free(str);
	return backtrace_line;
}
/*
 * back stack size
 */
#define SIZE 1024


void back_trace ()
{
    void *stack[SIZE];
    char **str;
    char fname[100];
    int i;
    int frames = backtrace (stack, SIZE);
	/*
	 * can't use WLOG family, as we should write as soon as possible without 
	 * using any victims (even WLOG - which can malloc memory and block to stop)
	 */

	sprintf (fname, "/tmp/backtrace-%d", getpid());

    int16_t fid = open(fname, O_WRONLY|O_CREAT|O_TRUNC,0755);
    char logb[SIZE];

	sprintf(logb, "debug line: %s\n", log_buf_debug);
	write(fid, logb, strlen(logb));

    sprintf(logb, "%d addresses on stack\n", frames);
	write(fid, logb, strlen(logb));

    str = backtrace_symbols (stack, frames);

    for (i = 0; i < frames; ++i) { 
        sprintf(logb, "%s\n", str[i]); 
	write(fid, logb, strlen(logb));
    } 
    free(str);
    close(fid);
	exit(EXIT_FAILURE);
}


/*
 * generated, based on argv[0] (which should be provided by ptr *a)
 * configuration file
 *
 * used by:
 * filec -> cfg/filec.cfg
 * idscron -> cfg/idscron.cfg
 *
 * out:
 * 0 - good
 * 1- bad
 */
int get_cfg_filename(char *base, char *cfg) 
{
        /*
         * is base begin as full path
         */
         if (base[0] == '/') {
                char *a;
		// add cfg on end
                sprintf(cfg,"%s.cfg", base);
		// rename bin with cfg
                a = strstr(cfg, "bin");
                if (a) {
                        a[0] = 'c';
                        a[1] = 'f';
                        a[2] = 'g';
			return 0;
                }
        } else {
        /*
         * exeute without absolute path, use default location
         */
		int a;
		for(a =  strlen(base); a> 0; a--)
        	        if (base[a] == '/') {  break; }
		a++;
		if (! strncmp (&base[a], "filec", 5)) {
        		sprintf (cfg, "%s/get/netbone/cfg/filec.cfg", getenv("HOME"));
			return 0;
		}
		if (! strncmp (&base[a], "idscron", 7)) {
                        sprintf (cfg, "%s/get/idscron/cfg/idscron.ids", getenv("HOME"));
			return 0;
                }	
        }
/*
 * old fasion
 *        strncpy(cname, argv[0], a);
 *       sprintf(cname,"%s%s.cfg",cname, &argv[0][s]);
 */
	return 1;
}

void get_object_timeout() {
        /*
         * can't use any WLOG functions, as it is asynchronise 
         * so, it can block exit from this
         * TODO: how to inform user that timeout occur?
         */
     //   WLOG_FAST("timeout\n");
            exit(1);
}


/*
 * DESC:
 * function download object from remote
 * depend on size use UDP or TCP protocol
 *
 * in:
 * comm - command to download  (with <r ... /r><n../n> parameter list )
 * size - size object to download
 * sockfd - current UDP connection
 * ip - IP address to connect
 * 
 * out:
 * 0 - unable to download object
 * 1 - share memory has valid data
 */
int get_object(char *comm, uint32_t size, int sockfd, char *ip)
{
    /*
     * status for return code for waitpid
     */
    int status = 0;

    /*
     * check size is fit to share memory buffer
     */
    if (size > DATA_MAX) {
        WLOG("%s size %d greater than %d, skipping...\n", comm, DATA_MAX,size);
        return 0;
    }
    memset (checker_sh_meta_data, 0, sizeof(struct comm));
    memset(checker_sh_data, 0, DATA_MAX);

    /*
     * candidate for separate function
     * e.g. for client to get data by TCP
     */

    if (UNLIKE(debug_get_object)) {
        WLOG_NB("comm %s size %d\n", comm, size);
    }
     /*
      * Pobranie nowych danych GET przez fork()
      * aby pozbyc sie memory leak w send_request
      * jak sa problemy (lepiej fork niz pthread, bo pozniej trzeba
      * szukac, to co nasmiecil pthread, a tak system sam sprzata
      * po fork
      */

    get_object_pid = fork();
    
    if (get_object_pid < 0) {
        WLOG("fork error: %s\n", strerror(errno));
        return 0;
    }
/*
 * child
 */	
    if (! get_object_pid) {
        /*
         * initialize logging
         */
        fidlog = -1;
        pthread_mutex_init(&wlog_lock, NULL);
        /*
         * detach from current session
         * (sometimes this fork receive SIGKILL which terminate whole files process)
         * TODO: try to find this SIGKILL source. (it's kernel - memory killer...:( )
         */

        setsid();
        /*
         * set alarm for process
         */	
        signal(SIGALRM, (void *)get_object_timeout);
        alarm (timeout_client);

        if (UNLIKE(debug_get_object)) {
            WLOG_NB("comm %s timeout %d\n", comm, timeout_client);
        }
        /*
         * less than 23kB use UDP
         * size doesn't know and bigger then TCP
         */
        if ((size > 0) && (size < (10 * BUF_DATA))) { 
            struct comm *ret;
            ret = send_request(comm, 0, 0, sockfd, ip, checker_sh_data);

		    if (UNLIKE(debug_get_object)) {
			    if (ret) {
				    WLOG_NB("UDP good is %d\n", ret->good);
			    } else {
				    WLOG_NB("UDP ret is 0\n");
			    }
		    }
		    if ((ret) && (ret->good)) {
				/*
				 * calculate CRC for whole packet
				 * which is checked by checker
				 */
				if (net_crc) {
					ret->crc = calc_crc(checker_sh_data, ret->size);

                    if (UNLIKE(debug_get_object)) {
                       WLOG_NB("UDP CRC is %d\n", ret->crc);
                    }
				}
                /*
                 * copy meta data to share
                 */

                memcpy(checker_sh_meta_data, ret, sizeof(struct comm));

            	exit (0);
        	}

		    WLOG_NB("UDP - ret or ret->good not positive\n");
		    exit(1);

        } else {
	        /*
	         * TCP
	         */
            struct sockaddr_in sad;
            int sd; // socket
		int r; // return value 
		int  j = 0, k = 0; /* j for count timout, k for read 0 size data */
            int32_t i = 0, ret_s = 0;
            char buf[65570];
            char *data_buf;
            struct comm *ret;
            ret = calloc(1, sizeof(struct comm));

            if (! ret) {
               WLOG_NB("alloc error\n");
               exit(1);
            }

            struct sockaddr_in null_ad;

            memset((char *) & null_ad, 0, sizeof (null_ad)); /* clear sockaddr structure   */

            memset((char *) & sad, 0, sizeof (sad));
            /*
             * create local buffer for data
             */
            data_buf = malloc(DATA_MAX);
            if (! data_buf) {
                WLOG("unable to alloc memory for buffer\n");
                exit(1);
            }
            memset(data_buf, 0, DATA_MAX);

            if((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                WLOG_NB("socket error: %s\n", strerror(errno));
                exit (1);
            }
            sad.sin_family = AF_INET;
            sad.sin_port = htons(start_port);
            sad.sin_addr.s_addr = inet_addr(ip);

            if (UNLIKE(debug_get_object)) {
                WLOG_NB("before connect to %s:%d\n", ip, start_port);
            }

            if (connect(sd, (struct sockaddr *) &sad, sizeof(sad)) < 0) {
                WLOG_NB("connect error to %s:%d : %s\n", ip, start_port, strerror(errno));
                exit(1);
            }

            if (UNLIKE(debug_get_object)) {
                WLOG_NB("TCP connected\n");
            }
		    /*
		     * send request
		    */
            r = send_packet(comm, 0, 0, sd, null_ad);
		if (UNLIKE(debug_get_object)) {
                WLOG_NB("send_packet return %d\n",r);
            }
		if (r < 1) {
			WLOG_NB("send packet return %d\n", r);
			close(sd);
			exit (1);

		}	
            for (i = 0;;i++) {
                fd_set rs;
                struct timeval czas;
                int re;

		        memset(buf, 0, 65570);
                FD_ZERO(&rs);
                FD_SET(sd, &rs);
                czas.tv_sec = 1;
                czas.tv_usec = 0;

                re = select (sd + 1, &rs, NULL, NULL, &czas);
                if (re < 0) {
                    WLOG_NB("select error: %s\n", strerror(errno));
			close(sd);
                    exit(1);
                }
                /* timeout */
                if (re == 0) {
                    if (j++ > 2) {
                        if (UNLIKE(debug_get_object)) {
                            WLOG_NB("3 times timeout without data for %s:%d...exiting\n", ip, start_port);
                        }
			            close(sd);
                        exit(1);
                    }
                    continue;
                }
                /* 
		         * r > 0 mean, data waiting for us,
		         * so, get data from socket
		         */
                r = read(sd, buf, 65535);
                
                if (r < 0) {
                    WLOG_NB("error read socket from %s:%d...exiting: %s\n", ip, start_port, strerror(errno));
			close(sd);
                    exit (1);
                }
		        if (UNLIKE(debug_get_object)) {
                    WLOG_NB("i %d read %d size %d\n", i, r, ret_s);
		        }
		        /*
		         * that is last packet, so we can encode it and exit from this process
		         */
                if (! r)  {
			if (ret_s) {
				    /* now packet is good */
				    if (ret_s >= size) {
						/*
                         * parse header
                         * (xml_parse_buf copy internally data to dest buffer)
		         		 */

                        if (! xml_parse_buf(data_buf, ret, ret_s, checker_sh_data, DATA_MAX)) {
                            WLOG_NB("error in xml_parse_buf for comm %s size %d (size in request %d) from %s:%d\n", comm, size, ret->good, ip, start_port);
                            ret->good = 0;
				close(sd);
                            exit (1);
                        }

			    		/*
						 * count CRC for data
						 */
						if (net_crc) {
							uint32_t rc = calc_crc(checker_sh_data, ret->size);
		
							if (UNLIKE(debug_get_object)) {
								WLOG_NB("CRC count: crc from packet %x crc counted %x size: %d\n", ret->crc, rc, ret->size);
							}
							/*
							 * if CRC is diffrent, then we should drop packet
							 */	
							if (ret->crc != rc) {
		               	        ret->good = 0;
					close(sd);
		                        exit(1);	
							}
						}
                        ret->good = 1;

                        memcpy(checker_sh_meta_data, ret, sizeof(struct comm));
				close(sd);
		                exit(0);
	               } 
	                /*
	                 * smaller object not accepted
	                 */
		            WLOG_NB("Warning: for %s req size is %d but ret->size is %d ret->good %d\n", comm, size, ret_s, ret->good);
				close(sd);
				    exit(1);
		        } else {
				if (k++ > 30) {
                        WLOG_NB("read 0 data, waited  3s without success for %s:%d...exiting\n", ip, start_port);
			close(sd);
                        exit(1);
                    }
				usleep (100000);
			}
		}
                if (r) {
	              /* 
	               * ret_s is buffer size 
	               */
	                if ((ret_s + r) > DATA_MAX) {
	                    WLOG_NB("download size %d greater than buffer size %d, skipping...\n", ret->size + r, DATA_MAX);
				close(sd);
	                    exit (1);
	                }
	                /* copy current data to big buffer */
	                memcpy (data_buf + ret_s, buf, r);
	
	                ret_s += r;
                }
            } /* for (i = 0;;i++) */
		/* 
		 * this point shouldn't be reached as 'positive' flow exit in if (! r) statement 
		 */
		close(sd);
        } /*if ( size < ...) end of UDP/TCP transmission */

	    WLOG_NB("exit...shouldn't be reached\n");
	    exit(1);
    } /* if (! checker_pid) - END OF CHILD */

    if (UNLIKE(debug_get_object)) {
        WLOG_NB("pid %d created\n", get_object_pid);
	}
	/*
	 * wait for process
	 */
again_wait:
    waitpid(get_object_pid, &status, 0);
    /*
     *  check if PID stil exist
     */
    if (! kill (get_object_pid,0)) {
        goto again_wait;        
    }
    /*
     * back to default (global variable) as no proccess is running
     */


    if (UNLIKE(debug_get_object)) {
        WLOG_NB("pid %d finished with %d status %d raw status %d\n", get_object_pid, WIFEXITED(status), WEXITSTATUS(status), status);
        if (checker_sh_meta_data->crc) {
            WLOG_NB("CRC w pakiecie %d\n", checker_sh_meta_data->crc);
        }
    }

    if ((WIFEXITED(status)) && (WEXITSTATUS(status) == 0) && (checker_sh_meta_data->good)) {
            get_object_pid = -1;
         return 1;
    }

	WLOG("pid %d finished with %d status %d\n", get_object_pid, WIFEXITED(status), WEXITSTATUS(status));
	if (! WEXITSTATUS(status)) { 
            WLOG_NB("good return %d\n", checker_sh_meta_data->good); 
    }
	get_object_pid = -1;
	return 0;
}

