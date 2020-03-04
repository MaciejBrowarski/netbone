/* 
 * SendD - Send Deamon
 * 
 * File:   sendd.c
 * Author: BROWARSKI
 *
 * Version: 4.1
 *
 * History: 
 * 
 * 0.2 2011 December - move send* functions to seprate process
 * 0.3 2013 January - add time limit to send_name_version to limit amount of files
 * 4.0 2014 November - code transmision
 * 4.1 2016 August - remove fork, ow this process is controlled by pthread from files
 */

// #define DEBUG_SEND_NAME_VERSION
#define DEBUG_SEND_NAME_VERSION_SEND
// #define CODE_DUMP

#include "common.h"

int client_Sockfd = 0;
/*
 * size of send packet
 */
int buf_out_size;

pthread_mutex_t s_lock;

struct send_version_comp {
    int size;
    time_t czas;
} sv_packet;


void send_name_version_send(char *);
/*
 * funkcja wysyla do zarejstrowanych serwerow informacje o posiadanych danych i ich wersjach
 * 
 * in:
 * n - 0 - no limit, >0 - newer object than n seconds
 * out:
 * NULL
 */

void send_name_version (uint32_t time_limit)
{
    int j = 0;
    struct data *cur;
	// for debug 
    u_int16_t i_0 = 0, i_1 = 0;

    char res[COMP_PACKET * BUF]; 

if (  pthread_mutex_trylock(&s_lock)) {	
	WLOG("can't do lock - skip\n");
	sleep (30);
	return;
	}

     /*
      * czy mamy jakies dane (oprocz pierwszego, ktory reprezentuje dane wewnetrzne
      */
     if (ptr_data->next) {
	uint32_t cur_time = time(0);
	/* limit for partial files */
         uint32_t b_time = cur_time - 86400; 
         cur = PTR (ptr_data->next);

        for (j = 0;cur ;cur = OFF_TO_PTR(cur->next)) {
            /*
             * j = 0 oznacza, ze trzeba wyczyscic pakiet z danymi
             * utworzenie kolejnego pakietu do wyslania
             */
            if (!j) {
                memset(res, 0, COMP_PACKET * BUF);
                /*
                 * first line is timestamp of whole package
                 */
                sprintf(res, "<n>/</n><v>%d.0</v><d>0</d><s>0</s>", cur_time);
                if (UNLIKE(debug_sendd_name_version)) { 
                	WLOG("add name %s (%p) size %d\n",cur->name, cur, (int)strlen(cur->name)) ;
		}
            }
            /*
             * jezeli nazwa danych nie jest pusta (jest to zabezpieczenie przed blednym wpisem)
		* jest juz sprawdzony
             * i objekt jest caly lub skasowany
		* a czesciowy to tylko z ostatni 24h
		* i jezeli jest ustawiony zakres czasowy, to tylko obiekty zmienione do timelimit
             */
            if (((strlen(cur->name))  && (cur->need_check == 0)) &&
                    ((cur->deleted == 0) || ((cur->deleted == 1) || (cur->t_sec > b_time))) &&
		((! time_limit) || (cur->t_sec > cur_time - time_limit))) {
                /*
                * l_res - size of packet
                */           
                uint16_t l_res = 0;
                /*
                * utworzenie linii nt. danej nazwy
                */
		if (UNLIKE(debug_sendd_name_version)) {
	                if (cur->deleted == 0) i_0++;
       	        	if (cur->deleted == 1) i_1++;
		}

                sprintf(res, "%s\n<n>%s</n><v>%d.%d</v><d>%d</d><s>%d</s>", res, cur->name, cur->t_sec, cur->t_msec, cur->deleted, cur->size);
		/*
		 * print name which is triggered by signal
		 */
     		if (time_limit == 121) {
                   WLOG_NB("name: %s\n", cur->name);
                }
                /*
                * ile juz mamy zajete w pakiecie
                */
                l_res = strlen(res);
        
                /*
                * czy jeszcze jest miejsce w tym pakiecie na nastepne linie
                */
                if ((l_res +  1) > (BUF_DATA * sv_packet.size)) {
                    /*
                     to wyslanie danych
                     */
                    send_name_version_send(res);
                /*
                 * sprawdzenie czy w nastepnych danych sa jakies dane
                 * i trzeba budowac nastepny pakiet
                 */
                    j = 0;
                    if (cur->next) {                    
                        continue;
                        /*
                        * to byla ostatnia linia i nie ma potrzeby budowac kolejnego pakietu
                        */
                        
                    } else break;                
                }
            }
            j++;
        }
    } else {
         /*
          * jezeli nic nie ma, to wyslanie pustego pakietu
          */
        memset (res,0, BUF);
        sprintf(res, "<n></n><v></v><s></s>\n");    
    }
     if (j)  send_name_version_send(res);
	if (UNLIKE(debug_sendd_name_version)) {
		WLOG(" time_limit %d good %d deleted %d \n", time_limit, i_0, i_1);
	}

	pthread_mutex_unlock(&s_lock);
}

void send_name_version_send(char *res)
{
    int alen = sizeof (struct sockaddr);
    /*
      * wyslanie wszystkich pakietow
      */
    time_t t = time(0);
    uLongf buf_s;
    char buf[COMP_PACKET * BUF];
    int c;     

    memset(buf, 0, COMP_PACKET * BUF);

    buf_s = COMP_PACKET * BUF;
    c = compress2 ((Bytef *)buf,  &buf_s, (Bytef *)res, strlen(res), 9);

    if (c != Z_OK) {
        if (c == Z_BUF_ERROR)  WLOG("compress buffer error\n");
        if (c == Z_MEM_ERROR) WLOG("compress memory\n");
        if (c == Z_DATA_ERROR) WLOG("compress input data stream error\n");
        goto out;
      }
	#ifdef CODE_DUMP
    DUMP_BUF_DEC(buf, buf_s);
    #endif

	if (code_trans) {
        code_decode(buf, buf_s);
    }
    #ifdef CODE_DUMP
    DUMP_BUF_DEC(buf, buf_s);
    #endif

    if ((buf_s) && (buf_s <= net_size)) {
        struct client *s;
        uint16_t i = 0;
        for (;i < MAX_IP; i++) {
            s = ptr_client + i;          
            if (s->czas) {
		int n;
            if (UNLIKE(debug_sendd_name_version)) {
                WLOG_NB("%d before compress %ld sending %ld to %s:%d\n", i, (long int)strlen(res), (long int)buf_s, inet_ntoa(s->client.sin_addr), ntohs(s->client.sin_port));
            }

                n = sendto(client_Sockfd, buf, buf_s, 0, (struct sockaddr *) & s->client, alen);
            }
            /*
             * TODO: check n !!
             */
        }
                /*
                 * if this is first packet, and last change was 10 minutes ago and
                 * compressed packet is smaller that 1000bytes
                 * try to increase compres
                 */
        if ((sv_packet.size < (COMP_PACKET - 1)) && (t > (sv_packet.czas + (10 * TIMEOUT))) && (buf_s < ((BUF * 2) / 3))) {
            sv_packet.size++;
            sv_packet.czas = t;
            #ifdef DEBUG_SEND_NAME_VERSION_SEND
            WLOG("increase packet to %d\n", sv_packet.size);
            #endif
        }
    } else {
      //  if ((t > (sv_packet.czas + TIMEOUT)) && (sv_packet.size > 1)) {
        if (sv_packet.size > 1) { /* less restriction to go down */
            sv_packet.size--;
            sv_packet.czas = t;
        }

        if (!sv_packet.czas) sv_packet.czas = t;

	    if (UNLIKE(debug_sendd_name_version)) {
        	WLOG_NB("Error: packet exceed packet size %d (has %ld) current var_comp_packet %d\n", net_size, buf_s, sv_packet.size);
	    }
    }

out:
    return;
}

int main_loop()
{
    key_t key = CMIT_SHARED_KEY;
    int shmid;
    unsigned int alen;
    int n;

    struct sockaddr_in sad; /* structure to hold server's address  */

    client_Sockfd = socket(PF_INET, SOCK_DGRAM, 0); /* CREATE SOCKET */

    if (client_Sockfd < 0) blad("main_loop: socket creation failed\n");

    memset((char *) & sad, 0, sizeof (sad)); /* clear sockaddr structure   */
    sad.sin_family = AF_INET; /* set family to Internet     */

    sad.sin_addr.s_addr = start_ip; /* set the local IP address   */

    sad.sin_port = htons((u_short) start_port + 2); /* set the port number        */
    for (;;) {
        if (bind(client_Sockfd, (struct sockaddr *) & sad, sizeof (sad)) < 0) {
            WLOG_NB("bind failed to %d port with error: %s\n", start_port + 2, strerror(errno));
            sleep (2);
            continue;
        }
        break;
    }
    alen = sizeof (struct sockaddr);
    /*
     * initialize compression
     */
    sv_packet.size = COMP_PACKET;
    /*
     * attach to shared IDS memories
     */
    shmid = shmget(key, ids_max * sizeof(struct data), IPC_CREAT | 0644);
    if (shmid < 0) {
        WLOG("error to create shared memory: %s\n", strerror(errno));
        return 0;
    }
    ptr_data = shmat(shmid, NULL, 0);

    if (ptr_data == (void *) -1) {
        WLOG("error to attach shared memory: %s\n", strerror(errno));
        return 0;
    }
    
    shmid = shmget(key + 1, MAX_IP * sizeof(struct client), IPC_CREAT | 0644);
    if (shmid < 0) {
        WLOG("error to create shared memory: %s\n", strerror(errno));
        return 0;
    }
    ptr_client = shmat(shmid, NULL, 0);

    if (ptr_client == (void *) -1) {
        WLOG("error to attach shared memory: %s\n", strerror(errno));
        return 0;
    }
	/*
	 * send, in regular time, our objects
	*/
    for(n = 0;;n++) {
	
	if (n == 5) {
        	send_name_version(0);
		n = 0;
	} else {
		 send_name_version(120);
	}
	/*
	 * sleep for 30 seconds
	 * when signal occur, then start counter again from 30 seconds
	 * this is to prevent make a flood from us
	 */
        for (;sleep (21););
    }
	return 0;
}
void send_name_version_sig() {
	WLOG_NB("signal: execute on\n");
	send_name_version(121);
	return;
}
int main(int argc, char** argv) {
    int i, f; 

    if (argc < 2) {
        printf("Missing configuration file\n");
        return -2;
    }
   if (strlen(argv[1]) >  NAME_SIZE) {
            printf("cfg filename  to long, exceed %d chars\n", NAME_SIZE);
            return -1;
    } else {
           memcpy(cfg_file, argv[1], strlen(argv[1]));
    }
    
    start_port = 0;

    ip[0] = 0;

    if (!read_file(argv[1], ip, 0)) {
        printf("main_loop: unable to open file %s\n", argv[1]);
        return -3;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    /*
     * Control - C save exit
     */
   
     signal(SIGUSR1, (void *)send_name_version_sig);
     i = strlen(argv[0]);

     for (;i > 0;i--) 
        if (argv[0][i] == '/') break;
        
     sprintf(pid_file, "%s/%s.pid", pid_file, &argv[0][i]);
        
     f = creat(pid_file, 0755);
     if (f != -1) {
        char n[20];
        sprintf(n, "%d", getpid());
        if (write(f, n, strlen(n)) == -1) {
            WLOG("main: unable to write pid file in %s error: %s\n", pid_file, strerror(errno));
            return -5;
        } else {
            WLOG( "main: file %s with pid save succesfully\n", pid_file);
        }
        close (f);
     } else  {
        WLOG("main: unable to create pid file %s error: %s\n", pid_file, strerror(errno));
        return -4;
     }

     if (!start_port) blad ("in configuration file doesn't find port= variable");

     main_loop();
     return -6;
}
