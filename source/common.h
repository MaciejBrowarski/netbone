/* 
 * File:   common.h
 * Author: BROWARSKI
 *
 * Created on 8 June 2009, 22:07
 * 0.0.4 - 2010 Jan -   add finish_ip function, all log written in /var/tmp directory,
 *                      start_port variable (port number taken from configuration file)
 * 0.0.5 2010 Jan - add compression header in packet (add send_packet function, rewrite all sendto to send_packet), add in xml_parse decompression
 * 0.0.6 2010 Jul - add log dir and pid_file as parameters takan from configurartion file
 * 0.1.3 2010 December - move code into C and H file
 */
#include "common-client.h"
/*
 * functions for share data memory
 */
#define MALLOC_S(size) malloc_s(size, __FILE__, __LINE__ )
#define REALLOC_S(ptr, size) realloc_s(ptr, size, __FILE__, __LINE__ )
#define CALLOC_S(nr, size) calloc_s(nr, size, __FILE__, __LINE__ )
#define FREE_S(ptr) free_s(ptr, __FILE__, __LINE__)
/*
 * functions for share list memory
 */
#define MALLOC_L(size) malloc_s(size, __FILE__, __LINE__)
#define FREE_L(ptr) free_s(ptr, __FILE__, __LINE__)


#define FREE_NULL(ptr) free(ptr)
#define MALLOC_NULL(ptr) malloc(ptr)
#define CALLOC_NULL(nr, size) calloc(nr, size)
/*
 * czas w sekundach pomiedzy ktorymi beda wysylane pakiety z nazwami i wersjami do zarejstrowanych klientow
 */
#define TIMEOUT 30
/*
 * max compression ratio for checks packets between IDSes
 */
/*
 * ilosc pakietow do spakowania przed wyslanie - used in send repository to another IDS
 * used by: sendd.c and datad.c - checker()
 */
#define COMP_PACKET 10
/*
 * dedicate for function
 */

/*
 * lock for function
 */
extern pthread_mutex_t get_free_data_lock;



/*
 * file with config - for reload
 */
char cfg_file[NAME_SIZE];
/*
 * struktura przechowuje klientow, ktorzy sie podlaczyli w celu otrzymywania raportow
 */

struct client {
    struct sockaddr_in client;
  //  struct client *prev;
  //  struct client *next;
    time_t czas;
};

/*
 *poczatek struktury, gdzie sa podlaczeni klienci
 */
extern struct client *ptr_client;

/*
 * struktura gdzie my sie mamy rejestrowac
 */
struct reg_ser {
    struct sockaddr_in ip;
    struct reg_ser *next;
    /*
     * when receive last data
     */
    time_t last;
    /*
     * when send register information
     */
    time_t reg;
};

extern struct reg_ser *ptr_check;

int32_t get_free_data(char *);
/* 
 * function name: create_data
 * synopsis: create object in memory
 */
struct data *create_data (char *);
/*
 * array with data pointer for better searching
 */
extern struct data **qsort_data;

/*
 * how many pointers are in qsort_data
 */
extern uint64_t qsort_c;


void qsort_count(int64_t);

void qsort_refresh();

int8_t qsort_cmp(char *, char *);
uint64_t qsort_rec (int,int,char *);


uint64_t qsort_search(char *);

struct data *search_name(char *);

/*
 * execute PERL script taken from buffer
 * IN:
 * 1 - program to execute
 * 2 - data size
 * 3 - ptr to data
 * OUT:
 * number - 0 error, >0 bytes writes to pipe
 */
int pipe_exec(char *,int32_t, char *);

void *malloc_s(size_t, char *, uint32_t);
void *calloc_s(int, size_t, char *, uint32_t);
void *realloc_s(void *, size_t, char *, uint32_t);
void free_s(void *,  char *, uint32_t);

void *malloc_l(size_t, char *, uint32_t);
void *calloc_l(int, size_t, char *, uint32_t);
void *realloc_l(void *, size_t, char *, uint32_t);
void free_l(void *,  char *, uint32_t);
