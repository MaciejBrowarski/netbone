/*
 * common library for clients
 *
 * Version: 4.2
 *
 * History:
 * 0.1.0 2010 October - created
 * 0.1.1 2010 November - add to read_file 2 parameters: name and listen to accept on dedicated ip address
 *                         correct time (set to 1s) in get_list for response.
 * 0.1.2 2010 November - add WLOG macro for logging with (un)lock, add lock and unlock to monitor mutex (un)locks
 * 0.1.3 2010 December - make real header file, code move to c file 
 * 0.1.4 2013 July - add backtrace procedure
 * 2.0 2013 December - add buffer cache structure
 * 2.1 2014 June - rewrite WLOG_NB to try lock 
 * 2.2 1014 September - add code/decode packets
 * 4.0 2014 November - add WLOG_NB_TRACE - WLOG with back trace function, to know how run function
 * 4.1 - 2014 December - dump_buf fuction to dump buffers into file for debug
 * 4.2 - 2015 January - add debug_* variables
 *
 * Copyright by BROWARSKI
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#ifndef WIN32
/*
 * for backtrace - unix only
 */
 #include <execinfo.h>
#endif
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include "decode.h"
#include "wlog.h"
#include "send_request.h"
#include "read_file.h"
#include "bind_port.h"
#include "strfind.h"
#include "xml_parse.h"

#ifdef WIN32
#include <Winsock2.h>
#include <stdint.h>
typedef uint32_t in_addr_t;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
// `#include <syslog.h>
#endif

#include "params.h"


// #define DEBUG_READ_FILE 1
/*
 * CONSTANTS
 */

#define MAX_IP 16
/*
 * back stack size
 */
#define SIZE 1024


#define FREE_GET_LIST(xx) if (xx) { if (xx->buf) { free(xx->buf); xx->buf = (char *)0; } free(xx); xx = (struct comm *)0; }

#define DUMP_BUF_DEC(buf,size) dump_buf(__func__, __LINE__, buf, size, 1)
#define DUMP_BUF_RAW(buf,size) dump_buf(__func__, __LINE__, buf, size, 0)
/*
 * functions to mask normal allocation
 */
#define MALLOC_N(size)  malloc(size); WLOG("MALLOC at %s:%d: %d", __FILE__, __LINE__, size);
#define FREE_N(ptr) { free(ptr); WLOG("FREE_N at %s:%d: ptr %p", __FILE__, __LINE__, ptr); }
#define REALLOC_N(ptr, size) realloc(ptr, size); WLOG("REALLOC_N: at %s:%d: at %p to %ld\n", __FILE__, __LINE__, ptr, size);
#define CALLOC_N(nr, size) calloc(nr, size); WLOG("CALLOC_N at %s:%d size %ld * %d\n", __FILE__, __LINE__, size, nr );

#define LIKE(x)       __builtin_expect((x),1)
#define UNLIKE(x)     __builtin_expect((x),0)

//#define OFF_TO_PTR(xx) xx ? ptr_data + xx : 0
/*
 * poczatek kolejki z danymi
 */
extern struct data *ptr_data;

extern struct data *OFF_TO_PTR(off_t);

#define IS_PTR_NULL(xx) (ptr_data == xx)
#define PTR(xx) (ptr_data + xx)
// #define PTR_TO_OFF(xx) (xx - ptr_data)
/*
 * GLOBAL VARIABLES
 */
/*
 * for back_trace_line function
 */

extern char backtrace_line[4096];

/*
 * ip address and port for listen
 */
extern in_addr_t start_ip;
extern uint32_t start_port;
/*
 * UDP network packet size 
 * (only for sendd)
 */
extern uint32_t net_size;
/*
 * name for IDS
 */

char *ids_name;
extern int ids_mode;
/*
 * count CRC for data and add to header
 * when off - it can be faster
 */
extern uint8_t net_crc;

/*
 * code transmission between IDSes
 * when off - send can be faster but unsecure
 */
extern uint8_t code_trans;

#ifdef AGENT
#define MONITOR_ID_SIZE 30
char monitor_id[MONITOR_ID_SIZE];
char agent_name[NAME_SIZE];
#endif

/*
 *    global as to kill it on stop signal
 */
extern int16_t get_object_pid;
/*
 * access to share buffor for get_object function
 */
extern struct comm *checker_sh_meta_data;
extern char *checker_sh_data;



/* 
 * client time flush or spartb 
 */
extern uint8_t buffer_flush;

/*
 * how many objects will be held by IDS
 */
extern int32_t ids_max;

/*
 * array for other IDS ip's
 */
char *ip[MAX_IP];
uint16_t load_ip(char **, uint16_t, char *);
time_t cm_check();
pthread_mutex_t ip_block;
/*
 * syslog priority
 */
extern int priority;
/*
 * file fid pid file
*/
extern char pid_file[PATH_MAX];
extern char sendd_pid_file[PATH_MAX];
/*
 * relative path clients (native and fuse)
 */
char rpath[NAME_SIZE];
/*
 * backup path port for IDS
 */
char bpath[NAME_SIZE];
int bpath_load;
/*
 * buffer for logs
 */
char log_buf[4096];

/*
 * buffer for debug logs
 */
char log_buf_debug[4096];

/*
 * time out for all client action
 */
extern uint16_t timeout_client;

extern int Clifd;

extern uint16_t ser_nr;

 // extern int shmid_server;

 // extern  int shmid_mem;
//extern int pid_sendd;
/*
 * variable use to keep seed
 * required for random in get_list function
 */
extern unsigned int get_list_seed;

/*
 * cache valid time
 */
extern unsigned int cache_valid;
/*
 * for add and partial - client
 */
char part[BUF_HEAD];
/*
 * STRUCTURES
 */

/*
 * struct for received data using by clients
 */
struct comm {
    char command[30];
    char name[NAME_SIZE];

    // wielkosc danych
    unsigned int size;
    unsigned int part_1;
    unsigned int part_2;
    unsigned int start;
    unsigned int stop;
    unsigned int id;
#ifdef IDS_FOR_FILE
    mode_t mode;
    uid_t owner;
    gid_t group;
#endif
    /*
     *  time stamp
     */
    uint32_t t_sec;
    uint32_t t_msec;
    /*
     * data CRC
     */
    uint32_t crc;
    /*
     * source IP of request
     */
    struct sockaddr_in client;
    char *buf;
    char good; /* 0 - zadanie nie pelne, 1 - pelne, mozna kopiowac do data */

};

struct data_send {
    struct comm *ret;
    char *comma;
    char *ip;
    char *buf;
    uint32_t buf_s;
};

/*
 * struktura przechowujaca dane
 * if next NULL this mean this structure is last
 */
struct data {
    //struct data *next;
    off_t next;
    char name[NAME_SIZE];
    pthread_mutex_t block; //
    /*
     * size of data
     */
    uint32_t size;
    /*
     * timestamp of object
     */
    uint32_t t_sec;
    uint32_t t_msec;
    /*
     * array to data
     */
    char *buf;
    /*
     * 0 - meta data and data are completed
     * 1 - deleted object, only meta_data no data
     * 2 - parted, meta data exist, data are not completed
     * if deleted > 0 and t_sec < time - 1 day object can be overwritten by new
     */
    uint8_t deleted;
    /*
     * 0 - don't need check with other IDS (default)
     * 1 - need check with other IDS (after init load) - also passive mode IDS
     */
    uint8_t need_check;
    /*
     * who create or change this object
     */
     struct sockaddr_in modify_ip;
#ifdef IDS_FOR_FILE
    /*
     * atributes for files
     * for FUSE client
     */
    mode_t mode;
    uid_t owner;
    gid_t group;
#endif
};
//#ifdef IDS_CLIENT
struct client_cache {
    char ip[16];
    time_t last_success;
    time_t last_contact;
};

struct client_cache_buf {
    pthread_mutex_t lock;
    time_t data_lock;
    pid_t pid_lock;
    int16_t buf_size;
    char buf[5 * BUF_DATA];
};
//#endif
/*
 * FUNCTIONS
 */
/*
 * prototypes
 */



/*
 * critical error for application, exit from program with error
 * Please, use this function only in emergency case, when there are not possiblity to handle error
 * IN:
 * str: ptr to string, which will be printed
 */
int blad(char *); 

/*
 * UNUSED
 * inline int lock(pthread_mutex_t *, char *);
 * inline int unlock(pthread_mutex_t *, char *);
 */

int16_t client_request (uint8_t, char *,int , char *, uint8_t);
/*
 *
 */
void call_get_list (struct data_send *);
/*
 * free space for IP addresses
 */
int finish_ip(char **);

/*
 * out
 * ilosc wyslanych danych
 */
int64_t multiply_put(const char *, const char *, size_t , off_t , int , char *, uint32_t , uint32_t );


#include "send_packet.h"
/*
 * Wyslanie informacji do klienta
 * IN:
 * str - ciag znakow, ktory chcemy opakowac do wyslania
 * id - id requestu
 * OUT:
 * wskaznik do odpowiedzi
 */
char *xml_return_i(char *, unsigned int);


char *get_list_meta_data(struct data *, char *, int, int8_t);
/*
 * handle by signal SIGV
 * back trace what corrupt us
 */
void back_trace();
/*
 * back trace function names
 */
char *back_trace_line (const char *);
/*
 * check available IDS and refresh cache infromation about it
 */
void refresh_client_cache();


int dump_buf(const char *, int32_t, char *, size_t, int s);
/*
 * determine and generate config file name based on argv[0]
 */
int get_cfg_filename(char *, char *);

int get_object(char *, uint32_t, int, char *);
