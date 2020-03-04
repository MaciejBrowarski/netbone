/*
 * wielkosc bufora do wysylania i odbierania
 * raczej nie powinna byc wieksza niz wielkosc pakietu sieci
 * powyzej niej moze pojawic sie fragmentacja
 * uzycie 1500 dla Ethernetu
 * uzycie 1480 dla Ethernetu w maszynach wirtualnych
 */
//
#define BUF 1500
/*
 * ilosc danych w pakiecie
 */
#define BUF_DATA 1300
/* 
 * miejsce na naglowek po kompresji
 */
#define BUF_HEAD 180
/*
 * ilosc miejsca na naglowek przed kompresja
 */
#define BUF_HEAD_R 512

/*
 * size for file with directory
 */
#define NAME_SIZE 130
/*
 * maximum number of client (how many bind from client side is allowed)
 */
#define MAX_CLIENT 100

/*
 *  DATA_MAX used for get_object function (as this function works as fork)
 *  so this DATA_MAX buffer is used to copy data from child to parent
 *  via shared memory segment
 *  this limit can be increase without issue, but alloc memory in share memory segment
 */
#define DATA_MAX 10000000


/*
 * when set, then IDS send more details about file (permission, user and group)
 */
//#define IDS_FOR_FILE
/*
 * 1,2,3 digit - constant - depend on env
 * last digit
 * 0 - meta data
 * 1 - register servers
 * 2 - client cache
 * 3 - checker meta data
 * 4 - checker data
 * 0xa - 0xf - client cache buffer
 */
#define CMIT_SHARED_KEY 0x14d03010

