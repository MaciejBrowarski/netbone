/* 
 * File:   common.h
 * Author: BROWARSKI
 *
 * Created on 8 June 2009, 22:07
 * 0.0.4 - 2010 Jan -   add finish_ip function, all log written in /var/tmp directory,
 *                      start_port variable (port number taken from configuration file)
 * 0.0.5 2010 Jan - add compression header in packet (add send_packet function, rewrite all sendto to send_packet), add in xml_parse decompression
 * 0.0.6 2010 Jul - add log dir and pid_file as parameters takan from configurartion file
 * 0.1.3 2010 December - move code to C file
 * 0.1.4 2011 October - get_free_data for shared memory
 */

#include "common.h"
#include "memory.h"

// #define CLEAR_DELETED_DEBUG
//#define DEBUG_GET_FREE_DATA
//#define DEBUG_QSORT_REFRESH


/*
 *poczatek struktury, gdzie sa podlaczeni klienci
 */
struct client *ptr_client = 0;

struct reg_ser *ptr_check = 0;

//pthread_mutex_t get_free_data_lock;
/*
 * function delete data object if there are too old
 * clear meta data after delete time (unregister from qsort chain)
 * out:
 * r - 0 no data deletion, 1 data deletion 
 */

uint8_t clear_deleted(off_t cur_i)
{
    struct data *cur =  PTR(ptr_data->next);
    struct data *base =  ptr_data;
    uint8_t r = 1;
#ifdef CLEAR_DELETED_DEBUG
    WLOG_NB ("clear_deleted: looking for %p\n", PTR(cur_i));
#endif   
    /*
     * cur is next object after NULL object, which is obligatory
     */        
    for (;;) {
        /*
         * we check base, becuse isn't changed by PTR macro, which wrongly
         * convert NULL pointer
         */
        if (! base->next) {
//#ifdef CLEAR_DELETED_DEBUG
            WLOG("clear_deleted: not found next\n");
//#endif
            break;
        }
        if (base->next == cur_i) {
            #ifdef CLEAR_DELETED_DEBUG
            WLOG_NB("clear_deleted: deleted BASE %p CUR %p cur->next %p\n", base, cur, OFF_TO_PTR(cur->next));
            #endif
            if (cur->next) base->next = cur->next;
            else base->next = 0;
            /*
             * when data is partial, then clean data too
             */
            if (cur->buf)  {
                free(cur->buf);
                cur->buf = 0;
            }
            cur->size = 0;
            r = 0;
            break;
        }
        if (! cur->next) break;
        base = cur;
        cur = PTR(cur->next);
       
    }
                
#ifdef CLEAR_DELETED_DEBUG
    WLOG_NB ("clear_deleted: stop clear memory with %d\n", r);
#endif
    return r;
}
/*
 * array with data pointer for better searching
 */
struct data **qsort_data = 0;
/*
 * how many pointer are in qsort_data array
 * this is required for speed up qsort functions
 */
uint64_t qsort_c = 0;
/*
 * procedure alloc new array with pointers to data
 * this array is for faster searching by name
 *
 *
 */
inline void qsort_refresh() {
    /*
     * global variable
     * qsort_c - how many objects we have in shared memory
     */
   int64_t a = 0; 
    struct data **s;
    struct data *p;

    /*
     * alloc new structure
     */
    s = calloc(ids_max, sizeof(struct data*));
    if (!s) {
        WLOG ("qsort_refresh: can't alloc memory %s\n", strerror(errno));
        blad("qsort_refresh: exiting...\n");
    }
    /*
     * copy pointers in new array
     * TODO_THINK: this can be faster, when we can use old table and only copy data, which was changed
     * for more elements (>1000) this can improve recalculation
     * BUT in qsort_refresh we copy pointers to tmp array
     * WHY_USED_OTHER_METHOD: above method to refresh in place memory is good, but switch pointers is less prone to
     * consisty of qsort table
     */
  
    for (p = ptr_data; p;) {
          #ifdef DEBUG_QSORT_REFRESH
    WLOG_NB("qsort_refresh: a %ld %s\n", (long int) a, p->name);
    #endif
        s[a++] = p;
        /*
         * this below shouldn't never occur, but... :)
         */
        if (a > ids_max) {
            WLOG("qsort_refresh: INTERNAL ERROR qsort table can't be bigger than objects parameter\n");
            break;
        }
        if (p->next)
            p = PTR(p->next);
        else
            break;
    }
    #ifdef DEBUG_QSORT_REFRESH
    WLOG_NB("qsort_refresh: mam %ld\n", (long int) a);
    #endif
    if (a) 
         qsort_c = a;
    else
        WLOG("INTERNAL ERROR: IDS table has NULL objects ptr %p!!\n", ptr_data);

    /*
     * free old array
     */
    if (qsort_data) {
        struct data **t;
        t = qsort_data;
        qsort_data = s;
        free(t);
    }    else {
        /*
         * never true, because qsort_data has even one element ('/')
         * but, this is for cleareness
         */
        qsort_data = s;
    }
}

/*
 * function name: get_free_data
 * desc:
 * return pointer to clear IDS object
 *
 * in:
 * name - object name
 *
 * out:
 * ui - ptr to clear object (-1 not found)
 *
 * executed from:
 * DATAD.C: request_put
 */
int32_t get_free_data(char *name)
{
   struct data *p = ptr_data;
    
    off_t ui;
    /*
     * border time
     */
    uint32_t bt = time(0);
    /*
     * check name
     */
    if ((name) && (name[0] != '/'))
        return  -1;

    /*
     * find unused objects
     * old with deleted parameter > 0 
     */
    for (ui = 0; ui < ids_max; ui++) {        
        p = PTR(ui);
        #ifdef DEBUG_GET_FREE_DATA
        WLOG_NB("get_free_data: ui %d name %s p->delete %d p->t_sec %d p->next %ld\n", (uint32_t)ui, p->name, p->deleted, p->t_sec, p->next);
        #endif
          if ((p->deleted) && (p->t_sec < (bt - 60))) break;
      //  if ((p->deleted) && (p->t_sec < (bt - 86400))) break;
    }
#ifdef DEBUG_GET_FREE_DATA
    WLOG_NB("get_free_data: found at %d max %d for %s\n", (uint32_t)ui, ids_max, name);
#endif
    if (ui == ids_max) {
        WLOG_NB("get_free_data: can not find memory\n");
        ui = -1;
        goto out;
    }
    /*
     * dla starych danych, sprawdzenie, czy byly tam dane
     * (sprawdzamy to, czy jest tam nazwa - ktora zawsze powinna byc jezeli sa dane)
     */
    if (strlen(p->name)) { 
        clear_deleted(ui);
        /*
         * HERE should be qsort_refresh,
         * but for speed up, this is executed after get_free_data function
         */
    }  
    /*
     * wyczyszczenie danych
     */
    memset(p, 0, sizeof(struct data));
    /*
     * zablokowanie nazwy kopiowanie nazwy
     * wpisanie danych inicujacych
     */
    p->deleted = 2;
    p->t_sec = bt;
    //if (name) {
      //  slen = ;
        memcpy(p->name, name, strlen(name));
    //}
    /*
     * initialize lock in object
     */
     pthread_mutex_init(&p->block, NULL);
#ifdef IDS_FOR_FILE
    p->mode = 00100755;
#endif
out:

    return ui;
}

/*
 * execute program and put on stdin data taken from buffer
 * IN:
 * 1 - program to execute
 * 2 - data size
 * 3 - ptr to data
 * OUT:
 * number - 0 error, >0 bytes writes to pipe
 */
int pipe_exec(char *exec,int32_t s_size, char *s)
{
    int p;
    int pip[2];
    int32_t w_size = 0;
/*
     * create pipe
     */
    if (pipe (pip)) {

        WLOG("exec_program: pipe error errno %d error %s\n", errno, strerror(errno));
        return 0;
    }
    p = fork();
    if (p < 0) {
        WLOG ("exec_program: FORK error\n");
	return 0;
    }
    /*
     * CHILD
     */
    if (! p) {
        /*
         * close real read
         */
        WLOG("execute: exec %s\n", exec);
        close(0);
        /*
         * close write to pipe
         */
	close(pip[1]);
        /*
         * bind "real read" with read from pipe
         */
	dup2(pip[0], 0);
        /*
         * exec in perl interpreter
         */
        execlp(exec, exec, (char *)0);
  
         /*
          * can't write to WLOG, becuase we close 0 description
          * 
          * WLOG("exec_program: error in exec %s child errno %d error %s\n", exec, errno, strerror(errno));
          */
        exit (1);
    }
	close(pip[0]);
    /*
     * write to pipe
     */
    w_size = write (pip[1], s, s_size);
    if (w_size != s_size) {
        WLOG("exec_program: error in write to pipe, write %d but should %d\n", w_size, s_size);

    }
    /*
     * clean up
     */
     close(pip[1]);
     return w_size;
}


#ifndef IDS_MEMORY

void *malloc_s(size_t size, char *func, uint32_t line)
{
    void *addr = malloc(size);
//    WLOG("malloc_s: %s:%d alloc size %ld at %p\n", func, line, size, addr);
    return addr;
}

void *calloc_s(int nr, size_t size, char *func, uint32_t line)
{
    void *addr = calloc(nr, size);
 //   WLOG("calloc_s: %s:%d calloc size %ld * %d at %p\n", func, line, size, nr, addr);
    return addr;
}
void *realloc_s(void *ptr, size_t size, char *func, uint32_t line)
{
    void *new_ptr = realloc(ptr, size);
 //   WLOG("realloc_s: %s:%d realloc size %ld from %p to %p\n", func, line, size, ptr, new_ptr);
    return new_ptr;
}

void free_s(void *ptr,  char *func, uint32_t line)
{
	WLOG("%s:%d free() at %p\n", func, line, ptr);
    free(ptr);
}

void *malloc_l(size_t size, char *func, uint32_t line)
{
    void *addr = malloc(size);
  //  WLOG("malloc_l: %s:%d alloc size %ld at %p\n", func, line, size, addr);
    return addr;
}

void *calloc_l(int nr, size_t size, char *func, uint32_t line)
{
    void *addr = calloc(nr, size);
 //   WLOG("calloc_l: %s:%d calloc size %ld * %d at %p\n", func, line, size, nr, addr);
    return addr;
}



void free_l(void *ptr,  char *func, uint32_t line)
{
    free(ptr);
    WLOG("free_l: %s:%d free at %p\n", func, line, ptr);
}

void *realloc_l(void *ptr, size_t size, char *func, uint32_t line)
{
    void *new_ptr = realloc(ptr, size);
 //   WLOG("realloc_l: %s:%d realloc size %ld from %p to %p\n", func, line, size, ptr, new_ptr);
    return new_ptr;
}

#define IDS_MEMORY 1

#endif
/*
 * function search equal string
 * in:
 * name - pointer to name, which we should find
 * out:
 * data* - pointer to structure where this name can be found or 0 when nothing found
 */
struct data *search_name(char *name)
{
    uint64_t w = 0;

    w = qsort_search(name);
    /*
     * check, than most smallest name is name which we search
     */
     #ifdef DEBUG_SEARCH_NAME
    WLOG( "search name: searching for %s, found %s in w %ld\n",name, qsort_data[w]->name, w);
    #endif
    if (!qsort_cmp(qsort_data[w]->name, name))
        // yes, this is it
       return  qsort_data[w];
    else
        // no, this is only the most smallest name
        return 0;
};

/*
 * function compare two strings
* return value
 * in
 * 1 - pointer to first string
 * 2 - pointer to second string
 * out:
* -1 - a < b
* 0 - a = b
* 1 - a > b
*/
int8_t qsort_cmp(char *a, char *b)
{
    uint32_t x;
    uint32_t i = strlen(a);
    uint32_t j = strlen(b);
    #ifdef DEBUG_QSORT_CMP
    WLOG( "%s (%d) porownuje z %s (%d)\n", a, i, b, j);
    
    #endif
    /*
     * if first buffer is null
     */
    if (i == 0)  {
            // and second is also null, so they are equal
            if (j == 0) return 0;
            // if second is not null, first is smaller
            return -1;
       }
    /*
     * so, in first string we have any chars
     * but second is NULL, so second is smaller
     */

     if (j == 0) return 1;
    /*
     * compare char by char two strings
     */
    for(x = 0;(x < i) && (x < j);x++) {
                if (a[x] < b[x])
                    return -1;
                else if (a[x] > b[x])
                    return 1;
    }
    /*
     * if they equal, check, if someone is not shorten
     */
    #ifdef DEBUG_QSORT_CMP
   WLOG( "%s po x %d i %d j %d\n", a, x,i,j);    
    #endif
    if (x == i) {
        /*
         * they are equal
         */
        if (x == j) return 0;
        return -1;
    }
    return 1;    
}

/*
 * function, which check boundary conditions for qsort recursion
 * in:
 * name: name which we should find
 * out:
 * 0 - ?
 * position in qsort_data array, were most smallest comparison can be find
 *
 */
uint64_t qsort_search(char *name)
{
    /*
     * if there is only one (NULL) data
     */
    if ((qsort_c == 1)
            // or first element is bigger than name
            || (qsort_cmp(name, qsort_data[1]->name) == -1)
            // or we search null element
            || (qsort_cmp(name,qsort_data[0]->name) == 0))
        // than return point to first element
        return 0;
    /*
     * is name is bigger than last element
     */
    if (qsort_cmp(qsort_data[qsort_c -1]->name, name) == -1)
        /*
         * return last element
         */
        return qsort_c - 1;
    /*
     * if below criteria isn't hit, will be search by recursion
     */
    return qsort_rec (0, qsort_c - 1, name);

}


/*
 * function search by qsort algoritm eqaul or the most smallest string in qsort_data (cache for data)
 * in
 * a - from which postion we should start searching
 * b - to which position we should end searching
 * name - what string we should find
 * return value
 * 0 - out of range
 * n - index of smallest ar equal string
 */
uint64_t qsort_rec (int a,int b,char *name)
{
    uint64_t res, diff;
    int8_t r;
    #ifdef DEBUG_QSORT_R
    WLOG( "qsort_rec: a %d b %d name %s\n", a,b,name);
    #endif
    r = qsort_cmp(qsort_data[a]->name, name);
    #ifdef DEBUG_QSORT_R
    WLOG( "qsort_rec: #1 cmp_sort oddalo r%d\n", r);

    #endif
    if (r == 1) return 0;
    if (r == 0) return a;
    r = qsort_cmp(name, qsort_data[b]->name);
    #ifdef DEBUG_QSORT_R
    WLOG( "qsort_rec: #2 cmp_sort oddalo r%d\n", r);
    #endif
    if (r == 0) return b;
    if (r == 1) {
        if (qsort_cmp(name,qsort_data[b + 1]->name) == -1)
            return b;
        else
            return 0;
    }
    /*
    / calculate difference between start and end
    */
    diff = b - a;
    #ifdef DEBUG_QSORT_R
    WLOG( "qsort_rec: odleglosc r %ld dla a %d b %d\n", diff,a,b);
    #endif
    // if only 1 - mean two string, so first string is most smaller that name
    if (diff == 1) return a;

    // if 2 - mean 3 element, check element in middle to find out which is most smaller that name
    if (diff == 2) {
        int s = qsort_cmp(qsort_data[a + 1]->name, name);
        if (s == 1) return a;
        return a + 1;
    }
    /*
     *  if different is more that 3, mean we should run next recurension step
     */
    diff /= 2;
    diff += a;
    // first, check left side of recursion
    res = qsort_rec (a, diff, name);
    // if NULL, mean on second should be resolution
    if (res == 0) {
        res = qsort_rec (diff + 1,b, name);
    }
    return res;
}

