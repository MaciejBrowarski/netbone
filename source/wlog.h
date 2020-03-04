#include <stdint.h>
/*
 * WLOG - function try to sync log to file (force lock and do sync to file)
 * WLOG_NB - for more debug - no guarantee that log will be write to file, but always return from this funtions (ask for lock, async write to file)
 * WLOG_FAST - no lock, no buffer
 */
#define WLOG(str...) {  pthread_mutex_lock(&wlog_lock);  sprintf(log_buf, ## str); wlog(log_buf, 1, __func__);  pthread_mutex_unlock(&wlog_lock); }
#define WLOG_NB(str...) {  if (! pthread_mutex_trylock(&wlog_lock)) {  sprintf(log_buf, ## str);   wlog(log_buf, 0, __func__);  pthread_mutex_unlock(&wlog_lock); } }
#define WLOG_FAST(str...) {  sprintf(log_buf, ## str);   wlog(log_buf, 0, __func__);   }

// #define WLOG(str...) {  pthread_mutex_lock(&wlog_lock);  sprintf(log_buf, ## str); wlog(log_buf, 1, __func__);  pthread_mutex_unlock(&wlog_lock); }
#define WLOG_NB_TRACE(str...) {  if (! pthread_mutex_trylock(&wlog_lock)) {  sprintf(log_buf, ## str);   wlog(log_buf, 0, back_trace_line(__func__));  pthread_mutex_unlock(&wlog_lock); } }

#define FID_CLEAR if (fidlog) {  close (fidlog);  fidlog = -1; }

/*
 * mutex for logging
 */
pthread_mutex_t wlog_lock;
/*
 * File ID for logs
 */
extern int16_t fidlog;

extern char log_name[20];
/*
 * function name: wlog
 * synopsis:
 * write log to file pointed by FID
 * FID is assign when wlog is running first time
 * argument
 *   in:
 *      1 - string
 *   out:
 *
 */
int wlog(char *, uint8_t, const char *);
int wlog_fid(char *, uint8_t, int16_t, const char *);
int wlog_create_log();
