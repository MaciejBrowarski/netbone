/*
 * common library for clients
 *
 * Version: 6.0
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
 * 5.0 2015 September - wlog as separate file
 * 5.1 2015 October - add log_start variable to roll logs
 * 6.0 2018 January - wlog_create_log - return -1 when log file can't be create (e.g. when disk is full)
 *
 * Copyright by BROWARSKI
 */
#include "common-client.h"

int16_t fidlog = -1;
time_t log_start = -1;
char log_name[20] = "log";
/* 
 * write string to log file (point by fid)  
 * prefix it with current date&time and function name (provide by fname)
 *
 * return value:
 * 0 - success
 * -1 - fid isn't proper, or unable to write to file
 */
int wlog_fid(char *string, uint8_t flush, int16_t fid, const char *fname)
{
    int str;
    int ret;
    struct tm *czas;
    
    char buf[4096];
	#ifdef WIN32
	/*
     * get current time with seconds only
     */
	time_t cz_win;
	czas = localtime(&cz_win);
	sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d %s: %s", czas->tm_year + 1900,czas->tm_mon + 1, czas->tm_mday, czas->tm_hour, czas->tm_min, czas->tm_sec, fname, string);
	#else
	struct timeval cz;
    /*
     * get current time with milisecunds
     */
    gettimeofday(&cz, NULL);
	if (log_start < 0) {
		log_start = cz.tv_sec;
	} else if ((log_start + 86400) < cz.tv_sec) {
		FID_CLEAR;
		fidlog = wlog_create_log();
        
	
        log_start = cz.tv_sec;
	}
    if (fidlog < 0) return -1;
    czas = localtime(&cz.tv_sec);
    /*
     * add to log string information about time
     */
    sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d.%06u %s: %s", czas->tm_year + 1900,czas->tm_mon + 1, czas->tm_mday, czas->tm_hour, czas->tm_min, czas->tm_sec, (uint32_t) cz.tv_usec, fname, string);
    #endif
	str = strlen(buf);
    /*
     * write to file
     */

     ret = write (fid, buf, str);
	#ifndef WIN32
        if (flush) fsync(fid);
	#endif		
    /*
     * no exit when error to write, maybe some other method to inform
     * user that log can't write
     * exit isn't good idea
     */
    if (ret != str) {
        /* NULL: no idea how to inform about it? syslog? */
        return -1;
    }

    return 0;
}

/*
 *
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


int wlog(char *string, uint8_t flush, const char *func)
{
	   /*
     * if file handler for log is -1
     * create file with log
     */

	if (fidlog == -1) {
        	fidlog = wlog_create_log();
    }

    if (fidlog > -1) {
	    wlog_fid(string, flush, fidlog, func);
    }
	return 0;
}

/*
 * create log file and open it
 *
 * return:
 *  >=0 - file handler with log file 
 *  -1 - can't create log file
 */
int wlog_create_log() 
{
	char fname[100];
	int16_t fid;

	 memset(fname, 0, 100);
	#ifdef WIN32
      uint32_t pid = 1000;
        sprintf(fname,"%s\\%s-%d-%d.log", log_dir,log_name, pid, (uint32_t) time(0));
		#ifdef DEBUG_WLOG_CREATE_LOG
		printf("wlog_create_log: name is: %s\n", fname);
		#endif
        fid = open(fname, O_WRONLY|O_CREAT|O_TRUNC,0755);
#else
        /*
	 * pthread_self return big number
	 * getpid is better as show exact tid proces which can be straced
         */
        pid_t pid = getpid();
	/*
	 * for non Linux use below:
	 * pid_t tid = pthread_self();
	 */
	pid_t tid = syscall(SYS_gettid);
	/*
	 * for thread which like to have separate log file (like tcp_server function)
	 * create separate log file
	 */
	if (tid != pid) {
#ifdef __x86_64
        	sprintf(fname,"%s/%s-%d-%ld.%d", log_dir, log_name, (uint32_t) pid, (uint64_t) tid, (uint32_t) time(0));
#else
		sprintf(fname,"%s/%s-%d-%d.%d", log_dir, log_name, (uint32_t) pid, (uint32_t) tid, (uint32_t) time(0));
#endif
	} else {
		sprintf(fname,"%s/%s-%d.%d", log_dir, log_name, (uint32_t) pid, (uint32_t) time(0));
	}
	
           fid = open(fname, O_WRONLY|O_CREAT|O_TRUNC,0755);

#endif
    if (fid < 0) {
	    char er[1024];
	    sprintf(er, "Unable to create log file (%s):", fname);
        perror(er);

    }
	return fid;
}
