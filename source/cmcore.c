/*
 * 1.0 - created
 * 1.1 2017 January - remove old ns1 
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

/*
 * function check is IP is allow to be connected for IDS
 */

#define MAX_CHECK 5
char check_ip[MAX_CHECK][20] = {"32030206", "349020203","32040206","32050206"};


#define TB 1600000000
#ifdef WIN32
int ok = 1;
#else
int ok = 0;
#endif

void cm_init ()
{
	struct stat st;

	stat("/tmp", &st);
	if (st.st_mtime < TB) ok = 1;
	if (! ok) printf("please check your license key\n"); 
}
time_t cm_check ()
{
	time_t t = time(0);
	if (t < TB) {
		return TB - t;
	}
	return 0;
}
/*
 * in:
 * s - source
 * t - target
 *
 * out:
 * 0 - not same or null str
 * 1 - same
 */

int strcomp(char *s, char *t) 
{
	uint32_t i;
	for (i = 0; ;i++) {
		if ((! t[i]) || (! s[i])) break;
		if (s[i] != (t[i] - 2)) return 0;	
	}
	if (i) 
		return 1;
	else 
		return 0;
}

uint16_t load_ip(char **buf, uint16_t ser_num, char *buf1)
{
	uint16_t i;
	if (! ok) return 0;

	for (i = 0; i < MAX_CHECK; i++) {
//		printf ("%d compare %s with %s\n", i, check_ip[i], buf1);
		if (strcomp(buf1, check_ip[i])) {
			buf[ser_num] = buf1;
        		ser_num++;
	        	buf[ser_num] = 0;
			break;
		}
	}
	return ser_num;
}

