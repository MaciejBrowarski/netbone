#include "bind_port.h"
#include "common-client.h"

// #define DEBUG_BIND_PORT 1
/*
 * ip address and port for listen
 */
in_addr_t start_ip = INADDR_ANY;
uint32_t start_port = 0;
/*
 * TODO: don't know if it used as global :)
 */

int Clifd;
/*
 * NAME: bind_port
 * Synopsis: Bind UDP port for client (port is higher that start_port + 5 till start_port + 50
 * if not find free port exist from program (should be correct to handle this by laucher)
 * args:
 * IN:
 * None
 * OUT:
 * id from bind port
 *
 */
int bind_port()
{
    int Clifd;
    struct sockaddr_in sad; /* structure to hold server's address  */
    int port; /* protocol port number                */;
    
	#ifdef WIN32
	WSADATA wsaData;
    if (WSAStartup(MAKEWORD(1,1), &wsaData) == SOCKET_ERROR) {
        printf ("Error initialising WSA.\n");
        return -1;
    }
	#endif
    Clifd = socket(PF_INET, SOCK_DGRAM, 0);
    if (Clifd < 0) { 
	printf ("socket creation failed\n"); 
	return -1;
	}

    for (port = start_port + 5; ;port++) {
        memset((char *) & sad, 0, sizeof (sad)); /* clear sockaddr structure   */
        sad.sin_family = AF_INET; /* set family to Internet     */      
        sad.sin_addr.s_addr = start_ip; /* set the local IP address   */      
        sad.sin_port = htons((u_short)port); /* set the port number        */

        if (bind(Clifd, (struct sockaddr *) & sad, sizeof (sad)) < 0) {
            #ifdef DEBUG_BIND_PORT
            printf("bind failed, port %d\n", port);
            #endif
            if (port > (start_port + MAX_CLIENT)) {
                WLOG("bind_port: bind failed, reached max numbers of clients\n");
                return -1;
            }
        } else {
            break;
        }
    }

    return Clifd;
}

