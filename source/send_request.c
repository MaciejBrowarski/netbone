/* 
 * IDS - Independent Data Storage
 * 
 * File:   send_request.c
 * Author: BROWARSKI
 *
 * Version: 0.2
 *
 * History:
 * Created on 29 may 2009, 22:01
 *
 * 0.1 2016 May - base ID on time and rand
 * 0.2 2016 May - get name from com and compare it with received packet
 */

#include "send_request.h"
#include "common-client.h"

// #define DEBUG_SEND_REQUEST 1
struct comm *get_list(char *com, char *data, unsigned int data_l, int Clifd, char *ip)
{
    
    return send_request(com, data, data_l, Clifd, ip, 0);
}
/*
 * funkcja wysyla do klienta zapytania
 * in:
 * 0 - naglowek z zadaniem
 * 1 - jak jest wskaznik, to przekopiowanie ze wskaznika danych do zadania (dla PUT/ADD/RENAME)
 * 2 - wielkosc danych
 * 3 - id polaczenia
 * 4 - adres ip
 * 5 - bufor na dane (jak 0 to funkcja sama stworzy taki bufor)

 * out:
 * wskaznik na wypelniona structure odpowiedzi, ktora nalezy zwolnic po uzyciu
 * jezeli 0 funkcji nie udalo sie pobrac zadania
 * UWAGA !!!
 * funkcja ma wycieki pamieci, np. wtedy gdy nie moze czegos pobrac
 * dla przyspieszenia dzialania funkcji zostaly usuniete wszelkie
 * czyszczenia. Kod powinnien byc wykonany pod procesem z forkiem,
 * aby system sam wyczyscil ewentualny wyciek
 * !!!!
 */
struct comm  *send_request(char *com, char *data, unsigned int data_l, int Clifd, char *ip, char *ret_buf)
{
    char buff[BUF]; // bufor, ktory wysylamy do UDP
    char buff_d[BUF]; // bufor, do ktorego trafiaja dane z UDP
    unsigned int a = 0, i = 0;
	#ifdef WIN32
	int alen;
	#else
	unsigned int alen;
	#endif
    struct sockaddr_in cad;
	int n, send_ok = 0;
    unsigned int id = 0, max = 0;
    int16_t n_start = 0, n_stop = 0;
    struct comm **res = 0;
   	struct timeval pt;
	if (! gettimeofday(&pt, NULL)) {
           srand(abs(id + pt.tv_usec + pt.tv_sec) + getpid());
    }
	

    /*
     * znalezienie nazwy w com
     * (jest to szybsze, niż tworzenie nowej funkcji z nowym argumentem, dla przyspieszenia działania można przepisać)
    * nazwa jest potrzebna do rozroznienia pakietow bo czasami samo ID moze nie wystarczyc
     */
    n_start = strfind(com, "<n");
    n_stop = strfind(com, "/n>");
        if ((n_start > 0) && (n_stop > n_start)) {
                n_start += 2;
		n_stop -= n_start;
        } else {
	/* 
	 * not found <n /n> in request (e.g. buffer request)
	 * so, inform id and rest to not use name as variable for identify
	*/
		n_start = 0;
	}

	res = calloc (2, sizeof(struct comm *));;

    if (! res) {
        WLOG ("unable to calloc memory for res\n");
        goto out;
    }

    alen = sizeof(cad);
    memset(buff, 0, BUF);
    /*
     * wygenerowanie ID pakietu
     */

    id = rand();

	if (UNLIKE(debug_send_request)) {
	WLOG_NB("alloc %p id %d n_start %d\n", res, id, n_start);
	if (n_start) {
    		WLOG_NB("nazwa %s\n", &com[n_start]);    
	}
	}
    sprintf(buff, "%s<i%d/i>", com, id);

    cad.sin_family = AF_INET; /* set family to Internet     */
    cad.sin_addr.s_addr = inet_addr(ip); /* set  IP address   */
    cad.sin_port = htons((u_short) start_port); /* set the port number        */
    /*
     * glowna petla oczekujaca na odpowiedz
     * a - ilosc timeout
     * i - ilosc odpowiedzi (> 0 dla GET)
     */
    for (a = 0, i = 0; a < 3;) {
        fd_set rfs;
        struct timeval czas;
        int r;
	if (UNLIKE(debug_send_request)) {
        	WLOG_NB ("ID %d petla a %d\n", id, a);
		if (n_start) WLOG_NB ("ID %d - nazwa %s\n", id, &com[n_start]);
	}

        /*
        * Wyslanie zapytania jezeli jeszcze nie nie bylo  wyslane lub wystapil timeout
        */
        if (! send_ok) {
		if (UNLIKE(debug_send_request)) {
            WLOG_NB("Sendto IP: %s\n",ip);            
		}
            n = send_packet(buff, data, data_l, Clifd, cad);
            if (n < 0) {               
              
                WLOG("Sendto IP: %s errno %d error: %s \n",ip, errno, strerror(errno));
                /*
                 * errno
		 * 9 - bad file description
                 * 88 - Socket operation on non-socket
                 * 101 - Network is unreachable
                 */
           	a++; 
#ifdef WIN32
                Sleep (1);
#else
                sleep (1);
#endif
                continue;      
            }
		if (UNLIKE(debug_send_request)) {
            WLOG_NB("petla a %d ID %d wyslano n %d zadeklarowano danych %d buff %p\nbufor\n%s\n",a, id, n, data_l, buff, buff);            
		}
        }

        FD_ZERO(&rfs);
        FD_SET(Clifd, &rfs);
        czas.tv_sec = 1;
        czas.tv_usec = 0;

        r = select (Clifd + 1, &rfs, NULL, NULL, &czas);
	if (UNLIKE(debug_send_request)) {
        	WLOG("ID %d select oddalo:  %d\n",id,r);       
        	if (i) {
             		WLOG("res[0] p1 %p %d\n",&res[0]->part_1, res[0]->part_1);             
        	}
	}
        /*
         * czeka na nas pakiet
         */
        if (r) {
            uint32_t j, s = 0, jest = 0;
            uint32_t cur = 0;
            uint32_t cur_size = 0;
            /*
             * czekaja na nas jakies dane, co oznacza, ze nie musimy juz ponownie wysylac senda
             */
            send_ok = 1;
            a = 0;
            memset(buff_d, 0, BUF);

            n = recvfrom(Clifd, buff_d, BUF, 0, (struct sockaddr *) & cad, &alen);
            /*
             * gdy dostalismy mniej danych
             */
            if (n < 1) {
		if (UNLIKE(debug_send_request)) {
            		WLOG("ID %d blad recvfrom odebralo %d\n", id, n);            
		}
                continue;
            }
		if (UNLIKE(debug_send_request)) {
            		WLOG_NB("ID %d recvfrom odebralo %d i %d\n", id, n, i);
		}
            /*
             * gdy juz jest to kolejny pakiet
             * to doallokuj strukture
             */
            if (i) {
                res = realloc (res, (i + 2) * sizeof(struct comm *));
       		if (UNLIKE(debug_send_request)) {      
               		WLOG_NB("new ptr %p i %d\n", res, i);
		}
                if (!res) {
			WLOG("realloc error\n");
			exit(-1);	
		}
                /* 
                 * new null pointer - end of array
                 */
                res[i + 1] = (struct comm *)0;
            } // if (i)

            if (res[i]) WLOG("alloc new memory in current %p !!\n", res[i]);
            res[i] = calloc(1, sizeof(struct comm));
            if (!res[i]) {
                WLOG ("malloc error for %d x struct comm: %s\n", i, strerror(errno));
            }

            /*
             * jezeli jest to niepoprawna odpowiedz lub jezeli ma niepoprane ID
             */
            if ((!xml_parse(buff_d, res[i], n)) || (res[i]->id != id) || ((n_start > 0) && (strncmp(res[i]->name, &com[n_start], n_stop) )))  {
		if (UNLIKE(debug_send_request)) {
                 WLOG_NB("ID %d ERROR res->command %s res->name %s\n",id,  res[i]->command, res[i]->name);
		}
                 FREE_GET_LIST(res[i]);                    
                continue;
            }
		if (UNLIKE(debug_send_request)) {
            		WLOG_NB("res[%d] = %p res[0] p1 %p %d buff_d %p\n",i, res[i], &res[0]->part_1, res[0]->part_1, buff_d);            
            		WLOG_NB("od %s odebrano %d bytes command %s name %s p1 %d p2 %d size %d id %d\n\n",  ip, n, res[i]->command, res[i]->name, res[i]->part_1, res[i]->part_2, res[i]->size, res[i]->id);
		}
            /*
             * jezeli zapytanie zwrocil tylko sam naglowek, (part2 = 0)
             * lub jeden pakiet
             */
          if (!res[0]->part_2) {
               struct comm *ret;
              res[0]->good = 1;           
              if (ret_buf) {
                  memcpy(ret_buf, res[0]->buf, res[0]->size);
              }
              ret = res[0];
              free(res);
              return ret;
          }
            /*
             * sprawdzenie czy juz nie mamy tej czesci
             */
            jest = 0;
            for(j = 0;j < i;j++) {
                if (res[j]->part_1 == res[i]->part_1) {
                    jest = 1;
                    break;
                }
            }
            if (jest) {
                FREE_GET_LIST(res[i]);
                continue;
            }
            /*
             * sprawdzenie czy mamy wszystkie czesc
             * szukamy w czesciach p1 = p2
             */
            cur = 0;
            jest = 0;
            /*
             * correct max value from last packet
             */
            if (max < res[i]->part_2) {
                max = res[i]->part_2;
            }
            for(j = 0;j < i + 1;) {
            
                /*
                 * szukamy p1 = 0 - czyli pierwszego pakietu
                 * s - wskaznik na pierwsza czesc
                 */
                if (res[j]->part_1 == 0) 
                    s = j;
                
                /*
                 * czy p1 jest szukanym pakietem
                 * w cur - liczba w kolejnosci juz zebranych pakietow od poczatku
                 */
                if (res[j]->part_1 == cur) {
                    /*
                     * czy szukany pakiet jest ostatnim pakietem
                     */
                    if ((res[j]->part_1 == max)) {
                        jest = 1;
                        break;
                    }
                    /*
                     * jezeli nie doszlismy do ostatniego pakietu
                     * to szukaj kolejnych elementow od poczatku
                     */
                    cur++;
                    cur_size += res[j]->size;
                    j = 0;

                } else j++;
            }
      
            /*
             * jezeli wskaznik przeskoczyl do konca, tzn. ze mamy wszystkie czesci
             */
            if (jest) {
                /*
                 * obliczenie wielkosc wszystkich danych z pakietow
                 * start bierzemy z pierwszego pakietu, stop bierzemy z ostatniego pakietu
                 * s - wsk na pierwszy pakiet
                 * j - wsk na ostatni pakiet
                 */
                char *tot;
                uint32_t estop = res[j]->stop;
                uint32_t size = estop - res[s]->start;
		 uint32_t a = 1;
                 struct comm *ret;
                /*
                 * przegranie tam danych ze wszystkich zadan                 
                 */
                 if (ret_buf)
                     tot = ret_buf;
                 else
                    tot = malloc(size);
                 
                for (j = 0; j < i + 1;j++) {
			if (UNLIKE(debug_send_request)) {
                    		WLOG_NB("start pierwszego pakietu %d start %d pakietu %d stop %d\n", res[s]->start, j, res[j]->start, res[j]->stop);                    
			}
                    memcpy(tot + res[j]->start - res[s]->start, res[j]->buf, res[j]->stop - res[j]->start);
                }
                /*
                 * zwolnienie pierwotnej zawartosci pierwszego requestu
                 */
		if (UNLIKE(debug_send_request)) {
                	WLOG_NB("zwalnianie pierwszego bufora %p\n", res[0]->buf);                
		}
                free (res[0]->buf);
                /*
                 * i zastapienie w pierwszym requescie bufora pelnymi danymi
                 */
                res[0]->buf = tot;
                res[0]->size = size;
                res[0]->start = res[s]->start;
                res[0]->stop = estop;
                /*
                 * zwolnienie reszty buforow
                 */
                for (; res[a];a++) {      
                    FREE_GET_LIST(res[a]);
                }
                res[0]->good = 1;
                ret = res[0];
                free (res);
                
                if (UNLIKE(debug_send_request)) {
			WLOG_NB("koniec, odpowiedz w %p\n", ret);
		}
                
                return ret;
            }
            /*
             * przebudowa pakietu zadania, tak aby zaczac pobieranie danych od dalszych pozycji
             */
            if (cur) {
                uint32_t m = max;
                 memset(buff, 0, BUF);
                 /*
                  * searching any element between cur and max (we don't need request packets that we have)
                  * and request elements from cur_size + 1 to this -1 byte before packet we have
                  */
                 for (j = 0; j <= i; j++) {
                     if ((res[j]->part_1 > cur) && (res[j]->part_1 < m)) {
                         /*
                          * w m najbliszy pakiet, ktory posiadamy za cur i przed max, pierwszy za brakujacymi pakietami
                          */
                         m = j;
                     }
                 }
                 if (m == max)
                     sprintf(buff, "%s<i%d/i><s%d/s><p%u 0/p>", com, id, cur_size,cur);
                 else
                    sprintf(buff, "%s<i%d/i><s%d/s><e%d/e><p%u 0/p>", com, id, cur_size, res[m]->start, cur);       
            }
		if (UNLIKE(debug_send_request)) {
            WLOG_NB("aktualne zapytanie %s\n",buff);            
		}
            /*
             * przeskoczenie do nastepnego elementu
             */
            i++;
        /*
         * TIMEOUT na select
         */
        } else if (r == 0) {
		if (UNLIKE(debug_send_request)) {
            		WLOG_NB("id %d #%d Timeout od %s\n",id, a, ip);
		}
            /*
             * wyslanie raz jeszcze zapytania
             */
            send_ok = 0;
            /*
             * zwieksze ilosc timeout
             */
            a++;
        } else {
           WLOG ("CRITICAL: blad w select\n");
		exit(-1);
	}
    }
out:
    /*
     * 3 x TIMEOUT
     */
	if (UNLIKE(debug_send_request)) {
    WLOG_NB ("zwalnianie pamieci i %d res[0] = %p\n", i, res[0] );     
    WLOG_NB("jestem na koncu\n");    
	}
    a = 0;

    for (a = 0; res[a];a++) {
        FREE_GET_LIST(res[a]);
    }
    
    free(res);
    return 0;
}
