/*
 * funkcja wysyla do klienta zapytania
 * in:
 * 0 - naglowek z zadaniem
 * 1 - jak jest wskaznik, to przekopiowanie ze wskaznika danych do zadania (dla PUT/ADD/RENAME)
 * 2 - wielkosc danych
 * 3 - id polaczenia
 * 4 - adres ip
 * out:
 * wskaznik na wypelniona structure odpowiedzi, ktora nalezy zwolnic bo uzyciu
 */

#ifndef SEND_REQUEST_H

struct comm *get_list(char *, char *, unsigned int, int, char *);
struct comm *send_request(char *, char *, unsigned int, int, char *, char *);

#define SEND_REQUEST_H 1
#endif

