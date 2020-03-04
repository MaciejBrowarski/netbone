#include <stdint.h>
#include <string.h>

#ifndef STRFIND_H
/*
 * DESC:
 * Szukanie w str ciagu z str1
 * IN:
 * str - ciag znakow, w ktorych mam szukac
 * str1 - ciag znakow, ktory szukamy
 * OUT:
 * -1 - nie znaleziono
 * n - index, w ktorym str znalezlismy pierwsza litere z str1
 *
 */
int32_t strfind(char *, char *);
/*
 * same as above but 3rd argument is:
 * int - size of str parameter
 */
int32_t strfind_l(char *, char *, int);
#define STRFIND_H
#endif
