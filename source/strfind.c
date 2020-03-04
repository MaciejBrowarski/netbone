#include "strfind.h"
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
int32_t strfind(char *str, char *str1) {
	return strfind_l(str, str1, strlen(str));
}

int32_t strfind_l(char *str, char *str1, int size) {
    int size1 = strlen(str1);
    int a, b = 0;
    int c = -1;

    for (a = 0; a < size; a++) {
         #ifdef DEBUG_STRFIND
         WLOG( "str[%d] = %c str1[%d] %c c %d\n", a, str[a], b, str1[b],c);
         
         #endif
        if (str[a] == str1[b]) {
            if (b == 0) c = a;
            b++;
            if (b == size1) {
                return c;
            }

        } else {
            if (b) a--;
            b = 0;
            c = -1;
        }
    }
    return -1;
}

