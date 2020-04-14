#include <string.h>
#include <stdlib.h>

#include "common.h"


size_t strlcpy(char *dst, const char *src, size_t size)
{
    size_t    srclen;         /* Length of source string */

    /* Figure out how much room is needed */
    size--;
    srclen = strlen(src);

   /* Copy the appropriate amount */
    if (srclen > size)
      srclen = size;

    memcpy(dst, src, srclen);
    dst[srclen] = '\0';

    return (srclen);
}


char *osm_strdup(const char *s)
{
    size_t size = strlen(s) + 1;
    char *p = malloc(size);
    if (p != NULL) {
        memcpy(p, s, size);
    }
    return p;
}


char *osm_strndup(const char *s, size_t n)
{
    char *p = memchr(s, '\0', n);
    if (p != NULL)
        n = p - s;
    p = malloc(n + 1);
    if (p != NULL) {
        memcpy(p, s, n);
        p[n] = '\0';
    }
    return p;
}
