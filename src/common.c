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
