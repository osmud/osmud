#ifndef _COMMON
#define _COMMON

#include <stdio.h>


#include "oms_messages.h"

#define CHECK_NOT_NULL(ptr, ret)                                \
do                                                              \
{                                                               \
    if (ptr == NULL)                                            \
    {                                                           \
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_GENERAL,     \
                            "[%s:%d] %s is NULL",               \
                            __FUNCTION__, __LINE__, #ptr);      \
                                                                \
        return ret;                                             \
    }                                                           \
} while (0)

#define PRIu8 "hu"
#define PRId8 "hd"
#define PRIx8 "hx"
#define PRIu16 "hu"
#define PRId16 "hd"
#define PRIx16 "hx"
#define PRIu32 "u"
#define PRId32 "d"
#define PRIx32 "x"
#define PRIu64 "llu"
#define PRId64 "lld"
#define PRIx64 "llx"

#define FMT_SIZE_T "zu"

size_t                    /* O - Length of string */
strlcpy(char *dst,        /* O - Destination string */
        const char *src,  /* I - Source string */
        size_t size);     /* I - Size of destination string buffer */

#endif /* _COMMON */
