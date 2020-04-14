#ifndef _COMMON
#define _COMMON

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

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

#define FORMAT_IP "%d.%d.%d.%d"
#define IP_TO_FORMAT(num)   ((num) >> 24) & 0xFF, ((num) >> 16) & 0xFF, ((num) >> 8) & 0xFF, ((num) >> 0) & 0xFF

#define FMT_SIZE_T "zu"

size_t                    /* O - Length of string */
strlcpy(char *dst,        /* O - Destination string */
        const char *src,  /* I - Source string */
        size_t size);     /* I - Size of destination string buffer */

char *osm_strdup(const char *s);
char *osm_strndup(const char *s, size_t n);

#endif /* _COMMON */
