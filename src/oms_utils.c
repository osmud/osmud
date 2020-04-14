/* Copyright 2018 osMUD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include "oms_messages.h"
#include "oms_utils.h"

char *
safe_malloc(unsigned n)
{
    /* this will call malloc and exit with error if malloc returns 0 */

    char *t;

    if (n)
    {
        if (!(t = malloc(n)))
            logOmsMessage(OMS_CRIT, OMS_SUBSYS_GENERAL, OUT_OF_MEMORY);
    }
    else
    {
        t = 0;
    }
    return t;
}

void
safe_free(char* p)
{
    if (p)
    {
        (void)free(p);
    }
}

char *
copystring(const char *s)
{
    char *st;
    if (!s)
        return 0;
    st = safe_malloc((unsigned)(strlen(s) + 1));
    (void) strcpy(st,s);
    return st;
}

int
strcmpi(const char s1[], const char s2[])
{
/* this routine returns >, ==, or < 0
   as s1 is >, ==, or < s2.  case is
   NOT taken into account */

    int diff, i;
    char c1, c2;

    i = 0;
    do
    {
            c1 = islower(s1[i]) ? toupper(s1[i]) : s1[i];
            c2 = islower(s2[i]) ? toupper(s2[i]) : s2[i];
            diff = c1 - c2;
            i++;
    } while (s1[i - 1] && s2[i - 1] && !diff);
    return diff;
}

int
writeStringToFile(char *buf, char *outputFileName)
{
   int writeResult = 0;
   FILE *fp;

   if (buf && outputFileName) {
       if ((fp = fopen(outputFileName, "w"))) {
           (void)fwrite(buf, sizeof(char), strlen(buf), fp);
           (void)fclose(fp);
           writeResult = 1;
       }
   }

   return writeResult;
}

char *
readFileToString(char *inputFileName)
{
   FILE *fp;
   struct stat statbuf;
   char *fileContents = (char *)0;
   size_t f;

   if (inputFileName) {
       if ((fp = fopen(inputFileName, "r"))) {
           if (stat(inputFileName, &statbuf) == 0) {
               fileContents = safe_malloc(statbuf.st_size + 1);
               f = fread(fileContents, sizeof(char), statbuf.st_size, fp);
               fileContents[f] = '\0';
           }
           (void)fclose(fp);
       }
   }

   return fileContents;
}


// remove_ext: removes the "extension" from a file spec.
//   mystr is the string to process.
//   dot is the extension separator.
//   sep is the path separator (0 means to ignore).
// Returns an allocated string identical to the original but
//   with the extension removed. It must be freed when you're
//   finished with it.
// If you pass in NULL or the new string can't be allocated,
//   it returns NULL.

char *
remove_ext (char* mystr, char dot, char sep) {
    char *retstr, *lastdot, *lastsep;

    // Error checks and allocate string.

    if (mystr == NULL)
        return NULL;
    if ((retstr = safe_malloc (strlen (mystr) + 1)) == NULL)
        return NULL;

    // Make a copy and find the relevant characters.

    strcpy (retstr, mystr);
    lastdot = strrchr (retstr, dot);
    lastsep = (sep == 0) ? NULL : strrchr (retstr, sep);

    // If it has an extension separator.

    if (lastdot != NULL) {
        // and it's before the extenstion separator.

        if (lastsep != NULL) {
            if (lastsep < lastdot) {
                // then remove it.

                *lastdot = '\0';
            }
        } else {
            // Has extension separator with no path separator.

            *lastdot = '\0';
        }
    }

    // Return the modified string.

    return retstr;
}

/*
 * This will look for the last "." character in fileUrl and replace
 * afterward with newExtension.
 *
 * Caller is responsible for freeing this memory
 */
char *
replaceExtension(char* fileUrl, char *newExtension) {
    char *retstr;
    char *base;
    char *lastdot;

    if (fileUrl == NULL)
         return NULL;

    if (newExtension == NULL)
        return NULL;

    if ((base = safe_malloc(strlen (fileUrl) + 1)) == NULL)
        return NULL;

    if ((retstr = safe_malloc(strlen (fileUrl) + strlen(newExtension) + 1)) == NULL)
        return NULL;

    strcpy (base, fileUrl);
    lastdot = strrchr (base, '.');
    if (lastdot != NULL)
    {
        *lastdot = '\0';
    }

    sprintf(retstr, "%s.%s", base, newExtension);

    safe_free(base);

    return retstr;
}

int
run_command(char **args)
/* args must point to valid memory, terminated with 0 sentinal */
{
    int errorcode = 0;
    pid_t pid;

    if ((pid = fork()) == 0) {
        execvp(args[0],args+1);
    }
    else if (pid == -1)
    {
        errorcode = 1;
    }
    else
    {
        while (wait(&errorcode) != pid);   /* wait for the appropriate child */
    }

    return errorcode;
}

int
run_command_with_output_logged(char *fullCommandLine)
{
    int errorcode = 0;
    int fd[2];
    pipe(fd);
    pid_t childpid;

    int RESULT_SIZE = 10000;
    char result[RESULT_SIZE]; // TODO: Do this better

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, fullCommandLine);

    // TODO: Don't actually run the command just yet.... just return success
    return 0;

    if ((childpid = fork()) == 0) {
        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, "....Execing");
        dup2(fd[1], 1);
        close(fd[0]);
        execlp("/bin/sh", "/bin/sh", "-c", fullCommandLine, NULL);
    }
    else if (childpid == -1)
    {
        errorcode = 1; /* fork failed */
    }
    else
    {
        while (wait(&errorcode) != childpid);   /* wait for the appropriate child */

        read(fd[0], result, RESULT_SIZE);

        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, result);
    }

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_GENERAL, "Returning after done");

    return errorcode;
}

/*
 * Recursive function that will create a list of directories. It uses stack memory
 * and assumes the path input is memory that can be modified.
 * Returns 0 - successful path creation
 *         1 - something went wrong
 */
int mkdir_path(char *path)
{
    int result = 0;
    char *sep = strrchr(path, '/' );

    if(sep != NULL) {
        *sep = 0;
        if ((result = mkdir_path(path))) {
            /* There was a problem making the path - stop and return error */
            return 1;
        }
        *sep = '/';
    }

    if (*path) {
        if( mkdir(path,0755) && errno != EEXIST ) {
            return 1;
        } else {
            return 0;
        }
    }
    /* else, a null path does not cause an error - it's skipped */

    return 0;
}

/*
 * Attempts to open a file that includes a path. All parts of the path will try to be created
 * If the path cannot be created or the file cannot be opened, null will be returned
 */
FILE *fopen_with_path(char *path, char *mode)
{
    char *sep = strrchr(path, '/' );
    int result = 0;

    if (sep) {
        char *path_t = strdup(path);
        path_t[sep - path] = 0;
        result = mkdir_path(path_t);
        safe_free(path_t);
    }

    if (!result)
        return fopen(path, mode);
    else
        return (FILE *)0;
}
