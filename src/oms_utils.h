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

#ifndef _OMS_UTILS
#define _OMS_UTILS

char *safe_malloc(unsigned n);
void safe_free(char* p);
char *copystring(const char *s);
int writeStringToFile(char *buf, char *outputFileName);
char *readFileToString(char *inputFileName);
char *remove_ext (char* mystr, char dot, char sep);
char *replaceExtension(char* fileUrl, char *newExtension);
int strcmpi(const char s1[], const char s2[]);

int run_command(char **args);
int run_command_with_output_logged(char *fullCommandLine);
int mkdir_path(char *path);
FILE *fopen_with_path( char *path, char *mode );

#endif
