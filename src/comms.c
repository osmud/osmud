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
#include <curl/curl.h>

#include "oms_utils.h"
#include "oms_messages.h"

extern int noFailOnMudValidation;

typedef struct {
    char *fileName;
    FILE *outputFile;
    int data;
} CurlOptions;

/**
 * Iterative call made whenever there is data to write. Data must
 * be appended to the output from prior calls.
 */
size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
    CurlOptions *p = (CurlOptions *)userp;
    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_COMMUNICATION, "in write data");

    return fwrite(buffer, size, nmemb, p->outputFile);
}

int getOpenMudFile(char *mudFile, char *outputFile)
{
  CURL *curl;
  CURLcode retval = CURLE_OK;
  CurlOptions curlData;

  char message[1000];

  curl_global_init(CURL_GLOBAL_DEFAULT);
                logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_COMMUNICATION, "curl_easy_perform() doing it now....");

  curl = curl_easy_init();
  if(curl) {
    curlData.fileName = outputFile;
    curlData.outputFile = fopen(outputFile, "w");
    curlData.data = 1;

    curl_easy_setopt(curl, CURLOPT_URL, mudFile);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curlData);

    // Allow for less strict SSL verification when not enforcing strict MUD file P7S verification
    // This is for debugging only and should not be on in a production setting.
    // Additionally, this will be removed from a future release.
    if (noFailOnMudValidation)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    else
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    struct curl_slist *headers=NULL;
    headers = curl_slist_append(headers, "Accept: application/mud+json");
    headers = curl_slist_append(headers, "Accept-Language: en-us");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl");

    // TODO: If this takes a long time, it can't block the rest of the app
    //       may need this to be a new thread or something of the sort
    retval = curl_easy_perform(curl);

    if(retval != CURLE_OK) {
        sprintf(message, "curl_easy_perform() failed: %s\n", curl_easy_strerror(retval));
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_COMMUNICATION, message);
    } else {
        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_COMMUNICATION, "curl_easy_perform() success");
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
    fclose(curlData.outputFile);
  }

  curl_global_cleanup();

  return retval;
}
