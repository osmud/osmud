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
#include <string.h>
#include <time.h>
#include "oms_messages.h"
#include "oms_utils.h"

FILE *logFile;
int omsLogLevel = OMS_INFO;

const char * omsLogMessages[600];

const char* getMessage(int msgId)
{
	return omsLogMessages[msgId];
}

const char* getSeverityText(enum OMS_SEVERITY_CLASSES severity)
{
   switch (severity)
   {
   	   case OMS_INFO: return "INFO";
   	   case OMS_WARN: return "WARNING";
   	   case OMS_ERROR: return "ERROR";
   	   case OMS_CRIT: return "CRITICAL";
   	   case OMS_DEBUG: return "DEBUG";
   	   default: return "UNKNOWN";
   }
}

int getLogLevelFromArg(char *logLevel)
{
	if (!logLevel)
		return OMS_INFO;

	if (!strcmpi(logLevel, "INFO"))
		return OMS_INFO;
	else if (!strcmpi(logLevel, "WARN"))
		return OMS_WARN;
	else if (!strcmpi(logLevel, "ERROR"))
		return OMS_ERROR;
	else if (!strcmpi(logLevel, "CRITICAL"))
		return OMS_CRIT;
	else if (!strcmpi(logLevel, "DEBUG"))
		return OMS_DEBUG;
	else
		return OMS_INFO;
}

const char* getSubsystemText(enum OMS_SUBSYSTEM_CLASSES subsystem)
{
   switch (subsystem)
   {
   	   case OMS_SUBSYS_GENERAL: return "GENERAL";
   	   case OMS_SUBSYS_CONTROLLER: return "CONTROLLER";
   	   case OMS_SUBSYS_COMMUNICATION: return "COMMUNICATION";
   	   case OMS_SUBSYS_MUD_FILE: return "MUD_FILE_OPERATIONS";
   	   case OMS_SUBSYS_DEVICE_INTERFACE: return "DEVICE_INTERFACE";
   	   default: return "UNKNOWN";
   }
}

void setOmsLogger(FILE *loggerFd)
{
	logFile = loggerFd;
}

void setLoggingLevel(int logLevel)
{
	omsLogLevel = logLevel;
}

void initializeMessageLogging()
{
	/* initialize all with NULL's so invalid codes correspond to NULL pointers */
	memset(omsLogMessages, (long)NULL, 600 * sizeof(const char *));

	omsLogMessages[CANT_READ_FILE] = "Cannot read file";
	omsLogMessages[CANT_WRITE_FILE] = "Cannot write file";
	omsLogMessages[OUT_OF_MEMORY] = "Out of memory";
}

void logOmsMessage(int severity, int omsSubsystem, int msgId)
{
	if (severity <= omsLogLevel) {
		time_t ltime;
		ltime=time(NULL);
		struct tm *tm;
		tm=localtime(&ltime);

		fprintf(logFile, "%04d-%02d-%02d %02d:%02d:%02d %s::%s::%s\n", tm->tm_year+1900, tm->tm_mon,
				tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, getSeverityText(severity), getSubsystemText(omsSubsystem), getMessage(msgId));
		fflush(logFile);
	}
}

void logOmsGeneralMessage(int severity, int omsSubsystem, char * messageText)
{
	if (severity <= omsLogLevel) {
		time_t ltime;
		ltime=time(NULL);
		struct tm *tm;
		tm=localtime(&ltime);

		fprintf(logFile, "%04d-%02d-%02d %02d:%02d:%02d %s::%s::%s\n", tm->tm_year+1900, tm->tm_mon,
				tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, getSeverityText(severity), getSubsystemText(omsSubsystem), messageText);
		fflush(logFile);
	}
}

