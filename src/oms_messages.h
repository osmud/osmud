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

#ifndef _OMS_MESSAGES
#define _OMS_MESSAGES

typedef struct {
	int messageIndex;
	int severity;
	char *messageText;
} omsMessage;

enum OMS_SEVERITY_CLASSES {
	OMS_CRIT = 1,
	OMS_ERROR = 2,
	OMS_WARN = 3,
	OMS_INFO = 4,
	OMS_DEBUG = 5
};

// Allow the caller to identify the OMS subsystem when creating a message
enum OMS_SUBSYSTEM_CLASSES {
 OMS_SUBSYS_GENERAL,
 OMS_SUBSYS_CONTROLLER,
 OMS_SUBSYS_COMMUNICATION,
 OMS_SUBSYS_MUD_FILE,
 OMS_SUBSYS_DEVICE_INTERFACE
};

void logOmsMessage(int severity, int omsSubsystem, int msgId);
void logOmsGeneralMessage(int severity, int omsSubsystem, char *messageText);
void setOmsLogger(FILE *loggerFd);
void setLoggingLevel(int logLevel);
int getLogLevelFromArg(char *logLevel);
void initializeMessageLogging();

#define CANT_READ_FILE 1
#define CANT_WRITE_FILE 2
#define OUT_OF_MEMORY 3

#endif
