/*
 * ftpserv.c
 *
 *  Created on: Aug 20, 2016
 *
 *  Modified on: Sep 01, 2019
 *
 *      Author: lightftp
 * 
 * 
 * Copyright (c) LightFTP 2007 - 2019 Project authors
 *
 * Port to ESP32, and changes to support IPv6, are (c) 2020, 2023 by Danny Backx.
 * Also turned into an esp-idf component, and made most symbols static (internal to this source).
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 *     Redistributions of source code must retain the above copyright notice, this list
 *     of conditions and the following disclaimer.
 * 
 *     Redistributions in binary form must reproduce the above copyright notice, this
 *     list of conditions and the following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * 
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ftpserv.h"
#include "esp_log.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x4000
#endif
typedef void * gnutls_session_t;

static void * x_malloc(size_t size);	// Forward declaration, avoid additional files

#define	MAX_CMDS 33

static int ftpUSER	(PFTPCONTEXT context, const char *params);
static int ftpQUIT	(PFTPCONTEXT context, const char *params);
static int ftpNOOP	(PFTPCONTEXT context, const char *params);
static int ftpPWD	(PFTPCONTEXT context, const char *params);
static int ftpTYPE	(PFTPCONTEXT context, const char *params);
static int ftpPORT	(PFTPCONTEXT context, const char *params);
static int ftpEPRT	(PFTPCONTEXT context, const char *params);
static int ftpLIST	(PFTPCONTEXT context, const char *params);
static int ftpAPPE	(PFTPCONTEXT context, const char *params);
static int ftpCDUP	(PFTPCONTEXT context, const char *params);
static int ftpCWD	(PFTPCONTEXT context, const char *params);
static int ftpRETR	(PFTPCONTEXT context, const char *params);
static int ftpABOR	(PFTPCONTEXT context, const char *params);
static int ftpDELE	(PFTPCONTEXT context, const char *params);
static int ftpPASV	(PFTPCONTEXT context, const char *params);
static int ftpPASS	(PFTPCONTEXT context, const char *params);
static int ftpREST	(PFTPCONTEXT context, const char *params);
static int ftpSIZE	(PFTPCONTEXT context, const char *params);
static int ftpMKD	(PFTPCONTEXT context, const char *params);
static int ftpRMD	(PFTPCONTEXT context, const char *params);
static int ftpSTOR	(PFTPCONTEXT context, const char *params);
static int ftpSYST	(PFTPCONTEXT context, const char *params);
static int ftpFEAT	(PFTPCONTEXT context, const char *params);
static int ftpRNFR	(PFTPCONTEXT context, const char *params);
static int ftpRNTO	(PFTPCONTEXT context, const char *params);
static int ftpOPTS	(PFTPCONTEXT context, const char *params);
static int ftpMLSD	(PFTPCONTEXT context, const char *params);
static int ftpAUTH (PFTPCONTEXT context, const char *params);
static int ftpPBSZ (PFTPCONTEXT context, const char *params);
static int ftpPROT (PFTPCONTEXT context, const char *params);
static int ftpEPSV (PFTPCONTEXT context, const char *params);
static int ftpHELP (PFTPCONTEXT context, const char *params);
static int ftpSITE (PFTPCONTEXT context, const char *params);

static const FTPROUTINE ftpprocs[MAX_CMDS] = {
  ftpUSER, ftpQUIT, ftpNOOP, ftpPWD, ftpTYPE, ftpPORT, ftpLIST, ftpCDUP,
  ftpCWD, ftpRETR, ftpABOR, ftpDELE, ftpPASV, ftpPASS, ftpREST, ftpSIZE,
  ftpMKD, ftpRMD, ftpSTOR, ftpSYST, ftpFEAT, ftpAPPE, ftpRNFR, ftpRNTO,
  ftpOPTS, ftpMLSD, ftpAUTH, ftpPBSZ, ftpPROT, ftpEPSV, ftpHELP, ftpSITE,
  ftpEPRT
};

static const char *ftpcmds[MAX_CMDS] = {
  "USER", "QUIT", "NOOP", "PWD",  "TYPE", "PORT", "LIST", "CDUP",
  "CWD",  "RETR", "ABOR", "DELE", "PASV", "PASS", "REST", "SIZE",
  "MKD",  "RMD",  "STOR", "SYST", "FEAT", "APPE", "RNFR", "RNTO",
  "OPTS", "MLSD", "AUTH", "PBSZ", "PROT", "EPSV", "HELP", "SITE",
  "EPRT"
};

/*
 * FTP_PASSCMD_INDEX
 * must be in sync with ftpprocs & ftpcmds "PASS" index
 */
#define FTP_PASSCMD_INDEX  13

static unsigned int g_newid = 0;

static void delete_last_slash(char *s)
{
  if (*s != 0)
  {
    /*
     * don't remove root directory sign as special case
     */
    if ((s[0] == '/') && (s[1] == 0))
      return;

    while (s[1] != 0)
      ++s;

    if (*s == '/')
      *s = 0;
  }
}

static void add_last_slash(char *s)
{
  if (*s != 0)
  {
    while (s[1] != 0)
      ++s;

    if (*s != '/')
    {
      s[1] = '/';
      s[2] = 0;
    }
  }
}

/*
 * Cuts off filename from string leaving only path.
 * Return value: pointer to a terminating null character at the end of path
 */
static char *filepath(char *s)
{
  char  *p = s;

  if (*s == 0)
    return s;
/*
 * leave root directory sign untouched
 */
  if (*s == '/')
  {
    ++s;
    ++p;
  }

  while (*s != 0) {
    if (*s == '/')
      p = s;
    ++s;
  }

  *p = 0;

  return p;
}

/*
 * This function filters the path out of ".." members
 * not allowing user to escape the home directory
 */
static void format_path(char *input_path, char *filtered_path)
{
  char  *p0, *pnext, *fp0;
  size_t  sl;

  if (*input_path == '/')
  {
    ++input_path;
    *filtered_path = '/';
    ++filtered_path;
  }

  p0 = input_path;
  pnext = input_path;
  fp0 = filtered_path;
  *fp0 = 0;

  while (1)
  {
    while ((*pnext != '/') && (*pnext != 0))
      ++pnext;

    sl = pnext - p0;

    while (sl > 0)
    {
      if (sl == 1)
        if (*p0 == '.')
          break;

      if (sl == 2)
        if ((p0[0] == '.') && (p0[1] == '.'))
        {
          delete_last_slash(filtered_path);
          fp0 = filepath(filtered_path);
          if (fp0 != filtered_path)
          {
            *fp0 = '/';
            ++fp0;
            *fp0 = 0;
          }
          break;
        }

      strncpy(fp0, p0, sl);
      fp0 += sl;
      if (*pnext != 0)
      {
        *fp0 = '/';
        ++fp0;
      }
      *fp0 = 0;

      break;
    }

    if (*pnext == 0)
      break;

    ++pnext;
    p0 = pnext;
  }
}

static char *finalpath(char *root_dir, char *current_dir, char *params, char *result_path)
{
  char  *tmp, *user_root;
  size_t  total_len;

  total_len = strlen(root_dir)+strlen(current_dir);
  if (params != NULL)
    total_len += strlen(params);

  if (total_len >= SIZE_OF_GPBUFFER)
    return NULL;

  tmp = (char *)x_malloc(SIZE_OF_GPBUFFER);

  strcpy(result_path, root_dir);
  add_last_slash(result_path);
  user_root = result_path+strlen(result_path);

  do {
    if ( params == NULL )
    {
      strcpy(tmp, current_dir);
      add_last_slash(tmp);
      break;
    }

    if ( params[0] != '/' )
    {
      strcpy(tmp, current_dir);
      add_last_slash(tmp);
    }

    strcat(tmp, params);
  } while (0);

  format_path(tmp, user_root);
  free(tmp);
  return result_path;
}

static ssize_t sendstring_plaintext(SOCKET s, const char *Buffer)
{
  ESP_LOGD("ftp", "sendstring %s", Buffer);
  return (send(s, Buffer, strlen(Buffer), MSG_NOSIGNAL) >= 0);
}

static SOCKET create_datasocket(PFTPCONTEXT context)
{
  SOCKET        clientsocket = INVALID_SOCKET;
  struct sockaddr_in6  laddr;
  socklen_t      asz;

  memset(&laddr, 0, sizeof(laddr));
  ESP_LOGD("ftp", "create_datasocket(AF %d, IPv%d)", context->af, (context->af == AF_INET) ? 4 : 6);

  switch ( context->Mode ) {
  case MODE_NORMAL:
    clientsocket = socket(context->af, SOCK_STREAM, IPPROTO_TCP);
    context->DataSocket = clientsocket;
    if ( clientsocket == INVALID_SOCKET ) {
      ESP_LOGD("ftp", "create_datasocket : socket %d %s", errno, strerror(errno));
      return INVALID_SOCKET;
    }

    laddr.sin6_family = context->af;
    laddr.sin6_port = context->DataPort;

    if (context->af == AF_INET6)
      laddr.sin6_addr = context->DataIPv6;
    else {
      struct sockaddr_in *sa = (struct sockaddr_in *)&laddr;
      sa->sin_family = AF_INET;
      sa->sin_port = context->DataPort;
      sa->sin_addr.s_addr = context->DataIPv4;
      ESP_LOGD("ftp", "create_datasocket : remote port %d", ntohs(sa->sin_port));
    }

    if (connect(clientsocket, (const struct sockaddr *)&laddr, sizeof(laddr)) == -1) {
      ESP_LOGD("ftp", "create_datasocket : connect %d %s", errno, strerror(errno));
      close(clientsocket);
      return INVALID_SOCKET;
    }
    break;

  case MODE_PASSIVE:
    asz = sizeof(laddr);
    clientsocket = accept(context->DataSocket, (struct sockaddr *)&laddr, &asz);
    close(context->DataSocket);
    context->DataSocket = clientsocket;

    if ( clientsocket == INVALID_SOCKET ) {
      ESP_LOGE("ftp", "create_datasocket : accept %d %s", errno, strerror(errno));
      return INVALID_SOCKET;
    }

    bzero(&context->DataIPv6, 0);
    context->DataIPv4 = 0;

    context->DataPort = 0;
    context->Mode = MODE_NORMAL;
    break;

  default:
    ESP_LOGE("ftp", "create_datasocket : default (-> invalid socket)");
    return INVALID_SOCKET;
  }
  return clientsocket;
}

static ssize_t sendstring(PFTPCONTEXT context, const char *Buffer)
{
  size_t  l = strlen(Buffer);
  ESP_LOGD("ftp", "sendstring %s", Buffer);

  return (send(context->ControlSocket, Buffer, l, MSG_NOSIGNAL) >= 0);
}

static ssize_t sendstring_auto(SOCKET s, gnutls_session_t session, const char *Buffer)
{
  size_t  l = strlen(Buffer);

  if (session == NULL)
    return (send(s, Buffer, l, MSG_NOSIGNAL) >= 0);
  else return 0;
}

static ssize_t send_auto(int __fd, gnutls_session_t session, const void *__buf, size_t __n)
{
  if (session == NULL)
    return (send(__fd, __buf, __n, MSG_NOSIGNAL));
  else return 0;
}

static ssize_t recv_auto(int __fd, gnutls_session_t session, void *__buf, size_t __n)
{
  if (session == NULL)
    return (recv(__fd, __buf, __n, 0));
  else return 0;
}

static ssize_t writeconsolestr(const char *buffer)
{
  ESP_LOGD("FTP Server", "%s", buffer);
  return 0;
}

static int writelogentry(PFTPCONTEXT context, const char *logtext1, const char *logtext2)
{
  char    text[SIZE_OF_GPBUFFER];
  time_t    itm = time(NULL);
  struct tm  ltm;

  localtime_r(&itm, &ltm);

  if (context == NULL)
  {
    snprintf(text, sizeof(text), "%02u-%02u-%u %02u:%02u:%02u : %s%s",
        ltm.tm_mday, ltm.tm_mon+1, ltm.tm_year+1900,
        ltm.tm_hour, ltm.tm_min, ltm.tm_sec, logtext1, logtext2 ? logtext2 : "");
  }
  else
  {
    snprintf(text, sizeof(text), "%02u-%02u-%u %02u:%02u:%02u S-id=%u : %s%s",
        ltm.tm_mday, ltm.tm_mon+1, ltm.tm_year+1900,
        ltm.tm_hour, ltm.tm_min, ltm.tm_sec,
        context->SessionID, logtext1, logtext2 ? logtext2 : "");
  }

  return writeconsolestr(text);
}

static void WorkerThreadCleanup(PFTPCONTEXT context)
{
  // int          err;
  // void        *retv = NULL;

  if ( context->WorkerThreadValid == 0 ) {

    /*
     * trying to stop gracefully
     */
    context->WorkerThreadAbort = 1;
    sleep(2);

    context->WorkerThreadValid = -1;
  }

  if ( context->DataSocket != INVALID_SOCKET ) {
    close(context->DataSocket);
    context->DataSocket = INVALID_SOCKET;
  }

  if ( context->File != -1 ) {
    close(context->File);
    context->File = -1;
  }

    bzero(&context->DataIPv6, 0);
    context->DataIPv4 = 0;

  context->DataPort = 0;
  //writelogentry(context, "WorkerThreadCleanup complete", "");
}

static int ftpUSER(PFTPCONTEXT context, const char *params)
{
  if ( params == NULL )
    return sendstring(context, error501);

  context->Access = FTP_ACCESS_NOT_LOGGED_IN;

  /*
   * Save username in GPBuffer for next PASS command
   */

  writelogentry(context, " USER: ", (char *)params);

  strcpy(context->GPBuffer, interm331);
  strcat(context->GPBuffer, params);
  strcat(context->GPBuffer, interm331_tail);
  sendstring(context, context->GPBuffer);

  strcpy(context->GPBuffer, params);
  return 1;
}

static int ftpQUIT(PFTPCONTEXT context, const char *params)
{
  writelogentry(context, " QUIT", "");
  sendstring(context, success221);
  /*
   * retrun 0 to break command processing loop
   */
  return 0;
}

int ftpNOOP(PFTPCONTEXT context, const char *params)
{
  return sendstring(context, success200);
}

static int ftpPWD(PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);

  strcpy(context->GPBuffer, "257 \"");
  strcat(context->GPBuffer, context->CurrentDir);
  strcat(context->GPBuffer, "\" is a current directory.\r\n");
  return sendstring(context, context->GPBuffer);
}

int ftpTYPE(PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);

  if (params == NULL)
    return sendstring(context, error501);

  switch (*params)
  {
  case 'A':
  case 'a':
    return sendstring(context, success200_1);
  case 'I':
  case 'i':
    return sendstring(context, success200_2);
  }

  return sendstring(context, error501);
}

static char *ShowIPv6(in6_addr *ia, int sz) {
  static char res[21], x[5];
  res[0] = 0;
  for (int i=0; i<16; i+=2) {
    if (i != 0)
      strcat(res, ":");
    sprintf(x, "%02x%02x", ia->un.u8_addr[i], ia->un.u8_addr[i+1]);
    strcat(res, x);
  }
  return res;
}

/*
 * See RFC 2428.
 * EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>
 * Examples
 *  EPRT |1|132.235.1.2|6275|
 *  EPRT |2|1080::8:800:200C:417A|5282|
 */
static int ftpEPRT(PFTPCONTEXT context, const char *params)
{
  ESP_LOGD("ftp", "ftpEPRT %s", params);

  in_addr_t	DataIP4;
  in6_addr	DataIP;
  uint32_t	DataPort;
  char		*p = (char *)params;
  int		af;

  if (*p++ != '|') {
    return sendstring(context, error501);
  }
  switch (*p++) {
  case '1':	// IPv4
    af = AF_INET;
    if (inet_pton(af, ++p, (char *)&DataIP4) <= 0) {
      ESP_LOGD("ftp", "ftpEPRT line %d error 501", __LINE__);
      return sendstring(context, error501);
    }
    p = strchr(p, '|');
    if (p == 0) {
      ESP_LOGD("ftp", "ftpEPRT line %d error 501", __LINE__);
      return sendstring(context, error501);
    }
    DataPort = htons(strtoul(++p, NULL, 10));
    if ( DataIP4 != context->ClientIPv4 ) {
      ESP_LOGD("ftp", "ftpEPRT line %d error 501", __LINE__);
      return sendstring(context, error501);
    }
    context->DataIPv4 = DataIP4;
    break;
  case '2':	// IPv6
    af = AF_INET6;
    if (inet_pton(af, ++p, (char *)&DataIP) <= 0) {
      ESP_LOGD("ftp", "ftpEPRT line %d error 501 (%s)", __LINE__, p);
      return sendstring(context, error501);
    }
    p = strchr(p, '|');
    if (p == 0) {
      ESP_LOGD("ftp", "ftpEPRT line %d error 501", __LINE__);
      return sendstring(context, error501);
    }
    DataPort = htons(strtoul(++p, NULL, 10));
    ESP_LOGD("ftp", "ftpEPRT port %d", (int)DataPort);
    if (memcmp(&DataIP, &context->ClientIPv6, sizeof(in6_addr)) != 0) {
      ESP_LOGD("ftp", "ftpEPRT line %d difference", __LINE__);
      ESP_LOGD("ftp", "ftpEPRT DataIP %s", ShowIPv6(&DataIP, sizeof(in6_addr)));
      ESP_LOGD("ftp", "ftpEPRT ClientIP %s", ShowIPv6(&context->ClientIPv6, sizeof(in6_addr)));
      return sendstring(context, error501);
    }
    context->DataIPv6 = DataIP;
    break;
  default:
    ESP_LOGE("ftp", "ftpEPRT line %d error 501", __LINE__);
    return sendstring(context, error501);
  }

  context->DataPort = DataPort;
  context->Mode = MODE_NORMAL;

  ESP_LOGD("ftp", "success200 dataport = %d", ntohs(DataPort));
  return sendstring(context, success200);
}

// IPv4
static int ftpPORT(PFTPCONTEXT context, const char *params)
{
  int      c;
  in_addr_t  DataIP = 0, DataPort = 0;
  char    *p = (char *)params;

  ESP_LOGD("ftp", "ftpPORT %s", params);

  bzero(&DataIP, 0);
  bzero(&DataPort, 0);
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);

  if ( params == NULL )
    return sendstring(context, error501);

  for (c = 0; c < 4; c++) {
    DataIP += ((unsigned char)strtoul(p, NULL, 10)) << c*8;
    while ( (*p >= '0') && (*p <= '9') )
      p++;
    if ( *p == 0 )
      break;
    p++;
  }

  for (c = 0; c < 2; c++) {
    DataPort += ((unsigned char)strtoul(p, NULL, 10)) << c*8;
    while ( (*p >= '0') && (*p <= '9') )
      p++;
    if ( *p == 0 )
      break;
    p++;
  }

  if ( DataIP != context->ClientIPv4 ) {
    return sendstring(context, error501);
  }

  context->DataIPv4 = DataIP;
  context->DataPort = DataPort;
  context->Mode = MODE_NORMAL;

  ESP_LOGD("ftp", "success200 dataport = %d", ntohs(DataPort));
  return sendstring(context, success200);
}

/*
filemode.c -- make a string describing file modes

  Copyright (C) 1985, 1990, 1993, 1998-2000, 2004, 2006, 2009-2018 Free
  Software Foundation, Inc.
*/

/* Return a character indicating the type of file described by
   file mode BITS:
   '-' regular file
   'b' block special file
   'c' character special file
   'C' high performance ("contiguous data") file
   'd' directory
   'D' door
   'l' symbolic link
   'm' multiplexed file (7th edition Unix; obsolete)
   'n' network special file (HP-UX)
   'p' fifo (named pipe)
   'P' port
   's' socket
   'w' whiteout (4.4BSD)
   '?' some other file type  */

static char
ftypelet (mode_t bits)
{
  /* These are the most common, so test for them first.  */
  if (S_ISREG (bits))
    return '-';
  if (S_ISDIR (bits))
    return 'd';

  /* Other letters standardized by POSIX 1003.1-2004.  */
  if (S_ISBLK (bits))
    return 'b';
  if (S_ISCHR (bits))
    return 'c';
  if (S_ISLNK (bits))
    return 'l';
  if (S_ISFIFO (bits))
    return 'p';

  /* Other file types (though not letters) standardized by POSIX.  */
  if (S_ISSOCK (bits))
    return 's';

  return '?';
}

/* Like filemodestring, but rely only on MODE.  */

static void
strmode (mode_t mode, char *str)
{
  str[0] = ftypelet (mode);
  str[1] = mode & S_IRUSR ? 'r' : '-';
  str[2] = mode & S_IWUSR ? 'w' : '-';
  str[3] = (mode & S_ISUID
            ? (mode & S_IXUSR ? 's' : 'S')
            : (mode & S_IXUSR ? 'x' : '-'));
  str[4] = mode & S_IRGRP ? 'r' : '-';
  str[5] = mode & S_IWGRP ? 'w' : '-';
  str[6] = (mode & S_ISGID
            ? (mode & S_IXGRP ? 's' : 'S')
            : (mode & S_IXGRP ? 'x' : '-'));
  str[7] = mode & S_IROTH ? 'r' : '-';
  str[8] = mode & S_IWOTH ? 'w' : '-';
  str[9] = (mode & S_ISVTX
            ? (mode & S_IXOTH ? 't' : 'T')
            : (mode & S_IXOTH ? 'x' : '-'));
  str[10] = ' ';
  str[11] = '\0';
}

/*
  END  filemode.c
*/

static int list_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry)
{
  char      text[SIZE_OF_GPBUFFER],
          sacl[12];

  struct stat    filestats;
  struct tm    ftm_fields;
  time_t      deltatime;

  if (strcmp(entry->d_name, ".") == 0)
    return 1;
  if (strcmp(entry->d_name, "..") == 0)
    return 1;

  strcpy(text, dirname);
  add_last_slash(text);
  strcat(text, entry->d_name);
#if 0
  if ( lstat(text, &filestats) == 0 )
#else
  if (stat(text, &filestats) == 0)
#endif
  {
    strmode(filestats.st_mode, sacl);

    localtime_r(&filestats.st_mtime, &ftm_fields);
    deltatime = time(NULL) - filestats.st_mtime;

    if (deltatime <= 180*24*60*60) {
      snprintf(text, sizeof(text), "%s %u %lu %lu %llu %s %02u %02u:%02u %s\r\n",
        sacl, filestats.st_nlink,
        (unsigned long int)filestats.st_uid,
        (unsigned long int)filestats.st_gid,
        (unsigned long long int)filestats.st_size,
        shortmonths[(ftm_fields.tm_mon)], ftm_fields.tm_mday,
        ftm_fields.tm_hour, ftm_fields.tm_min, entry->d_name);
    }
    else
    {
      snprintf(text, sizeof(text), "%s %u %lu %lu %llu %s %02u %02u %s\r\n",
        sacl, filestats.st_nlink,
        (unsigned long int)filestats.st_uid,
        (unsigned long int)filestats.st_gid,
        (unsigned long long int)filestats.st_size,
        shortmonths[(ftm_fields.tm_mon)], ftm_fields.tm_mday,
        ftm_fields.tm_year + 1900, entry->d_name);
    }

  }

  return sendstring_auto(s, session, text);
}

static void *list_thread(PFTPCONTEXT context)
{
  SOCKET        clientsocket;
  int          ret;
  DIR          *pdir;
  struct dirent    *entry;

  ret = 0;
  // TLS_datasession = NULL;

  clientsocket = create_datasocket(context);
  while (clientsocket != INVALID_SOCKET)
  {
#if 0
    if (context->TLS_session != NULL)
      InitTLSSession(&TLS_datasession, clientsocket, 0);
#endif
    pdir = opendir(context->GPBuffer);
    if (pdir == NULL)
      break;

    while ((entry = readdir(pdir)) != NULL) {
#if 0
      ret = list_sub(context->GPBuffer, clientsocket, TLS_datasession, entry);
#else
      ret = list_sub(context->GPBuffer, clientsocket, 0, entry);
#endif
      if ( (ret == 0) || (context->WorkerThreadAbort != 0 ))
        break;
    }

    closedir(pdir);
    break;
  }
  writelogentry(context, " LIST complete", "");

  if (clientsocket == INVALID_SOCKET) {
    sendstring(context, error451);
  }
  else {
    if ((context->WorkerThreadAbort == 0) && (ret != 0))
      sendstring(context, success226);
    else
      sendstring(context, error426);

    close(clientsocket);
    context->DataSocket = INVALID_SOCKET;
  }

  context->WorkerThreadValid = -1;
  return NULL;
}

static int ftpLIST(PFTPCONTEXT context, const char *params)
{
  struct  stat  filestats;

  if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
    return sendstring(context, error530);
  if (context->WorkerThreadValid == 0)
    return sendstring(context, error550_t);

  if (params != NULL)
  {
    if ((strcmp(params, "-a") == 0) || (strcmp(params, "-l") == 0))
      params = NULL;
  }

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  while (stat(context->GPBuffer, &filestats) == 0)
  {
    if ( !S_ISDIR(filestats.st_mode) )
      break;

    sendstring(context, interm150);
    writelogentry(context, " LIST", (char *)params);
    context->WorkerThreadAbort = 0;

    list_thread(context);

    return 1;
  }

  return sendstring(context, error550);
}

static int ftpCDUP(PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);

  if ( strcmp(context->CurrentDir, "/") == 0 )
    return sendstring(context, success250);

  delete_last_slash(context->CurrentDir);
  filepath(context->CurrentDir);

  writelogentry(context, " CDUP", "");
  return sendstring(context, success250);
}

static int ftpCWD(PFTPCONTEXT context, const char *params)
{
  // struct  stat  filestats;
  size_t      rl;

  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);

  if ( params == NULL )
    return sendstring(context, error501);

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;
#if 1
  // SPIFFS doesn't do directories, so stat() always fails
  rl = strlen(context->RootDir);
  strcpy(context->CurrentDir, context->GPBuffer+rl);
  writelogentry(context, " CWD: ", context->CurrentDir);
  return sendstring(context, success250);
#else
  if ( stat(context->GPBuffer, &filestats) == 0 ) {
    if ( S_ISDIR(filestats.st_mode) )
    {
      rl = strlen(context->RootDir);
      strcpy(context->CurrentDir, context->GPBuffer+rl);
      writelogentry(context, " CWD: ", context->CurrentDir);
      return sendstring(context, success250);
    }
  }
#endif

  return sendstring(context, error550);
}

static void *retr_thread(PFTPCONTEXT context)
{
  volatile SOCKET    clientsocket;
  int          sent_ok, f;
  off_t        offset;
  ssize_t        sz, sz_total;
  size_t        buffer_size;
  char        *buffer;
  struct timespec    t;
  signed long long  lt0, lt1, dtx;

  f = -1;
  sent_ok = 0;
  sz_total = 0;
  buffer = NULL;
  // TLS_datasession = NULL;
  clock_gettime(CLOCK_MONOTONIC, &t);
  lt0 = t.tv_sec*1e9 + t.tv_nsec;
    dtx = t.tv_sec+30;

  buffer = (char *)malloc(TRANSMIT_BUFFER_SIZE);
  if (buffer == 0) {
    ESP_LOGE("ftp", "%s: malloc failed", __FUNCTION__);
    sendstring(context, error550_t);
    return NULL;
  }

  while (buffer != NULL)
  {
        clientsocket = create_datasocket(context);
        if (clientsocket == INVALID_SOCKET)
            break;

    buffer_size = TRANSMIT_BUFFER_SIZE;

    f = open(context->GPBuffer, O_RDONLY);
    context->File = f;
    if (f == -1)
      break;

    offset = lseek(f, context->RestPoint, SEEK_SET);
    if (offset != context->RestPoint)
      break;

    while ( context->WorkerThreadAbort == 0 ) {
      sz = read(f, buffer, buffer_size);
      if (sz <= 0)
        break;

      sz_total += sz;

#if 0
      if (send_auto(clientsocket, TLS_datasession, buffer, sz) == sz)
#else
      if (send_auto(clientsocket, 0, buffer, sz) == sz)
#endif
        sent_ok = 1;
      else
      {
        sent_ok = 0;
        break;
      }

            /* heartbeat to control channel */
            clock_gettime(CLOCK_MONOTONIC, &t);
            if (t.tv_sec >= dtx)
            {
               dtx += 120;
               sendstring(context, "\r\n");
               writelogentry(context, "keepalive sent", "");
            }
    }

    /* calculating performance */

    clock_gettime(CLOCK_MONOTONIC, &t);
    lt1 = t.tv_sec*1e9 + t.tv_nsec;
    dtx = lt1 - lt0;
      snprintf(buffer, buffer_size, " RETR complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
        sz_total, sz_total/1048576.0, dtx/1000000000.0, (1000000000.0*sz_total)/dtx/1048576);
        writelogentry(context, buffer, "");

    break;
  }

  if (f != -1)
    close(f);

  context->File = -1;

    if (buffer != NULL) {
      free(buffer);
    }

  if (clientsocket == INVALID_SOCKET) {
    sendstring(context, error451);
  }
  else {
    if ((context->WorkerThreadAbort == 0) && (sent_ok != 0))
      sendstring(context, success226);
    else
      sendstring(context, error426);

    close(clientsocket);
    context->DataSocket = INVALID_SOCKET;
  }

  context->WorkerThreadValid = -1;
  return NULL;
}

static int ftpRETR(PFTPCONTEXT context, const char *params)
{
  struct  stat  filestats;

  if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
    return sendstring(context, error530);
  if (context->WorkerThreadValid == 0)
    return sendstring(context, error550_t);
  if ( params == NULL )
    return sendstring(context, error501);

  if ( context->File != -1 ) {
    close(context->File);
    context->File = -1;
  }

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  while (stat(context->GPBuffer, &filestats) == 0)
  {
    if ( S_ISDIR(filestats.st_mode) )
      break;

    sendstring(context, interm150);
    writelogentry(context, " RETR: ", (char *)params);
    context->WorkerThreadAbort = 0;

    retr_thread(context);

    return 1;
  }

  return sendstring(context, error550);
}

static int ftpABOR(PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);

  writelogentry(context, " ABORT command", NULL);
  WorkerThreadCleanup(context);
  return sendstring(context, success226);
}

int ftpDELE(PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);
  if ( context->Access < FTP_ACCESS_FULL )
    return sendstring(context, error550_r);
  if ( params == NULL )
    return sendstring(context, error501);

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  if ( unlink(context->GPBuffer) == 0 ) {
    sendstring(context, success250);
    writelogentry(context, " DELE: ", (char *)params);
  }
  else
    sendstring(context, error550_r);

  return 1;
}

static int pasv(PFTPCONTEXT context)
{
  SOCKET        datasocket;
  struct sockaddr_in  laddr;
  int          socketret = -1, result = 0;
  //unsigned long    c;
  //struct  timespec  rtctime;

  while (1)
  {
    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    {
      sendstring(context, error530);
      break;
    }

    if ( context->WorkerThreadValid == 0 )
    {
      sendstring(context, error550_t);
      break;
    }

    if ( context->DataSocket != INVALID_SOCKET )
      close(context->DataSocket);

    context->DataSocket = INVALID_SOCKET;

    datasocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (datasocket == INVALID_SOCKET)
    {
      sendstring(context, error451);
      break;
    }
#if 0
    for (c = g_cfg.PasvPortBase; c <= g_cfg.PasvPortMax; c++) {
      clock_gettime(CLOCK_REALTIME, &rtctime);
      memset(&laddr, 0, sizeof(laddr));
      laddr.sin_family = AF_INET;
      laddr.sin_port = htons((in_port_t)(g_cfg.PasvPortBase +
        (rtctime.tv_nsec % (g_cfg.PasvPortMax-g_cfg.PasvPortBase))));
      laddr.sin_addr.s_addr = context->ServerIPv4;
      socketret = bind(datasocket, (struct sockaddr *)&laddr, sizeof(laddr));
      if ( socketret == 0 )
        break;
    }
#endif
    if ( socketret != 0 ) {
      close(datasocket);
      sendstring(context, error451);
      break;
    }

    socketret = listen(datasocket, 5);
    if (socketret != 0) {
      close(datasocket);
      sendstring(context, error451);
      break;
    }
#if 0
    if ((context->ClientIPv4 & g_cfg.LocalIPMask) == (context->ServerIPv4 & g_cfg.LocalIPMask))
    {
      context->DataIPv4 = context->ServerIPv4;
      writelogentry(context, " local client.", "");
    } else {
      context->DataIPv4 = g_cfg.ExternalInterface;
      writelogentry(context, " nonlocal client.", "");
    }
#endif
    context->DataPort = laddr.sin_port;
    context->DataSocket = datasocket;
    context->Mode = MODE_PASSIVE;

    result = 1;
    break;
  }

  return result;
}

static int ftpEPSV (PFTPCONTEXT context, const char *params)
{
  if (pasv(context) == 0)
    return 1;

  snprintf(context->GPBuffer, SIZE_OF_GPBUFFER, success229,
      ntohs(context->DataPort));

  writelogentry(context, " entering extended passive mode", "");

  return sendstring(context, context->GPBuffer);
}

static int ftpPASV(PFTPCONTEXT context, const char *params)
{
  if (pasv(context) == 0)
    return 1;

  snprintf(context->GPBuffer, SIZE_OF_GPBUFFER, success227,
      (unsigned int)context->DataIPv4 & 0xff,
      (unsigned int)(context->DataIPv4 >> 8) & 0xff,
      (unsigned int)(context->DataIPv4 >> 16) & 0xff,
      (unsigned int)(context->DataIPv4 >> 24) & 0xff,
      (unsigned int)context->DataPort & 0xff,
      (unsigned int)(context->DataPort >> 8) & 0xff);

  writelogentry(context, " entering passive mode", "");

  return sendstring(context, context->GPBuffer);
}

static int ftpPASS(PFTPCONTEXT context, const char *params)
{
  char  temptext[256];

  if ( params == NULL )
    return sendstring(context, error501);

  memset(temptext, 0, sizeof(temptext));

  /*
   * we have username saved in context->GPBuffer from USER command
   */
  /*
   * No configuration
   */
#if 1
  // FIXME
    strcpy(temptext, "admin");  // HACK
    context->Access = FTP_ACCESS_FULL;
#else
  // if (config->ftpUser() == 0) {
    strcpy(temptext, "admin");  // HACK
    context->Access = FTP_ACCESS_FULL;
  } else 
  /*
   * Userid and Password
   */
  if (config->ftpUser() && (strcmp(context->GPBuffer, config->ftpUser()) == 0)
   && config->ftpPass() && (strcmp(params, config->ftpPass()) == 0)) {
    strcpy(temptext, "admin");
    context->Access = FTP_ACCESS_FULL;
  } else
  /*
   * Userid but no password
   */
  if (config->ftpUser() && (strcmp(context->GPBuffer, config->ftpUser()) == 0)
   && (config->ftpPass() == 0)) {
    strcpy(temptext, "admin");
    context->Access = FTP_ACCESS_FULL;
  } else {
  /*
   * Fail
   */
    ESP_LOGE("ftpPASS", "logon error (temptext %s)", temptext);
    return sendstring(context, error530_r);
  }
#endif
  writelogentry(context, " PASS->successful logon", "");
  return sendstring(context, success230);
}

static int ftpREST(PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);

  if ( params == NULL )
    return sendstring(context, error501);

  context->RestPoint = strtoull(params, NULL, 10);
  snprintf(context->GPBuffer, SIZE_OF_GPBUFFER, "%s %llu\r\n",
      interm350, (unsigned long long int)context->RestPoint);

  return sendstring(context, context->GPBuffer);
}

static int ftpSIZE(PFTPCONTEXT context, const char *params)
{
  struct stat    filestats;

  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);
  if ( params == NULL )
    return sendstring(context, error501);

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  if ( stat(context->GPBuffer, &filestats) == 0 )
  {
    snprintf(context->GPBuffer, SIZE_OF_GPBUFFER, "213 %llu\r\n",
        (unsigned long long int)filestats.st_size);
    sendstring(context, context->GPBuffer);
  }
  else
    sendstring(context, error550);

  return 1;
}

static int ftpMKD(PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);
  if ( context->Access < FTP_ACCESS_CREATENEW )
    return sendstring(context, error550_r);
  if ( params == NULL )
    return sendstring(context, error501);

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  if ( mkdir(context->GPBuffer, 0755) == 0 ) {
    sendstring(context, success257);
    writelogentry(context, " MKD: ", (char *)params);
  }
  else
    sendstring(context, error550_r);

  return 1;
}

static int ftpRMD(PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);
  if ( context->Access < FTP_ACCESS_FULL )
    return sendstring(context, error550_r);
  if ( params == NULL )
    return sendstring(context, error501);

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  if ( rmdir(context->GPBuffer) == 0 ) {
    sendstring(context, success250);
    writelogentry(context, " DELE: ", (char *)params);
  }
  else
    sendstring(context, error550_r);

  return 1;
}

static void *stor_thread(PFTPCONTEXT context)
{
  volatile SOCKET     clientsocket;
  int          f;
  ssize_t        sz, sz_total;
  size_t        buffer_size;
  char        *buffer;
  struct timespec    t;
  signed long long  lt0, lt1, dtx;

  f = -1;
  sz_total = 0;
  buffer = NULL;

  clock_gettime(CLOCK_MONOTONIC, &t);
  lt0 = t.tv_sec*1e9 + t.tv_nsec;
  dtx = t.tv_sec+30;

  buffer = (char *)malloc(TRANSMIT_BUFFER_SIZE);
  if (buffer == 0) {
    ESP_LOGE("ftp", "%s: malloc failed", __FUNCTION__);
    sendstring(context, error550_t);
    return 0;
  }
  while (buffer != NULL)
  {
    clientsocket = create_datasocket(context);
    if (clientsocket == INVALID_SOCKET)
      break;
    buffer_size = TRANSMIT_BUFFER_SIZE;

    f = open(context->GPBuffer, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH);
    context->File = f;
    if (f == -1)
      break;

    while ( context->WorkerThreadAbort == 0 ) {
      sz = recv_auto(clientsocket, 0, buffer, buffer_size);
      if (sz > 0)
      {
        sz_total += sz;
        write(f, buffer, sz);
      }
      else
        break;

            /* heartbeat to control channel */
            clock_gettime(CLOCK_MONOTONIC, &t);
            if (t.tv_sec >= dtx)
            {
               dtx += 120;
               sendstring(context, "\r\n");
               writelogentry(context, "keepalive sent", "");
            }
    }

    /* calculating performance */

    clock_gettime(CLOCK_MONOTONIC, &t);
    lt1 = t.tv_sec*1e9 + t.tv_nsec;
    dtx = lt1 - lt0;
    snprintf(buffer, buffer_size, " STOR complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
        sz_total, sz_total/1048576.0, dtx/1000000000.0, (1000000000.0*sz_total)/dtx/1048576);
    writelogentry(context, buffer, "");

    break;
  }

  if (f != -1)
    close(f);

  context->File = -1;

  if (buffer != NULL) {
      free(buffer);
    }

  if (clientsocket == INVALID_SOCKET) {
    sendstring(context, error451);
  }
  else {
    if (context->WorkerThreadAbort == 0)
      sendstring(context, success226);
    else
      sendstring(context, error426);

    close(clientsocket);
    context->DataSocket = INVALID_SOCKET;
  }

  context->WorkerThreadValid = -1;
  return NULL;
}

static int ftpSTOR(PFTPCONTEXT context, const char *params)
{
  struct stat    filestats;

  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);
  if ( context->Access < FTP_ACCESS_CREATENEW )
    return sendstring(context, error550_r);
  if ( params == NULL )
    return sendstring(context, error501);
  if ( context->WorkerThreadValid == 0 )
    return sendstring(context, error550_t);

  if ( context->File != -1 ) {
    close(context->File);
    context->File = -1;
  }

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  if ( stat(context->GPBuffer, &filestats) == 0 )
  {
    if ( context->Access != FTP_ACCESS_FULL )
      return sendstring(context, error550_r);
  }

  sendstring(context, interm150);
  writelogentry(context, " STOR: ", (char *)params);
  context->WorkerThreadAbort = 0;

  stor_thread(context);

  return 1;
}

static int ftpSYST(PFTPCONTEXT context, const char *params)
{
  return sendstring(context, success215);
}

static int ftpHELP(PFTPCONTEXT context, const char *params)
{
  return sendstring(context, success214);
}

static int ftpSITE(PFTPCONTEXT context, const char *params)
{
  if ( params != NULL )
    if (strcasecmp(params, "help") == 0)
      return sendstring(context, "200 chmod\r\n");

  return sendstring(context, error500);
}

static int ftpFEAT(PFTPCONTEXT context, const char *params)
{
  return sendstring(context, success211);
}

static void *append_thread(PFTPCONTEXT context)
{
  volatile SOCKET     clientsocket;
  int          f;
  ssize_t        sz, sz_total;
  size_t        buffer_size;
  char        *buffer;
  struct timespec    t;
  signed long long  lt0, lt1, dtx;

  f = -1;
  sz_total = 0;
  buffer = NULL;
  // TLS_datasession = NULL;
  clock_gettime(CLOCK_MONOTONIC, &t);
  lt0 = t.tv_sec*1e9 + t.tv_nsec;
    dtx = t.tv_sec+30;

  buffer = (char *)malloc(TRANSMIT_BUFFER_SIZE);
  if (buffer == 0) {
    ESP_LOGE("ftp", "%s: malloc failed", __FUNCTION__);
    sendstring(context, error550_t);
    return 0;
  }

  while (buffer != NULL)
  {
        clientsocket = create_datasocket(context);
        if (clientsocket == INVALID_SOCKET)
            break;

    buffer_size = TRANSMIT_BUFFER_SIZE;

    f = open(context->GPBuffer, O_RDWR);
    context->File = f;
    if (f == -1)
      break;

    lseek(f, 0, SEEK_END);

    while ( context->WorkerThreadAbort == 0 ) {
#if 0
      sz = recv_auto(clientsocket, TLS_datasession, buffer, buffer_size);
#else
      sz = recv_auto(clientsocket, 0, buffer, buffer_size);
#endif
      if (sz > 0)
      {
        sz_total += sz;
        write(f, buffer, sz);
      }
      else
        break;

            /* heartbeat to control channel */
            clock_gettime(CLOCK_MONOTONIC, &t);
            if (t.tv_sec >= dtx)
            {
               dtx += 120;
               sendstring(context, "\r\n");
               writelogentry(context, "keepalive sent", "");
            }
    }

    /* calculating performance */

    clock_gettime(CLOCK_MONOTONIC, &t);
    lt1 = t.tv_sec*1e9 + t.tv_nsec;
    dtx = lt1 - lt0;
    snprintf(buffer, buffer_size, " APPE complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
        sz_total, sz_total/1048576.0, dtx/1000000000.0, (1000000000.0*sz_total)/dtx/1048576);
    writelogentry(context, buffer, "");

    break;
  }

  if (f != -1)
    close(f);

  context->File = -1;

    if (buffer != NULL) {
        free(buffer);
    }

  if (clientsocket == INVALID_SOCKET) {
    sendstring(context, error451);
  }
  else {
    if (context->WorkerThreadAbort == 0)
      sendstring(context, success226);
    else
      sendstring(context, error426);

    close(clientsocket);
    context->DataSocket = INVALID_SOCKET;
  }

  context->WorkerThreadValid = -1;
  return NULL;
}

static int ftpAPPE(PFTPCONTEXT context, const char *params)
{
  struct  stat  filestats;

  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);
  if ( context->Access < FTP_ACCESS_FULL )
    return sendstring(context, error550_r);
  if ( params == NULL )
    return sendstring(context, error501);
  if ( context->WorkerThreadValid == 0 )
    return sendstring(context, error550_t);

  if ( context->File != -1 ) {
    close(context->File);
    context->File = -1;
  }

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  /*
   * stat must NOT fail
   */
  while (stat(context->GPBuffer, &filestats) == 0)
  {
    /*
     * do not try to "append" for directories
    */
    if ( S_ISDIR(filestats.st_mode) )
      break;

    sendstring(context, interm150);
    writelogentry(context, " APPE: ", (char *)params);
    context->WorkerThreadAbort = 0;

    append_thread(context);

    return 1;
  }

  return sendstring(context, error550);
}

static int ftpRNFR(PFTPCONTEXT context, const char *params)
{
  struct stat    filestats;

  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);
  if ( context->Access < FTP_ACCESS_FULL )
    return sendstring(context, error550_r);
  if ( params == NULL )
    return sendstring(context, error501);

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  if ( stat(context->GPBuffer, &filestats) == 0 )
  {
    writelogentry(context, " RNFR: ", context->GPBuffer);
    sendstring(context, interm350_ren);
  }
  else
    sendstring(context, error550);

  return 1;
}

static int ftpRNTO(PFTPCONTEXT context, const char *params)
{
  char  *_text;

  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);
  if ( context->Access < FTP_ACCESS_FULL )
    return sendstring(context, error550_r);
  if ( params == NULL )
    return sendstring(context, error501);

  _text = (char *)x_malloc(SIZE_OF_GPBUFFER);

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, _text) == NULL)
  {
    free(_text);
    return 0;
  }

  if ( rename(context->GPBuffer, _text) == 0 )
  {
    writelogentry(context, " RNTO: ", _text);
    sendstring(context, success250);
  }
  else
    sendstring(context, error550);

  free(_text);
  return 1;
}

static int ftpOPTS(PFTPCONTEXT context, const char *params)
{
  if ( params != NULL )
    if (strcasecmp(params, "utf8 on") == 0)
      return sendstring(context, "200 Always in UTF8 mode.\r\n");

  writelogentry(context, " unsupported OPTS: ", params);
  return sendstring(context, error500);
}

static int ftpAUTH(PFTPCONTEXT context, const char *params)
{
  if ( params == NULL )
    return sendstring(context, error501);

  if ( strcasecmp(params, "TLS") == 0 )
#if 0
    /* InitTLSSession will send reply */
    return InitTLSSession(&context->TLS_session, context->ControlSocket, 1);
#else
    return -1;
#endif
  else
    return sendstring(context, error504);
}

static int ftpPBSZ (PFTPCONTEXT context, const char *params)
{
  if ( params == NULL )
    return sendstring(context, error501);
#if 0
  if ( context->TLS_session == NULL )
#endif
    return sendstring(context, error503);

  context->BlockSize = strtoul(params, NULL, 10);
  return sendstring(context, success200);
}

static int ftpPROT (PFTPCONTEXT context, const char *params)
{
  if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
    return sendstring(context, error530);

  if ( params == NULL )
      return sendstring(context, error501);
#if 0
  if ( context->TLS_session == NULL )
#endif
    return sendstring(context, error503);

  switch (*params)
  {
  case 'C':
    context->DataProtectionLevel = 0;
    return sendstring(context, success200);
    break;

  case 'P':
    context->DataProtectionLevel = 100;
    return sendstring(context, success200);
    break;

  default:
    return sendstring(context, error504);
  }
}

static int mlsd_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry)
{
  char      text[SIZE_OF_GPBUFFER], *entrytype, *sizetype;
  struct stat    filestats;
  struct tm    ftm_fields;

  if (strcmp(entry->d_name, ".") == 0)
    return 1;
  if (strcmp(entry->d_name, "..") == 0)
    return 1;

  strcpy(text, dirname);
  add_last_slash(text);
  strcat(text, entry->d_name);

  if (stat(text, &filestats) == 0)
  {
    if ( S_ISDIR(filestats.st_mode) )
    {
      entrytype = (char *)"dir";
      sizetype = (char *)"sizd";
    }
    else
    {
      entrytype = (char *)"file";
      sizetype = (char *)"size";
    }

    if (S_ISLNK(filestats.st_mode))
    {
      entrytype = (char *)"OS.unix=slink";
    }

    localtime_r(&filestats.st_mtime, &ftm_fields);
    ++ftm_fields.tm_mon;

    snprintf(text, sizeof(text),
        "type=%s;%s=%llu;UNIX.mode=%lo;UNIX.owner=%lu;UNIX.group=%lu;modify=%u%02u%02u%02u%02u%02u; %s\r\n",
        entrytype, sizetype,
        (unsigned long long int)filestats.st_size,
        (unsigned long int)filestats.st_mode,
        (unsigned long int)filestats.st_uid,
        (unsigned long int)filestats.st_gid,
        ftm_fields.tm_year + 1900, ftm_fields.tm_mon, ftm_fields.tm_mday,
        ftm_fields.tm_hour, ftm_fields.tm_min, ftm_fields.tm_sec, entry->d_name
        );
  }

  return sendstring_auto(s, session, text);
}

static void *msld_thread(PFTPCONTEXT context)
{
  SOCKET        clientsocket;
  int          ret;
  DIR          *pdir;
  struct dirent    *entry;

  ret = 0;
  // TLS_datasession = NULL;

  clientsocket = create_datasocket(context);
  while (clientsocket != INVALID_SOCKET)
  {
#if 0
    if (context->TLS_session != NULL)
      InitTLSSession(&TLS_datasession, clientsocket, 0);
#endif
    pdir = opendir(context->GPBuffer);
    if (pdir == NULL)
      break;

    while ((entry = readdir(pdir)) != NULL) {
#if 0
      ret = mlsd_sub(context->GPBuffer, clientsocket, TLS_datasession, entry);
#else
      ret = mlsd_sub(context->GPBuffer, clientsocket, 0, entry);
#endif
      if ( (ret == 0) || (context->WorkerThreadAbort != 0 ))
        break;
    }

    closedir(pdir);
    break;
  }

  writelogentry(context, " LIST complete", "");

  if (clientsocket == INVALID_SOCKET) {
    sendstring(context, error451);
  }
  else {
    if ((context->WorkerThreadAbort == 0) && (ret != 0))
      sendstring(context, success226);
    else
      sendstring(context, error426);

    close(clientsocket);
    context->DataSocket = INVALID_SOCKET;
  }

  context->WorkerThreadValid = -1;
  return NULL;
}

static int ftpMLSD(PFTPCONTEXT context, const char *params)
{
  struct  stat  filestats;

  if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
    return sendstring(context, error530);
  if (context->WorkerThreadValid == 0)
    return sendstring(context, error550_t);

  if (finalpath(
      context->RootDir,
      context->CurrentDir,
      (char *)params, context->GPBuffer) == NULL)
    return 0;

  while (stat(context->GPBuffer, &filestats) == 0)
  {
    if ( !S_ISDIR(filestats.st_mode) )
      break;

    sendstring(context, interm150);
    writelogentry(context, " MLSD-LIST ", (char *)params);
    context->WorkerThreadAbort = 0;

    msld_thread(context);

    return 1;
  }

  return sendstring(context, error550);
}

static int recvcmd(PFTPCONTEXT context, char *buffer, size_t buffer_size)
{
  ssize_t  l, p = 0;

  if ( buffer_size < 5 )
    return 0;

  memset(buffer, 0, buffer_size);
  --buffer_size;

  while (buffer_size > 0)
  {
    l = recv(context->ControlSocket, buffer+p, buffer_size, 0);
    if ( l <= 0 )
      return 0;

    buffer_size -= l;
    p += l;

    if ( p >= 2 )
      if ( (buffer[p-2] == '\r') && (buffer[p-1] == '\n') )
      {
        buffer[p-2] = 0;
        return 1;
      }
  }

  return 0;
}

static void *ftp_client_thread(SOCKET *s)
{
  FTPCONTEXT		ctx __attribute__ ((aligned (16)));
  char			*cmd, *params, rcvbuf[FTP_PATH_MAX*2];
  int			c, cmdno, rv;
  size_t		i, cmdlen;
  socklen_t		asz;
  struct sockaddr_in6	laddr;

  ESP_LOGD("FTP Client handler", "Starting thread %p", xTaskGetCurrentTaskHandle());

  memset(&ctx, 0, sizeof(ctx));
  ctx.Access = FTP_ACCESS_NOT_LOGGED_IN;
  ctx.ControlSocket = *s;
  ctx.GPBuffer = (char *)x_malloc(SIZE_OF_GPBUFFER);

  memset(&laddr, 0, sizeof(laddr));
  asz = sizeof(laddr);
  while (getsockname(ctx.ControlSocket, (struct sockaddr *)&laddr, &asz) == 0)
  {
    // Overrule sin6_family based on evidence. FIX ME
    if (laddr.sin6_addr.un.u32_addr[0] == 0 && laddr.sin6_addr.un.u32_addr[1] == 0)
      laddr.sin6_family = AF_INET;

    // Store address family in the context
    ctx.af = laddr.sin6_family;

    // ctx.ServerIPv4 = laddr.sin_addr.s_addr;
    if (laddr.sin6_family == AF_INET)
      ctx.ServerIPv4 = laddr.sin6_addr.un.u32_addr[3];
    else
      ctx.ServerIPv6 = laddr.sin6_addr;

    ESP_LOGD("ftp", "getsockname -> %08x %08x %08x %08x",
      (unsigned int)laddr.sin6_addr.un.u32_addr[0],
      (unsigned int)laddr.sin6_addr.un.u32_addr[1],
      (unsigned int)laddr.sin6_addr.un.u32_addr[2],
      (unsigned int)laddr.sin6_addr.un.u32_addr[3]);

    memset(&laddr, 0, sizeof(laddr));
    asz = sizeof(laddr);
    if (getpeername(ctx.ControlSocket, (struct sockaddr *)&laddr, &asz) != 0)
      break;

    // Overrule sin6_family based on evidence. FIX ME
    if (laddr.sin6_addr.un.u32_addr[0] == 0 && laddr.sin6_addr.un.u32_addr[1] == 0)
      laddr.sin6_family = AF_INET;

    ESP_LOGD("ftp", "ftp_client_thread : AF %d", laddr.sin6_family);

    if (laddr.sin6_family == AF_INET) {
      ctx.ClientIPv4 = laddr.sin6_addr.un.u32_addr[3];
    } else if (laddr.sin6_family == AF_INET6) {
      ctx.ClientIPv6 = laddr.sin6_addr;
    } else {
    }

    ctx.Mode = MODE_NORMAL;
    ctx.WorkerThreadAbort = 0;
    ctx.WorkerThreadValid = -1;
    ctx.SessionID = __sync_add_and_fetch(&g_newid, 1);
    ctx.File = -1;
    ctx.DataSocket = INVALID_SOCKET;

    ctx.CurrentDir[0] = '/';
    // sendstring(&ctx, success220);
    snprintf(rcvbuf, sizeof(rcvbuf), "%s (host %s)\r\n", success220nocrlf,
      "(noname)");	// FIXME
      // config->myName());
    sendstring(&ctx, rcvbuf);
    ESP_LOGD("ftp", "%s", rcvbuf);

    memset(&rcvbuf, 0, sizeof(rcvbuf));

    if (laddr.sin6_family == AF_INET) {
      snprintf(rcvbuf, sizeof(rcvbuf), "<- New user IP=%u.%u.%u.%u:%u",
        (unsigned int)ctx.ClientIPv4 & 0xff,
        (unsigned int)(ctx.ClientIPv4 >> 8 ) & 0xff,
        (unsigned int)(ctx.ClientIPv4 >> 16 ) & 0xff,
        (unsigned int)(ctx.ClientIPv4 >> 24 ) & 0xff,
        (unsigned int)ntohs(laddr.sin6_port));
    } else if (laddr.sin6_family == AF_INET6) {
      snprintf(rcvbuf, sizeof(rcvbuf), "<- New user IP=....:%u",
        ntohs(laddr.sin6_port));
    }

    writelogentry(&ctx, rcvbuf, "");

    while ( ctx.ControlSocket != INVALID_SOCKET ) {
      if ( !recvcmd(&ctx, rcvbuf, sizeof(rcvbuf)) )
        break;

      i = 0;
      while ((rcvbuf[i] != 0) && (isalpha((int)rcvbuf[i]) == 0))
        ++i;

      cmd = &rcvbuf[i];
      while ((rcvbuf[i] != 0) && (rcvbuf[i] != ' '))
        ++i;

      cmdlen = &rcvbuf[i] - cmd;
      while (rcvbuf[i] == ' ')
        ++i;

      if (rcvbuf[i] == 0)
        params = NULL;
      else
        params = &rcvbuf[i];

      cmdno = -1;
      rv = 1;
      for (c=0; c<MAX_CMDS; c++)
        if (strncasecmp(cmd, ftpcmds[c], cmdlen) == 0)
        {
          cmdno = c;
          rv = ftpprocs[c](&ctx, params);
          break;
        }

      if ( cmdno != FTP_PASSCMD_INDEX )
        writelogentry(&ctx, " @@ CMD: ", rcvbuf);
      else
        writelogentry(&ctx, " @@ CMD: ", "PASS ***");

      if ( cmdno == -1 )
        sendstring(&ctx, error500);

      if ( rv <= 0 )
        break;
    };

    WorkerThreadCleanup(&ctx);

    writelogentry(&ctx, "User disconnected", "");
    break;
  }

  free(ctx.GPBuffer);
  close(ctx.ControlSocket);
  *s = INVALID_SOCKET;
  return NULL;
}

#if 0
static void ftpclient_handler(void *p) {
  SOCKET *s = (SOCKET *)p;
  ftp_client_thread(s);

  // Make sure not to return
  vTaskDelete(xTaskGetCurrentTaskHandle());
}
#endif

static void ftpmain(void *p)
{
  int    ftpsocket = INVALID_SOCKET,
      clientsocket,
      *scb = NULL,
      socketret,
      rv;

  socklen_t  asz;
  uint32_t  i;

  // ftpsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ((ftpsocket = socket(AF_INET6, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    ESP_LOGE("FTP server", "socket create error");
    vTaskDelete(xTaskGetCurrentTaskHandle());
  }

  rv = 1;
  setsockopt(ftpsocket, SOL_SOCKET, SO_REUSEADDR, &rv, sizeof(rv));

  scb = (SOCKET *)x_malloc(sizeof(SOCKET)*5);
  for (i = 0; i<5; i++)
    scb[i] = INVALID_SOCKET;

#if 1	// IPv6, sample code, doesn't work yet
  struct sockaddr_in6  laddr;
  memset(&laddr, 0, sizeof(laddr));
  laddr.sin6_family = AF_INET6;
  laddr.sin6_port = htons(21);

  laddr.sin6_addr = in6addr_any;

#else	// IPv4
  struct sockaddr_in  laddr;
  memset(&laddr, 0, sizeof(laddr));
  laddr.sin_family = AF_INET;
  laddr.sin_addr.s_addr = 0;
  laddr.sin_port = htons(21);
#endif

  if ((socketret = bind(ftpsocket, (struct sockaddr *)&laddr, sizeof(laddr))) != 0) {
    ESP_LOGE("FTP server", "Failed to start server. Can not bind to address.");
    free(scb);
    close(ftpsocket);
    vTaskDelete(xTaskGetCurrentTaskHandle());
  }

  writelogentry(NULL, success220nocrlf, "");

  socketret = listen(ftpsocket, 5);
  while ( socketret == 0 ) {
    memset(&laddr, 0, sizeof(laddr));
    asz = sizeof(laddr);
    clientsocket = accept(ftpsocket, (struct sockaddr *)&laddr, &asz);
 
    if (clientsocket != INVALID_SOCKET) {
      rv = -1;
      for (i=0; i<5; i++) {
        if ( scb[i] == INVALID_SOCKET ) {

          scb[i] = clientsocket;
	  ftp_client_thread(&scb[i]);
          break;
        }
      }

      if ( rv != 0 ) {
        sendstring_plaintext(clientsocket, NOSLOTS);
        close(clientsocket);
      }
    }
  }

  free(scb);
  close(ftpsocket);
  vTaskDelete(xTaskGetCurrentTaskHandle());
}

static TaskHandle_t ftpTask;

extern "C" {
  void ftp_init() {
    xTaskCreate(ftpmain, "FTP server task", 12000, 0, 2 | portPRIVILEGE_BIT, &ftpTask);
  }

  void ftp_stop() {
    vTaskDelete(ftpTask);
  }
}

static void * x_malloc(size_t size)
{
	void	*result;

	result = malloc(size);
	if (result == NULL)
	{
		printf("\r\nOut of memory\r\n");
		abort();
	}

	memset(result, 0, size);

	return result;
}
