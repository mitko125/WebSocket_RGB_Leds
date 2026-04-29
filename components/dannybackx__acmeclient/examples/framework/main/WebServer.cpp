/*
 * Copyright (c) 2019, 2020, 2021, 2022, 2023, 2024 Danny Backx
 *
 * License (GNU Lesser General Public License) :
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 3 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * This module implements two small web servers :
 * - a http server (should be on port 80) to serve
 *   . the temporary pages that the ACME protocol requires, and
 *   . Arduino-style simple OTA
 * - a https server (e.g. on 443) to serve other stuff
 *
 * Hooks for network connect/disconnect will start/stop the web servers.
 * The CertificateUpdate hook will start the https server on certificate changes.
 *
 * Please make sure to protect access to this module, it still needs to be secured,
 * even the https server (encryption is not access control).
 */

#include "App.h"
#include <esp_http_client.h>
#include "esp_log.h"
#include <regex.h>

WebServer::WebServer() {
  app->network->registerModule(webserver_tag, WsNetworkConnected, WsNetworkDisconnected);

  usrv = ssrv = 0;
  cert_key = 0;
  cert = 0;

  for (int i=0; i<CONFIG_TLS_SESSIONS; i++) {
    sessions[i].sock = -1;
    sessions[i].tls = 0;
    sessions[i].subject = 0;
  }

  subjects = 0;
  nsubjects = 0;
  
#ifdef CONFIG_CLIENT_CERTIFICATES
    setAcceptedCertificates(CONFIG_CLIENT_CERTIFICATES);
#endif
}

const char *WebServer::http_method2string(int m) {
  switch (m) {
  case HTTP_GET: return "HTTP_GET";
  case HTTP_PUT: return "HTTP_PUT";
  case HTTP_POST: return "HTTP_POST";
  default: return "?";
  }
}

void WebServer::start() {
  /*
   * Create SSL web server
   */
    ConfigureSSLServer();
    StartSSLServer();
    FreeCerts();

  /*
   * Create regular web server
   */
  ConfigureRegularServer();
  StartRegularServer();

  if (ssrv) {
    // app->installHandler(ssrv, "HTTPS", HTTP_GET, "/alarm", alarm_handler, webserver_tag, __FUNCTION__);
    // app->installHandler(ssrv, "HTTPS", HTTP_GET, "/favicon.ico", favicon_png_handler, webserver_tag, __FUNCTION__);
  }

  if (usrv) {
    // FIXME test
    app->installHandler(usrv, "HTTP", HTTP_GET, "/status", status_handler, webserver_tag, __FUNCTION__);

    // app->installHandler(usrv, "HTTP", HTTP_GET, "/alarm", alarm_handler, webserver_tag, __FUNCTION__);
    // app->installHandler(usrv, "HTTP", HTTP_GET, "/favicon.ico", favicon_png_handler, webserver_tag, __FUNCTION__);
  }

  app->WebServerStarted(usrv, ssrv);
}

WebServer::~WebServer() {
  StopSSLServer();
  StopRegularServer();

  if (subjects)
    free((void *)subjects);
  subjects = 0;
  nsubjects = 0;
}

/*
 * Note : need to run FreeCerts() after this
 */
void WebServer::ConfigureSSLServer() {
#ifdef CONFIG_HTTPS_SERVER_PORT
    scfg = HTTPD_SSL_CONFIG_DEFAULT();
    start_secure = true;
  
    scfg.port_secure = CONFIG_HTTPS_SERVER_PORT;
    scfg.httpd.stack_size = 2 * 4096;			// FIX ME
  
    // This 5 is also the default in components/esp_https_server/include/esp_https_server.h
    scfg.httpd.backlog_conn = 5;
    scfg.httpd.lru_purge_enable = true;	// NOT the default
    scfg.httpd.uri_match_fn = httpd_uri_match_wildcard;
#endif
}

/*
 * Keep a table of connections, to be able to block unauthenticated sessions.
 */
void WebServer::AddConnection(int sockfd, const esp_tls_t *tls) {
  ESP_LOGI(webserver_tag, "%s(sock %d, tls %p)", __FUNCTION__, sockfd, tls);

  for (int i=0; i<CONFIG_TLS_SESSIONS; i++)
    if (sessions[i].sock < 0) {
      sessions[i].sock = sockfd;
      sessions[i].tls = (esp_tls_t *)tls;
      sessions[i].subject = 0;

      // Fetch the "subject" (CN=..) field from the certificate, put it in the table
      mbedtls_ssl_context *sslc = (mbedtls_ssl_context *)esp_tls_get_ssl_context((esp_tls_t *)tls);
      mbedtls_x509_crt *peer_cert = (mbedtls_x509_crt *)mbedtls_ssl_get_peer_cert(sslc);
      if (peer_cert != 0) {
	mbedtls_x509_name subject = peer_cert->subject;
	char subject_name[82];			// FIX ME
	if (mbedtls_x509_dn_gets(subject_name, sizeof(subject_name)-1, &subject)) {
	  ESP_LOGI(app->ws->webserver_tag, "%s: got peer cert %s", __FUNCTION__, subject_name);
	  sessions[i].subject = strdup(subject_name);
	}
      }

      return;
    }

  ESP_LOGE(webserver_tag, "%s(sock %d, tls %p): session table full", __FUNCTION__, sockfd, tls);
}

void WebServer::DeleteConnection(const esp_tls_t *tls) {
  ESP_LOGI(webserver_tag, "%s(tls %p)", __FUNCTION__, tls);

  for (int i=0; i<CONFIG_TLS_SESSIONS; i++)
    if (sessions[i].tls == tls) {
      sessions[i].tls = 0;
      sessions[i].sock = 0;
      free((void *)sessions[i].subject);
      sessions[i].subject = 0;
    }
}

esp_tls_t *WebServer::QueryConnection(int sockfd) {
  ESP_LOGI(webserver_tag, "%s(%d)", __FUNCTION__, sockfd);
  for (int i=0; i<CONFIG_TLS_SESSIONS; i++)
    if (sessions[i].sock == sockfd)
      return sessions[i].tls;
  return 0;
}

/*
 * This function gets called from esp_https_server when an SSL connection is built or broken.
 * We use it to keep track of peer certificates for mutual authentication.
 * This is non-trivial because a connection can span multiple web queries so a call can
 * easily come in over connection 2 while connection 1 is still lingering between queries.
 *
 * Static function, refer to fields via _ws (app->ws)
 */
void WebServer::https_user_cb(esp_https_server_user_cb_arg *ptr) {
  if (ptr->user_cb_state == HTTPD_SSL_USER_CB_SESS_CREATE) {
    ESP_LOGD(app->ws->webserver_tag, "%s: tls %p, CREATE", __FUNCTION__, ptr->tls);

    int sfd;
    if (esp_tls_get_conn_sockfd(ptr->tls, &sfd) == ESP_OK)
      app->ws->AddConnection(sfd, ptr->tls);
    else {
      ESP_LOGE(app->ws->webserver_tag, "%s: fail, could not get sockfd", __FUNCTION__);
    }
  } else {
    ESP_LOGD(app->ws->webserver_tag, "%s: tls %p, DELETE", __FUNCTION__, ptr->tls);
    app->ws->DeleteConnection(ptr->tls);
  }
}

void WebServer::FreeCerts() {
  if (cert != 0) free((void *)cert);
  if (cert_key != 0) free((void *)cert_key);
  scfg.cacert_pem = cert = 0;
  scfg.prvtkey_pem = cert_key = 0;
}

void WebServer::StartSSLServer() {
    esp_err_t		err = ESP_FAIL;
    int			len;

    if (cert_key)
      free((void *)cert_key);
 
    cert_key = (unsigned char *)ReadFile(CONFIG_CERTKEY_FILENAME, &len);
    if (cert_key == 0)
      start_secure = false;
    scfg.prvtkey_pem = cert_key;
    scfg.prvtkey_len = cert_key ? len + 1 : 0;

    if (cert)
      free((void *)cert);
    cert = (unsigned char *)ReadFile(CONFIG_CERTIFICATE_FILENAME, &len);
    if (cert == 0)
      start_secure = false;
    scfg.cacert_pem = cert;
    scfg.cacert_len = cert ? len + 1 : 0;
    scfg.user_cb = https_user_cb;

    /*
     * See https_server:create_secure_context :
     * cacert = CA which signs client cert, or client cert itself , which is mapped to client_verify_cert_pem
     */
#if defined(ESP_IDF_VERSION_MAJOR) && (ESP_IDF_VERSION_MAJOR >= 5)
    scfg.servercert = scfg.cacert_pem;
    scfg.servercert_len = scfg.cacert_len;
#else
    scfg.client_verify_cert_pem = scfg.cacert_pem;
    scfg.client_verify_cert_len = scfg.cacert_len;
#endif

    ssrv = 0;
    if (start_secure && (scfg.port_secure != (uint16_t)-1)) {
      ESP_LOGD(webserver_tag, "Starting SSL web server ...");
      if ((err = httpd_ssl_start(&ssrv, &scfg)) != ESP_OK) {
        ESP_LOGE(webserver_tag, "Failed to start SSL webserver(%d), %d %s", scfg.port_secure,
          err, esp_err_to_name(err));
      } else {
        ESP_LOGI(webserver_tag, "Start SSL webserver (%d)", scfg.port_secure);
      }
    } else {
      ESP_LOGE(webserver_tag, "Not starting SSL webserver: start_secure %s, port %d",
        start_secure ? "true" : "false", scfg.port_secure);
    }
}

void WebServer::StopSSLServer() {
  if (ssrv) {
    ESP_LOGI(webserver_tag, "stop SSL webserver");
    httpd_ssl_stop(ssrv);
    ssrv = 0;
  }
}

void WebServer::ConfigureRegularServer() {
#ifdef CONFIG_HTTP_SERVER_PORT
    cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = CONFIG_HTTP_SERVER_PORT;
    cfg.uri_match_fn = httpd_uri_match_wildcard;
#endif
}

void WebServer::StartRegularServer() {
#ifdef CONFIG_HTTP_SERVER_PORT
    esp_err_t		err = ESP_FAIL;

    ESP_LOGD(webserver_tag, "Starting regular web server ...");
    if ((err = httpd_start(&usrv, &cfg)) != ESP_OK) {
      ESP_LOGE(webserver_tag, "failed to start %s (%d)", esp_err_to_name(err), err);
    } else {
      ESP_LOGD(webserver_tag, "Start webserver(%d)", cfg.server_port);
    }
#endif
}

void WebServer::StopRegularServer() {
  if (usrv) {
    httpd_stop(usrv);
    usrv = 0;
  }
}

/*
 * URI Handlers
 */

#if 0
extern const char icon_png_start[]	asm("_binary_icon_png_start");
extern const char icon_png_end[]	asm("_binary_icon_png_end");

/*
 * Respond with a PNG image when the browser asks /favicon.ico
 */
esp_err_t WebServer::favicon_png_handler(httpd_req_t *req) {
  ESP_LOGD(app->ws->webserver_tag, "%s(%s)", __FUNCTION__, req->uri);

  char cl[10];
  sprintf(cl, "%d", icon_png_end - icon_png_start);
  httpd_resp_set_status(req, "200 OK");
  httpd_resp_set_type(req, "image/x-icon");
  httpd_resp_set_hdr(req, "Content-Length", cl);

  httpd_resp_send_chunk(req, icon_png_start, icon_png_end - icon_png_start);
  httpd_resp_send_chunk(req, "\n\r", 2);
  httpd_resp_send_chunk(req, NULL, 0);

  return ESP_OK;
}
#endif

/*
 * This is a sample status handler
 */
esp_err_t WebServer::status_handler(httpd_req_t *req) {
  // Check whether this socket is secure (but HTTP allowed).
  if (! app->isPeerSecure(httpd_req_to_sockfd(req))) {
    const char *reply = "<!DOCTYPE html><html><head><title>Not authorized</title></head><body>Error: not authorized</body></html>";
    httpd_resp_send(req, reply, strlen(reply));
    httpd_resp_send_500(req);
    return ESP_OK;
  }

  char *s, boot[24], nows[24];
  wifi_ap_record_t apinfo;

  esp_err_t err = esp_wifi_sta_get_ap_info(&apinfo);
  app->timeString(app->boot_time, "%F %T", boot, sizeof(boot));
  struct timeval tv;
  gettimeofday(&tv, 0);
  time_t now = tv.tv_sec;
  app->timeString(now, "%F %T", nows, sizeof(nows));
  asprintf(&s,
    "<html><p>Node : %s, status : %s, IP " IPSTR ", SSID %s\n"
    "<p>Current time : %s, boot : %s, build : %s\n"
    "</html>\n",
    CONFIG_NODE_NAME, "armed",
    IP2STR(&app->ip_info.ip),
    (err == ESP_OK) ? (char *)apinfo.ssid : (char *)"no access point info",
    nows, boot, app->build);
  httpd_resp_send(req, s, strlen(s));
  free(s);
  return ESP_OK;
}

/*
 * Used by handlers after their processing, to send a normal page back to the user.
 * No status or error codes called.
 */
void WebServer::SendPage(httpd_req_t *req) {
  ESP_LOGD(app->ws->webserver_tag, "%s", __FUNCTION__);

  // Reply
  const char *reply_template1 =
    "<!DOCTYPE html>"
    "<HTML>"
    "<TITLE>ESP32 %s controller</TITLE>\r\n"
    "<BODY>"
    "<H1>General</h1>\r\n"
    "<p>Node name %s"
    "<p>Time %s"
    "<p>Alarm status %s";

  const char *reply_template2 =
    "<P>\r\n"
#ifdef WEB_SERVER_IS_SECURE
    "<form action=\"/alarm\" method=\"get\">\r\n"
      "<button class=\"button\" type=\"submit\" name=\"armed\" value=\"uit\">Uit</button>\r\n"
      "<button class=\"button\" type=\"submit\" name=\"armed\" value=\"nacht\">Nacht</button>\r\n"
      "<button class=\"button\" type=\"submit\" name=\"armed\" value=\"aan\">Aan</button>\r\n"
    "</form>"
#endif
    "</P>\r\n"
    "</BODY>"
    "</HTML>";

  char *buf1 = (char *)malloc(strlen(reply_template1) + 50);
  char *buf2 = (char *)malloc(strlen(reply_template1) + 70);
  
  strcpy(buf1, reply_template1);

  sprintf(buf2, buf1,
    "node name",		// Node name, in the title
    "node name",		// Node name, in page body
    "",
    ""
    );

  // No response code set, assumption that this is a succesfull call
  httpd_resp_send_chunk(req, buf2, strlen(buf2));
  free(buf1);
  free(buf2);

  httpd_resp_send_chunk(req, reply_template2, strlen(reply_template2));

  // Terminate reply
  httpd_resp_send_chunk(req, reply_template2, 0);
}

/*
 * Expose the server handle so we can pass it to the ACME library
 */
httpd_handle_t WebServer::getRegularServer() {
  return usrv;
}

httpd_handle_t WebServer::getSSLServer() {
  return ssrv;
}

void WebServer::WsNetworkConnected(void *ctx, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  ESP_LOGD(app->ws->webserver_tag, "Starting WebServer");
  // if (app->acme) app->acme->setWebServer(app->ws->getRegularServer());

  app->ws->start();
}

void WebServer::WsNetworkDisconnected(void *ctx, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  if (app->ws->getRegularServer())
    httpd_stop(app->ws->getRegularServer());
  if (app->ws->getSSLServer())
    httpd_stop(app->ws->getSSLServer());
}

/*
 * Static function (in a previous life, we registered this as a handler), so use fields via pointer
 */
void WebServer::CertificateUpdate() {
  app->ws->start_secure = true;

  app->ws->StopSSLServer();
  app->ws->ConfigureSSLServer();
  app->ws->StartSSLServer();
  app->ws->FreeCerts();
}

/*
 * This will read certificates from file, e.g. the ones obtained via ACME.
 * Note that we dynamically allocate memory per NREAD_INC, this is to work around
 * a filesystem deficiency : it won't report file size with seek().
 *
 * Caller must free allocated memory
 *
 * Prefix is prepended to the path specified, and length read is returned in the 2nd param.
 */
#define	NREAD_INC	250
const unsigned char *WebServer::ReadFile(const char *fn, int *plen) {
  char ffn[64];
  const char *prefix = CONFIG_ACME_FILENAME_PREFIX;
  snprintf(ffn, 64, "%s/%s", prefix, fn);

  FILE *f = fopen(ffn, "r");
  if (f == 0) {
    ESP_LOGE(webserver_tag, "Could not open file %s", ffn);
    if (plen != 0) *plen = 0;
    return 0;
  }
  ESP_LOGD(webserver_tag, "%s(%s)", __FUNCTION__, ffn);
  long len = fseek(f, 0L, SEEK_END);
  (void)fseek(f, 0L, SEEK_SET);
  if (len == 0)
    len = NREAD_INC;
  char *buffer = (char *)malloc(len+1);
  size_t total = fread((void *)buffer, 1, len, f);
  buffer[total] = 0;
  int inc = total;
  while (inc == NREAD_INC) {
    len += NREAD_INC;
    buffer = (char *)realloc((void *)buffer, len + 1);
    inc = fread((void *)(buffer + total), 1, NREAD_INC, f);
    total += inc;
    buffer[total] = 0;
    // ESP_LOGD(webserver_tag, "Reading -> %d bytes, total %d ", inc, total);
  }
  fclose(f);
  ESP_LOGI(webserver_tag, "%s: read from %s, len %d", __FUNCTION__, ffn, total);

  buffer[total] = 0;
  if (plen != 0) *plen = total;
  return (const unsigned char *)buffer;
}

/*
 * Block unauthenticated clients based on their certificate or absence of one
 */
bool WebServer::isPeerSecure(int sock) {
  ESP_LOGI(webserver_tag, "%s sock %d", __FUNCTION__, sock);

  for (int i=0; i<CONFIG_TLS_SESSIONS; i++) {
    // ESP_LOGI(webserver_tag, "%s - %d sock %d", __FUNCTION__, i, sessions[i].sock);
    if (sessions[i].sock != sock)
      continue;

    // Note could be simplified by using newlines between patterns and REG_NEWLINE
    for (int j=0; j<nsubjects; j++) {
      // FIX ME +3 is to skip "CN="
      if (certificateMatch(subjects[j], sessions[i].subject + 3)) {
	ESP_LOGI(webserver_tag, "%s: match %s", __FUNCTION__, subjects[j]);
	return true;
      }
    }
  }

  // Nothing found -> refuse connection
  ESP_LOGE(webserver_tag, "%s: no match", __FUNCTION__);
  return false;
}

bool WebServer::certificateMatch(const char *tmpl, const char *subject) {
  regex_t r;
  if (regcomp(&r, tmpl, REG_EXTENDED)) {
    ESP_LOGE(webserver_tag, "%s: couldn't compile regex %s", __FUNCTION__, tmpl);
    return false;
  }
  if (regexec(&r, subject, 0, 0, 0) == 0) {
    regfree(&r);
    ESP_LOGI(webserver_tag, "%s: match %s %s", __FUNCTION__, tmpl, subject);
    return true;
  }
  regfree(&r);
  ESP_LOGI(webserver_tag, "%s: fail %s %s", __FUNCTION__, tmpl, subject);
  return false;
}

void WebServer::clearSubjects() {
  for (int i=0; i<nsubjects; i++)
    if (subjects[i])
      free((void *)subjects[i]);

  nsubjects = 0;
  if (subjects)
    free((void *)subjects);
  subjects = 0;
}

/*
 * Initialize the subjects array to a list of certificate subjects.
 */
void WebServer::setAcceptedCertificates(const char *sl) {
  ESP_LOGI(webserver_tag, "%s(%s)", __FUNCTION__, sl);

  clearSubjects();

  // Count number of elements
  int count = 1;
  for (int i=0; sl[i]; i++)
    if (sl[i] == ',') count++;

  // Allocate
  subjects = (char **)calloc(count, sizeof(char *));

  for (int i=0; sl[i]; ) {
    // Take a substring
    int j;
    for (j=i; sl[j] && sl[j] != ','; j++) ;

    // Allocate
    char *p = (char *)malloc(j+1-i);
    for (int k=0; sl[i+k] && sl[i+k] != ','; k++) {
      p[k] = sl[i+k];
      p[k+1] = 0;
    }

    // Store
    subjects[nsubjects] = p;
    nsubjects++;
    ESP_LOGD(webserver_tag, "%s %d %s", __FUNCTION__, nsubjects, p);

    // Move on
    if (sl[j])
      i = j+1;
    else
      break;
  }
}

// Array parameter : no need to break up
void WebServer::setAcceptedCertificates(const char **sl) {
  // ESP_LOGI(webserver_tag, "%s(%s)", __FUNCTION__, sl);

  clearSubjects();

  // Count number of elements
  int count = 1;
  for (int i=0; sl[i]; i++)
    count++;

  // Allocate
  subjects = (char **)calloc(count, sizeof(char *));

  for (int i=0; sl[i]; i++) {
    subjects[i] = strdup(sl[i]);
    nsubjects++;
    ESP_LOGD(webserver_tag, "%s %d %s", __FUNCTION__, nsubjects, subjects[i]);
  }
}
