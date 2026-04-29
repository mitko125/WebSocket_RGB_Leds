/*
 * Application class file, contain all includes and "global" variables
 *
 * Copyright (c) 2023, 2024 by Danny Backx
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

#include <App.h>
#include <stdio.h>
#include <build.h>
#include <time.h>
#include <esp_sntp.h>
#include <esp_netif_sntp.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>

#include <ftpserv.h>
#include <esp_littlefs.h>

App		*app = 0;
char		*boot_msg = 0;

extern "C" void app_main(void)
{
  app = new App();
  app->setup();

  app->initialized = true;

  while(true) {
    vTaskDelay(pdMS_TO_TICKS(200));

    struct timeval tv;
    gettimeofday(&tv, 0);
    app->now = tv.tv_sec;

    app->loop(app->now);
  }
}

App::App() {
  initialized = false;
  build = __BUILD__;
  connected = false;
  ftp_started = false;
  boot_time = 0;
  app = this;
  web_server = 0;
  ws = 0;
  ota_busy = false;
  preset_ip = 0;
  preset_dns = 0;
  acme = 0;

  time_reboot = 0;
  time_reconnect = 0;

  // Avoid doing this on every TCP call - build a whitelist filter
  whitelist_filter = 0xFFFFFFFF;
  for (int i=CONFIG_WHITELIST_RANGE; i<32; i++) {
    in_addr_t x = 1 << (32-i-1);
    in_addr_t y = 0xFFFFFFFF - x;
    whitelist_filter &= y;
  }

  // Get report of failed memory allocations on error log
  heap_caps_register_failed_alloc_callback(failed_alloc_hook);
}

App::~App() {
}

bool App::isInitialized() {
  return initialized;
}

void App::setup() {
  ESP_ERROR_CHECK(nvs_flash_init());

  ESP_LOGI(tag, "Minimal acmeclient demo (c) 2017-2024 by Danny Backx");
  ESP_LOGI(tag, "Build %s", build);
  ESP_LOGI(tag, "Using Acmeclient v%s", ACMECLIENT_VERSION);

  // Initialize local file system early so we can log to it if we like
  ESP_LOGI(tag, "Mounting littlefs at %s", CONFIG_BASE_PATH);
  esp_vfs_littlefs_conf_t lcfg;
  bzero(&lcfg, sizeof(lcfg));
  lcfg.base_path = CONFIG_BASE_PATH;
  lcfg.format_if_mount_failed = true;
  lcfg.partition_label = "spiffs";
  ESP_ERROR_CHECK(esp_vfs_littlefs_register(&lcfg));

#ifdef REDIRECT_LOG_TO_FILE
  esp_log_set_vprintf(redirectLogToFile);
#endif

  // Make logging a bit more quiet
  esp_log_level_set("main_task", ESP_LOG_ERROR);
  esp_log_level_set("wifi", ESP_LOG_ERROR);
  esp_log_level_set("wifi_init", ESP_LOG_ERROR);
  esp_log_level_set("phy_init", ESP_LOG_ERROR);
  esp_log_level_set("heap", ESP_LOG_DEBUG);
  esp_log_level_set("heap_init", ESP_LOG_ERROR);
  esp_log_level_set("event", ESP_LOG_ERROR);
  esp_log_level_set("system_api", ESP_LOG_ERROR);
  esp_log_level_set("dhcp", ESP_LOG_DEBUG);
  esp_log_level_set("esp-x509-crt-bundle", ESP_LOG_ERROR);

  ESP_ERROR_CHECK(esp_event_loop_create_default());

  /*
   * Start WiFi.
   * Register event handlers to start server when Wi-Fi or Ethernet is connected,
   * and stop server when disconnection happens.
   */

  network = new Network();
  network->registerModule(tag, connect, disconnect);

  /*
   * This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
   * Read "Establishing Wi-Fi or Ethernet Connection" section in
   * examples/protocols/README.md for more information about this function.
   *
   * Note we're using a private version to be able to set fixed IP addresses.
   */
#ifdef	CONFIG_PRESET_IP
    preset_ip = (esp_netif_ip_info_t *)malloc(sizeof(esp_netif_ip_info_t));
    preset_ip->ip.addr = ipaddr_addr(CONFIG_PRESET_IP_ADDR);
    preset_ip->netmask.addr = ipaddr_addr(CONFIG_PRESET_IP_NETMASK);
    preset_ip->gw.addr = ipaddr_addr(CONFIG_PRESET_IP_GW);
  
    preset_dns = (esp_netif_dns_info_t *)malloc(sizeof(esp_netif_dns_info_t));
    if (CONFIG_PRESET_IP_DNS)
      preset_dns->ip.u_addr.ip4.addr = ipaddr_addr(CONFIG_PRESET_IP_DNS);
    else
      // Assume GW also serves as DNS
      preset_dns->ip.u_addr.ip4.addr = ipaddr_addr(CONFIG_PRESET_IP_GW);
    preset_dns->ip.type = IPADDR_TYPE_V4;
    ESP_LOGI(tag, "Preset IP " IPSTR " GW " IPSTR " SM " IPSTR " DNS " IPSTR,
      IP2STR(&preset_ip->ip), IP2STR(&preset_ip->gw), IP2STR(&preset_ip->netmask),
      IP2STR(&preset_dns->ip.u_addr.ip4));
    network->setPreset(preset_ip, preset_dns);
#endif

/*
 * Note : fix confirmed 03/10/2023, for broken esp-idf-v5.1 and 5.1.1 .
 * The C++ compiler stumbled on a 0 initializer in ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE .
 * The 0 should be IP_EVENT_STA_GOT_IP .
 *
 * See https://github.com/espressif/esp-idf/commit/ef451cab0fec03b24d71552054c8489c2bd6217b
 */

#if CONFIG_LWIP_SNTP_MAX_SERVERS < 3
#error Change setting in menuconfig for this to work
#else
/*
 * Second note : the macro below only works right if the setting in menuconfig also allows for
 * so many NTP servers. You'll need to see
 *   CONFIG_LWIP_SNTP_MAX_SERVERS=3
 * in sdkconfig, or this creates a compile error.
 */
  esp_sntp_config_t sntp_config = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(3,
    ESP_SNTP_SERVER_LIST(CONFIG_NTP_SERVER_0, CONFIG_NTP_SERVER_1, "pool.ntp.org" ) );
#endif
  sntp_config.start = false;
  esp_netif_sntp_init(&sntp_config);

  network->connect();

  // Register ourselves with a DynDNS provider
#ifdef CONFIG_RUN_DYNDNS
  DoDynDNS();
#endif

#ifdef CONFIG_HAVE_ACME
  acme = new Acme();

  acme->setFsPrefix(CONFIG_BASE_PATH);
#ifdef CONFIG_DYNDNS_DEVICE_URL
  acme->setUrl(CONFIG_DYNDNS_DEVICE_URL);
#else
#error did not define a URL for this device
#endif
  acme->setEmail(CONFIG_ACME_EMAIL);

  acme->setAccountFilename("account.json");
  acme->setOrderFilename("order.json");
  acme->setAccountKeyFilename("account.pem");
  acme->setCertKeyFilename("certkey.pem");

#ifdef CONFIG_ACME_PRODUCTION
  // Production server
#warning Watch out - the production server has rate limiting and should not be used for testing.
  acme->setAcmeServer("https://acme-v02.api.letsencrypt.org/directory");
  acme->setFilenamePrefix(CONFIG_BASE_PATH CONFIG_ACME_DIRECTORY "/production");
#else
  // Staging server
  acme->setAcmeServer("https://acme-staging-v02.api.letsencrypt.org/directory");
  acme->setFilenamePrefix(CONFIG_BASE_PATH CONFIG_ACME_DIRECTORY "/staging");
#endif

  // Causes reading it, so do this after setting the path !!
  acme->setCertificateFilename("certificate.pem");
#endif

  // Be accessible
  ESP_LOGI(tag, "Starting local web server and OTA ..");
  ws = new WebServer();
  ws->start();		// This will trigger OTA via App::WebServerStarted

#ifdef CONFIG_HAVE_ACME
  acme->setWebServer(web_server);

  /*
   * Startup code for ACME
   * Avoid talking to the server at each reboot
   */
  if (acme->HaveValidCertificate()) {
    ESP_LOGI(tag, "Certificate is valid, don't call the ACME server");
  } else {
    // This is just local processing
    if (acme->getAccountKey() == 0) {
      acme->GenerateAccountKey();
    }
    // This is just local processing
    if (acme->getCertificateKey() == 0) {
      acme->GenerateCertificateKey();
    }

    // Kickstart ACME, disable if this is not desired
    acme->CreateNewAccount();
    acme->CreateNewOrder();
  }
#endif
}

void App::loop(time_t now) {
  if (time_reboot != 0 && time_reboot > now)
    esp_restart();
  if (time_reconnect != 0 && time_reconnect > now) {
    // FIX
  }

  if (acme) {
    bool cert_updated = acme->loop(now);
    if (cert_updated) {
      ESP_LOGI(tag, "Certificate got updated, must restart secure web server");
      ws->CertificateUpdate();
    }
  }

  if (app->boot_time != 0 && boot_msg != 0) {
  }
}

void App::sntp_sync_notify(struct timeval *tvp) {
  ESP_LOGI(app->tag, "%s", __FUNCTION__);
  if (app->boot_time == 0) {
    app->boot_time = tvp->tv_sec;

    char ts[24];
    if (boot_msg == 0) {
      boot_msg = (char *)malloc(80);
      struct tm *tmp = localtime(&app->boot_time);
      strftime(ts, sizeof(ts), "%Y-%m-%d %T", tmp);
      sprintf(boot_msg, "Controller %s boot at %s", CONFIG_NODE_NAME, ts);
    }
  }
}

void App::connect(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;

  ESP_LOGI(app->tag, "Network connected, ip " IPSTR, IP2STR(&event->ip_info.ip));

  // Make local copies
  app->netif = event->esp_netif;
  app->ip_info = event->ip_info;

#ifdef	CONFIG_DEFAULT_TIMEZONE
    setenv("TZ", CONFIG_DEFAULT_TIMEZONE, 1);
#else
    setenv("TZ", "CET-1CEST,M3.5.0/2,M10.5.0/3", 1);
#endif
  tzset();

  esp_netif_sntp_start();
  sntp_set_time_sync_notification_cb(sntp_sync_notify);

  ESP_LOGI(app->tag, "Starting local ftp server");
  ftp_init();					// Start ftp server

  app->connected = true;
}

void App::disconnect(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  ESP_LOGI(app->tag, "%s", __FUNCTION__);

  app->connected = false;

  ftp_stop();					// Stop ftp server
  esp_sntp_stop();

  struct timeval tv;
  gettimeofday(&tv, 0);
  time_t nowts = tv.tv_sec;

  app->setReconnect(nowts + 20);
}

bool App::isConnected() {
  return connected;
}

void App::report(const char *line) {
}

char *App::timeString(void) {
  gettimeofday(&tv, 0);
  time_t n = tv.tv_sec;
  struct tm *tmp = localtime(&n);
  strftime(ts, sizeof(ts), "%Y-%m-%d %T", tmp);
  return ts;
}

char *App::timeString(time_t t) {
  struct tm *tmp = localtime(&t);
  strftime(ts, sizeof(ts), "%Y-%m-%d %T", tmp);
  return ts;
}

void App::timeString(time_t t, const char *format, char *buffer, int len) {
  struct tm *tmp = localtime(&t);
  strftime(buffer, len, format, tmp);
}

void App::timeString(time_t t, char *buffer, int len) {
  timeString(t, "%F %T", buffer, len);
}

void App::timeString(const char *format, char *buffer, int len) {
  time_t now = time(0);
  timeString(now, format, buffer, len);
}

const char *App::http_method2string(const int m) {
  switch (m) {
  case HTTP_GET:	return "GET";
  case HTTP_PUT:	return "PUT";
  case HTTP_POST:	return "POST";
  default:		return "?";
  }
}

void App::WebServerStarted(httpd_handle_t usrv, httpd_handle_t ssrv) {
  ESP_LOGI(tag, "%s", __FUNCTION__);
  app->web_server = usrv;
}

#ifdef REDIRECT_LOG_TO_FILE
int App::redirectLogToFile(const char *fmt, va_list args) {
  FILE *f = fopen(CONFIG_REDIRECT_LOG_TO_FILE_NAME, "a");
  if (!f)
    return -1;

  int ret = vfprintf(f, fmt, args);
  fflush(f);
  fclose(f);

  return ret;
}
#endif

#ifdef CONFIG_RUN_DYNDNS
void App::DoDynDNS() {
#if (!defined(CONFIG_DYNDNS_DEVICE_URL)) || (!defined(CONFIG_DYNDNS_AUTH))
  ESP_LOGE(tag, "%s: incomplete configuration", __FUNCTION__);
  return;
#endif

  ESP_LOGD(tag, "Registering with no-ip.com ... ");
  Dyndns *d = new Dyndns(DD_CLOUDNS);
  d->setHostname(CONFIG_DYNDNS_DEVICE_URL);
  d->setAuth(CONFIG_DYNDNS_AUTH);
  if (d->update())
    ESP_LOGI(tag, "%s(%s) succeeded", __FUNCTION__, CONFIG_DYNDNS_DEVICE_URL);
  else
    ESP_LOGE(tag, "%s(%s) failed", __FUNCTION__, CONFIG_DYNDNS_DEVICE_URL);
}
#endif

/*
 * Simplistic function combining both blacklist and whitelist.
 * This one gets used by OTA anyway (even if web security is cert based).
 *
 * You can specify a network address and number of bits, so 192.168.1.0/24 would
 * mean the default "home" address range gets allowed, with exception of blacklisted
 * hosts, which would e.g. be the DMZ host (because it's inherently dangerous).
 *
 * So example config :
 * BLACKLIST_IP_1 = 192.168.1.1 (your router)
 * BLACKLIST_IP_2 = 192.168.1.2 (your DMZ host)
 * WHITELIST_IP = 192.168.1.0 (network range)
 * WHITELIST_RANGE = 24 (specify last 8 bits consitute the range)
 *
 * This would allow all addresses in the 192.168.1.* ranage except 1 and 2.
 */
bool App::isPeerSecure(struct sockaddr_in *sap) {
  /*
   * Simplistic blacklist
   * Please note that depending on your NAT setup, you shouldn't blacklist the router.
   */
  if (sap->sin_addr.s_addr == ipaddr_addr(CONFIG_BLACKLIST_IP_1)) {
    ESP_LOGE(tag, "%s: blacklisted 1 (%s)", __FUNCTION__, inet_ntoa(sap->sin_addr));
    return false;
  }
  if (sap->sin_addr.s_addr == ipaddr_addr(CONFIG_BLACKLIST_IP_2)) {
    ESP_LOGE(tag, "%s: blacklisted 2 (%s)", __FUNCTION__, inet_ntoa(sap->sin_addr));
    // ESP_LOGE(tag, "%s: blacklisted", __FUNCTION__);
    return false;
  }
  if (sap->sin_addr.s_addr == ipaddr_addr(CONFIG_BLACKLIST_IP_3)) {
    ESP_LOGE(tag, "%s: blacklisted 3 (%s)", __FUNCTION__, inet_ntoa(sap->sin_addr));
    // ESP_LOGE(tag, "%s: blacklisted", __FUNCTION__);
    return false;
  }
  if (sap->sin_addr.s_addr == ipaddr_addr(CONFIG_BLACKLIST_IP_4)) {
    ESP_LOGE(tag, "%s: blacklisted 4 (%s)", __FUNCTION__, inet_ntoa(sap->sin_addr));
    // ESP_LOGE(tag, "%s: blacklisted", __FUNCTION__);
    return false;
  }

  /*
   * After the blacklist, add a simplistic whitelist.
   */
  in_addr_t caller = whitelist_filter & ntohl(sap->sin_addr.s_addr);
  in_addr_t white = whitelist_filter & ntohl(ipaddr_addr(CONFIG_WHITELIST_IP));

  if (caller == white) {
    ESP_LOGD(tag, "%s: address %s succeeded whitelist", __FUNCTION__, inet_ntoa(sap->sin_addr));
    return true;
  }

  ESP_LOGE(tag, "%s: address %s failed whitelist", __FUNCTION__, inet_ntoa(sap->sin_addr));
  return false;
}

bool App::isPeerSecure(int sock) {
  return isPeerSecure(sock, 0);
}

bool App::isPeerSecure(int sock, struct sockaddr_in *sap) {
  struct sockaddr_in sa;
  socklen_t al = sizeof(sa);

  errno = 0;
  if (getpeername(sock, (struct sockaddr *)&sa, &al) != 0) {
    ESP_LOGE(tag, "%s: getpeername failed, errno %d", __FUNCTION__, errno);
    return false;
  }

  if (sa.sin_addr.s_addr == 0) {
    // Try ipv6, see https://www.esp32.com/viewtopic.php?t=8317
    struct sockaddr_in6 sa6;
    al = sizeof(sa6);
    if (getpeername(sock, (struct sockaddr *)&sa6, &al) != 0) {
      ESP_LOGE(tag, "%s: getpeername6 failed, errno %d", __FUNCTION__, errno);
      return false;
    }

    sa.sin_addr.s_addr = sa6.sin6_addr.un.u32_addr[3];
  }

  ESP_LOGD(tag, "%s: IP address is %s, errno %d", __FUNCTION__, inet_ntoa(sa.sin_addr), errno);

  // Copy info into passed structure
  if (sap) {
    sap->sin_addr = sa.sin_addr;
  }
  return isPeerSecure(&sa);
}

/*
 * Helper function
 */
void App::installHandler(httpd_handle_t srv, const char *srv_s, httpd_method_t method,
	const char *uri, esp_err_t (*hdl)(httpd_req_t *r), const char *_tag, const char *fn) {
  httpd_uri_t uri_hdl_def;
  uri_hdl_def.uri = uri;
  uri_hdl_def.method = method;
  uri_hdl_def.user_ctx = 0;
  uri_hdl_def.handler = hdl;

  if (httpd_register_uri_handler(srv, &uri_hdl_def) != ESP_OK)
    ESP_LOGE(_tag, "%s: failed to register %s %s handler", fn, uri_hdl_def.uri,
      http_method2string(uri_hdl_def.method));
  else
    ESP_LOGI(_tag, "%s: registered %s %s handler for %s", fn,
      uri_hdl_def.uri, http_method2string(uri_hdl_def.method), srv_s);
}

void App::otaOngoing(bool busy) {
  ota_busy = busy;

  if (busy) {
    // OLED stuff deleted
  } else {
    // OLED stuff deleted
  }
}

void App::setReconnect(time_t then) {
  time_reconnect = then;
}

void App::setReboot(time_t then) {
  time_reboot = then;
}

void App::sendInfoMessage(char *msg) {
}

void App::sendAlarmMessage(char *msg) {
}

ModuleType App::String2ModuleType(const char *s) {
  if (s == 0)
    return mt_unknown;
  if (strcasecmp(s, json_module_type_cyd) == 0)
    return mt_cyd;
  if (strcasecmp(s, json_module_type_zx_ar) == 0)
    return mt_zx_ar;
  if (strcasecmp(s, json_module_type_zx_tr) == 0)
    return mt_zx_tr;
  return mt_unknown;
}

const char *App::ModuleType2String(ModuleType m) {
  switch (m) {
  case mt_cyd:
    return json_module_type_cyd;
  case mt_zx_ar:
    return json_module_type_zx_ar;
  case mt_zx_tr:
    return json_module_type_zx_tr;
  default:
    return "unknown";
  }
}

void App::failed_alloc_hook(size_t s, uint32_t caps, const char *fn) {
  char buf[80];
  buf[0] = 0;
  if (caps & MALLOC_CAP_EXEC) strcat(buf, "exec ");
  if (caps & MALLOC_CAP_32BIT) strcat(buf, "32bit ");
  if (caps & MALLOC_CAP_8BIT) strcat(buf, "8bit ");
  if (caps & MALLOC_CAP_DMA) strcat(buf, "DMA ");
  if (caps & MALLOC_CAP_PID2) strcat(buf, "PID2 ");
  if (caps & MALLOC_CAP_PID3) strcat(buf, "PID3 ");
  if (caps & MALLOC_CAP_PID4) strcat(buf, "PID4 ");
  if (caps & MALLOC_CAP_PID5) strcat(buf, "PID5 ");
  if (caps & MALLOC_CAP_PID6) strcat(buf, "PID6 ");
  if (caps & MALLOC_CAP_PID7) strcat(buf, "PID7 ");
  if (caps & MALLOC_CAP_SPIRAM) strcat(buf, "spiram ");
  if (caps & MALLOC_CAP_INTERNAL) strcat(buf, "internal ");
  if (caps & MALLOC_CAP_DEFAULT) strcat(buf, "default ");
  if (caps & MALLOC_CAP_IRAM_8BIT) strcat(buf, "iram8 ");
  if (caps & MALLOC_CAP_RETENTION) strcat(buf, "retention ");
  if (caps & MALLOC_CAP_RTCRAM) strcat(buf, "rtc ");
  if (caps & MALLOC_CAP_TCM) strcat(buf, "tcm ");
  if (caps & MALLOC_CAP_INVALID) strcat(buf, "? ");

  int buflen = strlen(buf);
  if (buflen > 0 && buf[buflen-1] == ' ')
    buf[buflen-1] = 0;	// Remove trailing space

  ESP_LOGE(app->tag, "Failed alloc: size %d caps %04X (caps %s) fn %s, task %s",
    (int)s, caps, buf, fn,
    pcTaskGetName(NULL));
}
