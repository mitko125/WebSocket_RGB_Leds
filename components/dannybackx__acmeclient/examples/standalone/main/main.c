/*
 * This is a copy of the 'simple' HTTPS example, with changes for acme and dyndns.
 *
 * These changes are © 2024 by Danny Backx.
 */
/* Simple HTTP + SSL Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#define	DO_PRODUCTION

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include <sys/time.h>
#include "esp_netif.h"
#include "protocol_examples_common.h"

#include <esp_https_server.h>
#include "esp_tls.h"
#include "sdkconfig.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"

#include "acmec.h"
#include <esp_littlefs.h>

#ifdef CONFIG_DO_FTPSERVER
#include <ftpserv.h>
#endif

#define	CONFIG_BASE_PATH	"/fs"

/* A simple example that demonstrates how to create GET and POST
 * handlers and start an HTTPS server.
*/

static const char *tag = "example";
static httpd_handle_t secure_server = 0;
static bool we_have_time = false;

/* An HTTP GET handler */
static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, "<h1>Hello Secure World!</h1>", HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}

static void print_peer_cert_info(const mbedtls_ssl_context *ssl)
{
    const mbedtls_x509_crt *cert;
    const size_t buf_size = 1024;
    char *buf = calloc(buf_size, sizeof(char));
    if (buf == NULL) {
        ESP_LOGE(tag, "Out of memory - Callback execution failed!");
        return;
    }

    // Logging the peer certificate info
    cert = mbedtls_ssl_get_peer_cert(ssl);
    if (cert != NULL) {
        mbedtls_x509_crt_info((char *) buf, buf_size - 1, "    ", cert);
        ESP_LOGI(tag, "Peer certificate info:\n%s", buf);
    } else {
        ESP_LOGW(tag, "Could not obtain the peer certificate!");
    }

    free(buf);
}
/**
 * Example callback function to get the certificate of connected clients,
 * whenever a new SSL connection is created and closed
 *
 * Can also be used to other information like Socket FD, Connection state, etc.
 *
 * NOTE: This callback will not be able to obtain the client certificate if the
 * following config `Set minimum Certificate Verification mode to Optional` is
 * not enabled (enabled by default in this example).
 *
 * The config option is found here - Component config → ESP-TLS
 *
 */
static void https_server_user_callback(esp_https_server_user_cb_arg_t *user_cb)
{
    ESP_LOGI(tag, "User callback invoked!");
    mbedtls_ssl_context *ssl_ctx = NULL;
    switch(user_cb->user_cb_state) {
        case HTTPD_SSL_USER_CB_SESS_CREATE:
            ESP_LOGD(tag, "At session creation");

            // Logging the socket FD
            int sockfd = -1;
            esp_err_t esp_ret;
            esp_ret = esp_tls_get_conn_sockfd(user_cb->tls, &sockfd);
            if (esp_ret != ESP_OK) {
                ESP_LOGE(tag, "Error in obtaining the sockfd from tls context");
                break;
            }
            ESP_LOGI(tag, "Socket FD: %d", sockfd);
            ssl_ctx = (mbedtls_ssl_context *) esp_tls_get_ssl_context(user_cb->tls);
            if (ssl_ctx == NULL) {
                ESP_LOGE(tag, "Error in obtaining ssl context");
                break;
            }
            // Logging the current ciphersuite
            ESP_LOGI(tag, "Current Ciphersuite: %s", mbedtls_ssl_get_ciphersuite(ssl_ctx));
            break;

        case HTTPD_SSL_USER_CB_SESS_CLOSE:
            ESP_LOGD(tag, "At session close");
            // Logging the peer certificate
            ssl_ctx = (mbedtls_ssl_context *) esp_tls_get_ssl_context(user_cb->tls);
            if (ssl_ctx == NULL) {
                ESP_LOGE(tag, "Error in obtaining ssl context");
                break;
            }
            print_peer_cert_info(ssl_ctx);
            break;
        default:
            ESP_LOGE(tag, "Illegal state!");
            return;
    }
}

static const httpd_uri_t root = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = root_get_handler
};

static httpd_handle_t start_webserver(const uint8_t *servercert, const uint8_t *prvtkey)
{
    httpd_handle_t server = NULL;

    if (servercert == 0 || prvtkey == 0)
      return NULL;

    // Start the httpd server
    ESP_LOGI(tag, "Starting server");

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();

    conf.servercert = servercert;
    conf.servercert_len = strlen((const char *)servercert) + 1;

    conf.prvtkey_pem = prvtkey;
    conf.prvtkey_len = strlen((const char *)prvtkey) + 1;

    conf.user_cb = https_server_user_callback;
    esp_err_t ret = httpd_ssl_start(&server, &conf);
    if (ESP_OK != ret) {
        ESP_LOGI(tag, "Error starting server!");
        return NULL;
    }

    // Set URI handlers
    ESP_LOGI(tag, "Registering URI handlers");
    httpd_register_uri_handler(server, &root);
    return server;
}

static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_ssl_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (secure_server) {
        if (stop_webserver(secure_server) == ESP_OK) {
            secure_server = NULL;
        } else {
            ESP_LOGE(tag, "Failed to stop https server");
        }
    }
}

void sntp_sync_notify(struct timeval *tvp) {
  we_have_time = true;
}

/*
 * This function was modified so it can take not just hardcoded certificates
 * but also certificates from ACME.
 */
static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
  ip_event_got_ip_t *evp = (ip_event_got_ip_t *)event_data;

  ESP_LOGI(tag, "%s: address " IPSTR, __FUNCTION__, IP2STR(&evp->ip_info.ip));

#ifdef	CONFIG_DEFAULT_TIMEZONE
  setenv("TZ", CONFIG_DEFAULT_TIMEZONE, 1);
#else
  setenv("TZ", "CET-1CEST,M3.5.0/2,M10.5.0/3", 1);	// Most of Europe
#endif
  tzset();
  esp_netif_sntp_start();
  sntp_set_time_sync_notification_cb(sntp_sync_notify);
}

void app_main(void)
{
  // Make logging a bit more quiet
  esp_log_level_set("esp-x509-crt-bundle", ESP_LOG_ERROR);
  esp_log_level_set("esp_netif_handlers", ESP_LOG_ERROR);
  esp_log_level_set("wifi", ESP_LOG_ERROR);
  esp_log_level_set("wifi_init", ESP_LOG_ERROR);
  esp_log_level_set("example_connect", ESP_LOG_ERROR);
  esp_log_level_set("example_common", ESP_LOG_ERROR);

  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  /*
   * Get a filesystem
   */
  ESP_LOGI("app_main", "Mounting littlefs at %s", CONFIG_BASE_PATH);
  esp_vfs_littlefs_conf_t lcfg;
  bzero(&lcfg, sizeof(lcfg));
  lcfg.base_path = CONFIG_BASE_PATH;
  lcfg.format_if_mount_failed = true;
  lcfg.partition_label = "spiffs";
  ESP_ERROR_CHECK(esp_vfs_littlefs_register(&lcfg));

  /* Register event handlers to start server when Wi-Fi or Ethernet is connected,
   * and stop server when disconnection happens.
   */

  // Moved https server id into a global variable
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, 0));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, 0));

  /*
   * Certificate handling also requires a notion of the time
   */
  esp_sntp_config_t sntp_config = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(1, {"pool.ntp.org"} );
  sntp_config.start = false;
  esp_netif_sntp_init(&sntp_config);

  /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
   * Read "Establishing Wi-Fi or Ethernet Connection" section in
   * examples/protocols/README.md for more information about this function.
   */
  ESP_ERROR_CHECK(example_connect());

  // Wait until we got time info
  while (! we_have_time)
    vTaskDelay(pdMS_TO_TICKS(1000));	// One second

  // DynDNS
  dyndns_init(DD_CLOUDNS);
  dyndns_set_hostname(CONFIG_URL);
  dyndns_set_auth(CONFIG_DYNDNS_AUTH);
  if (dyndns_update())
    ESP_LOGI(tag, "%s: DynDNS update ok (%s)", __FUNCTION__, CONFIG_URL);
  else
    ESP_LOGE(tag, "%s: DynDNS update failed (%s)", __FUNCTION__, CONFIG_URL);

#ifdef CONFIG_DO_FTPSERVER
  // Optional : start an FTP server
  ESP_LOGI(tag, "Starting local ftp server");
  ftp_init();					// Start ftp server
#endif

  // ACME
  if (secure_server == NULL) {
    acme_init();	// Without this, also not allowed to call have_valid_certificate()
    acme_set_fs_prefix("/fs");
#ifdef CONFIG_DO_PRODUCTION
    acme_set_filename_prefix("/fs/acme/production");
#else
    acme_set_filename_prefix("/fs/acme/staging");
#endif

    acme_set_account_filename("account.json");
    acme_set_order_filename("order.json");
    acme_set_account_key_filename("account.pem");
    acme_set_certkey_filename("certkey.pem");

    acme_set_url(CONFIG_URL);
    acme_set_email(CONFIG_EMAIL);
    acme_set_certificate_filename("certificate.pem");	// Causes reading it
#ifdef CONFIG_DO_PRODUCTION
    acme_set_acme_server("https://acme-v02.api.letsencrypt.org/directory");
#else
    acme_set_acme_server("https://acme-staging-v02.api.letsencrypt.org/directory");
#endif

    if (acme_have_valid_certificate()) {
      ESP_LOGI(tag, "%s: we have a valid cert", __FUNCTION__);
      // Note : leak
      secure_server = start_webserver(acme_read_certificate(), acme_read_cert_key());
    } else {
      ESP_LOGE(tag, "%s: we don't have a valid cert", __FUNCTION__);

      if (acme_get_account_key() == 0) {
        ESP_LOGI(tag, "generate account key");
        acme_generate_account_key();
      }
      if (acme_get_certkey() == 0) {
        acme_generate_certificate_key();
        ESP_LOGI(tag, "generate certificate key");
      }

      acme_create_new_account();
      acme_create_new_order();

      httpd_handle_t simplews = acme_start_webserver();
      acme_set_webserver(simplews);

      // Simplistic loop - keep going until we get a cert, then start secure webserver
      while (! acme_have_valid_certificate()) {
	struct timeval tv;
	gettimeofday(&tv, 0);

	if (acme_loop(tv.tv_sec)) {
	  // Aha, we do have one now
	  // Note : leak
	  secure_server = start_webserver(acme_read_certificate(), acme_read_cert_key());
	}
	vTaskDelay(pdMS_TO_TICKS(10000));	// Don't retry too quickly, this is 10s (very quick)
      }
      acme_stop_webserver();
    }
  }
}
