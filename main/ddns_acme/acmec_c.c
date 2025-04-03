#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include <esp_https_server.h>
#include "esp_tls.h"
#include <sys/time.h>

#include "secrets.h"    // вместо Konfig, ако липсва виж "secrets_demo.h"
#include "acmec_c.h"

static const char *TAG = "acmec_c.c";

static httpd_handle_t secure_server = NULL;

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
        ESP_LOGE(TAG, "Out of memory - Callback execution failed!");
        return;
    }

    // Logging the peer certificate info
    cert = mbedtls_ssl_get_peer_cert(ssl);
    if (cert != NULL) {
        mbedtls_x509_crt_info((char *) buf, buf_size - 1, "    ", cert);
        ESP_LOGI(TAG, "Peer certificate info:\n%s", buf);
    } else {
        ESP_LOGW(TAG, "Could not obtain the peer certificate!");
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
    ESP_LOGI(TAG, "User callback invoked!");
    mbedtls_ssl_context *ssl_ctx = NULL;
    switch(user_cb->user_cb_state) {
        case HTTPD_SSL_USER_CB_SESS_CREATE:
            ESP_LOGD(TAG, "At session creation");

            // Logging the socket FD
            int sockfd = -1;
            esp_err_t esp_ret;
            esp_ret = esp_tls_get_conn_sockfd(user_cb->tls, &sockfd);
            if (esp_ret != ESP_OK) {
                ESP_LOGE(TAG, "Error in obtaining the sockfd from tls context");
                break;
            }
            ESP_LOGI(TAG, "Socket FD: %d", sockfd);
            ssl_ctx = (mbedtls_ssl_context *) esp_tls_get_ssl_context(user_cb->tls);
            if (ssl_ctx == NULL) {
                ESP_LOGE(TAG, "Error in obtaining ssl context");
                break;
            }
            // Logging the current ciphersuite
            ESP_LOGI(TAG, "Current Ciphersuite: %s", mbedtls_ssl_get_ciphersuite(ssl_ctx));
            break;

        case HTTPD_SSL_USER_CB_SESS_CLOSE:
            ESP_LOGD(TAG, "At session close");
            // Logging the peer certificate
            ssl_ctx = (mbedtls_ssl_context *) esp_tls_get_ssl_context(user_cb->tls);
            if (ssl_ctx == NULL) {
                ESP_LOGE(TAG, "Error in obtaining ssl context");
                break;
            }
            print_peer_cert_info(ssl_ctx);
            break;
        default:
            ESP_LOGE(TAG, "Illegal state!");
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
    ESP_LOGI(TAG, "Starting server");

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();

    conf.servercert = servercert;
    conf.servercert_len = strlen((const char *)servercert) + 1;

    conf.prvtkey_pem = prvtkey;
    conf.prvtkey_len = strlen((const char *)prvtkey) + 1;

    conf.user_cb = https_server_user_callback;
    esp_err_t ret = httpd_ssl_start(&server, &conf);
    if (ESP_OK != ret) {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }

    // Set URI handlers
    ESP_LOGI(TAG, "Registering URI handlers");
    httpd_register_uri_handler(server, &root);
    return server;
}

void acme_client(void)
{
    esp_log_level_set(TAG, ESP_LOG_VERBOSE);
    esp_log_level_set("acme_c.cpp", ESP_LOG_VERBOSE);
    esp_log_level_set("Acme", ESP_LOG_VERBOSE);

    ESP_LOGI(TAG, "Start ACME client");
    if (secure_server == NULL) {
        acme_init(); // Without this, also not allowed to call have_valid_certificate()
        acme_set_fs_prefix(ACME_MOUNT_POINT);
#ifdef CONFIG_DO_PRODUCTION
        acme_set_filename_prefix(ACME_MOUNT_POINT "/acme/production");
#else
        acme_set_filename_prefix(ACME_MOUNT_POINT "/acme/staging");
#endif

        acme_set_account_filename("account.json");
        acme_set_order_filename("order.json");
        acme_set_account_key_filename("account.pem");
        acme_set_certkey_filename("certkey.pem");

        acme_set_url(CONFIG_URL);
        acme_set_email(CONFIG_EMAIL);
        acme_set_certificate_filename("certificate.pem"); // Causes reading it
#ifdef CONFIG_DO_PRODUCTION
        acme_set_acme_server("https://acme-v02.api.letsencrypt.org/directory");
#else
        acme_set_acme_server("https://acme-staging-v02.api.letsencrypt.org/directory");
#endif

        if (acme_have_valid_certificate()) {
            ESP_LOGI(TAG, "%s: we have a valid cert", __FUNCTION__);
            // Note : leak
            secure_server = start_webserver(acme_read_certificate(), acme_read_cert_key());
        } else {
            ESP_LOGE(TAG, "%s: we don't have a valid cert", __FUNCTION__);

            ESP_LOGE(TAG, "Ако четеш това може с ftp да копираш изправен 'staging' или 'production'.");
            ESP_LOGE(TAG, "Или закоментирай 'return' на долния ред.");
            return;

            if (acme_get_account_key() == 0) {
                ESP_LOGI(TAG, "generate account key");
                acme_generate_account_key();
            }
            if (acme_get_certkey() == 0) {
                acme_generate_certificate_key();
                ESP_LOGI(TAG, "generate certificate key");
            }

            acme_create_new_account();
            acme_create_new_order();

            httpd_handle_t simplews = acme_start_webserver();
            acme_set_webserver(simplews);

            // Simplistic loop - keep going until we get a cert, then start secure webserver
            while (!acme_have_valid_certificate()) {
                struct timeval tv;
                gettimeofday(&tv, 0);

                if (acme_loop(tv.tv_sec)) {
                    // Aha, we do have one now
                    // Note : leak
                    secure_server = start_webserver(acme_read_certificate(), acme_read_cert_key());
                }
                vTaskDelay(pdMS_TO_TICKS(10000)); // Don't retry too quickly, this is 10s (very quick)
            }
            acme_stop_webserver();
        }
    }
}