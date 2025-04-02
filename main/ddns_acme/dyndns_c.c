#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "esp_tls.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif
#include "esp_http_client.h"

#include "my_connect.h"
#include "dyndns_c.h"

static const char *TAG = "dyndns_c.c";

// за услугите на ClouDNS
#define DDNS_PROVIDEF 2 // DD_CLOUDNS
// за услугите на NoIP
// #define DDNS_PROVIDEF 1 // DD_NOIP

#include "secrets.h"

#define MAX_HTTP_OUTPUT_BUFFER 2048
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer; // Buffer to store response of http request from event handler
    static int output_len;      // Stores number of bytes read
    switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        // Clean the buffer in case of a new request
        if (output_len == 0 && evt->user_data) {
            // we are just starting to copy the output data into the use
            memset(evt->user_data, 0, MAX_HTTP_OUTPUT_BUFFER);
        }
        /*
         *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
         *  However, event handler can also be used in case chunked encoding is used.
         */
        if (!esp_http_client_is_chunked_response(evt->client)) {
            // If user_data buffer is configured, copy the response into the buffer
            int copy_len = 0;
            if (evt->user_data) {
                // The last byte in evt->user_data is kept for the NULL character in case of out-of-bound access.
                copy_len = MIN(evt->data_len, (MAX_HTTP_OUTPUT_BUFFER - output_len));
                if (copy_len)
                {
                    memcpy(evt->user_data + output_len, evt->data, copy_len);
                }
            } else {
                int content_len = esp_http_client_get_content_length(evt->client);
                if (output_buffer == NULL) {
                    // We initialize output_buffer with 0 because it is used by strlen() and similar functions therefore should be null terminated.
                    output_buffer = (char *)calloc(content_len + 1, sizeof(char));
                    output_len = 0;
                    if (output_buffer == NULL) {
                        ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                        return ESP_FAIL;
                    }
                }
                copy_len = MIN(evt->data_len, (content_len - output_len));
                if (copy_len) {
                    memcpy(output_buffer + output_len, evt->data, copy_len);
                }
            }
            output_len += copy_len;
        }
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
        if (output_buffer != NULL) {
            // Response is accumulated in output_buffer. Uncomment the below line to print the accumulated response
            // ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
            free(output_buffer);
            output_buffer = NULL;
        }
        output_len = 0;
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
        if (err != 0) {
            ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
            ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        if (output_buffer != NULL) {
            free(output_buffer);
            output_buffer = NULL;
        }
        output_len = 0;
        break;
    case HTTP_EVENT_REDIRECT:
        ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
        esp_http_client_set_header(evt->client, "From", "user@example.com");
        esp_http_client_set_header(evt->client, "Accept", "text/html");
        esp_http_client_set_redirection(evt->client);
        break;
    }
    return ESP_OK;
}

// за този буфер най добре да си поиграем с malloc(, но ме мързи
static char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};
// прочетеното от api.ipify.org IP
static char public_ip[4 * 4] = {0};
// записаното от dyndns_update() IP, трябва да го пазим в енергонезависима памет
char *nvs_ip = "";
static esp_err_t get_public_ip(void)
{
    esp_err_t err = ESP_OK;

    esp_http_client_config_t config = {
        .host = "api.ipify.org",
        .path = "/", // ако искаме обикновен текст
        // .path = "/?format=json",    // ако искаме да декодираме JSON
        .transport_type = HTTP_TRANSPORT_OVER_TCP, // ако искаме нешифрована връзка
        // .transport_type = HTTP_TRANSPORT_OVER_SSL,  // ако искама шифрована връзка но трябва и .cert_pem = сертификат
        // или .crt_bundle_attach = esp_crt_bundle_attach
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer, // Pass address of local buffer to get response
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // GET
    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        int64_t length = esp_http_client_get_content_length(client);
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %" PRId64, status, length);
        if (length) {
            strcpy(public_ip, local_response_buffer);
        }
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }
    ESP_LOG_BUFFER_HEXDUMP(TAG, local_response_buffer, strlen(local_response_buffer), ESP_LOG_DEBUG);

    esp_http_client_cleanup(client);

    return err;
}

void dynamic_dns_set(void)
{
    // esp_log_level_set(TAG, ESP_LOG_VERBOSE);
    // esp_log_level_set("dyndns", ESP_LOG_VERBOSE);

    ESP_ERROR_CHECK(get_public_ip());
    ESP_LOGI(TAG, "My public IP : %s", public_ip);

    while (strcmp(public_ip, nvs_ip)) {

        bool ddns_ok = false;
        do {
            vTaskDelay(1000 / portTICK_PERIOD_MS);

            dyndns_init(DDNS_PROVIDEF);
            dyndns_set_hostname(CONFIG_URL);
            dyndns_set_auth(CONFIG_DYNDNS_AUTH);
            ddns_ok = dyndns_update();
            if (ddns_ok)
                ESP_LOGI(TAG, "%s: DynDNS update ok (%s)", __FUNCTION__, CONFIG_URL);
            else
                ESP_LOGE(TAG, "%s: DynDNS update failed (%s)", __FUNCTION__, CONFIG_URL);
        } while (!ddns_ok);

        nvs_ip = public_ip; // това е само демо
    };
}