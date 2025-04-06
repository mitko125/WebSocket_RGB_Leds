/* HTTP Restful API Server

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <fcntl.h>
#include "esp_https_server.h"
#include "esp_chip_info.h"
#include "esp_random.h"
#include "esp_log.h"
#include "esp_vfs.h"
#include "cJSON.h"

#include "esp32-wifi-provision-care.h"

#include "secrets.h"    // вместо Konfig, ако липсва виж "secrets_demo.h"

static const char *REST_TAG = "esp-rest";
static const char *TAG = "ws-server";

#define REST_CHECK(a, str, goto_tag, ...)                                              \
    do                                                                                 \
    {                                                                                  \
        if (!(a))                                                                      \
        {                                                                              \
            ESP_LOGE(REST_TAG, "%s(%d): " str, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            goto goto_tag;                                                             \
        }                                                                              \
    } while (0)

#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + 128)
#define SCRATCH_BUFSIZE (10240)

typedef struct rest_server_context {
    char base_path[ESP_VFS_PATH_MAX + 1];
    char scratch[SCRATCH_BUFSIZE];
} rest_server_context_t;

#define CHECK_FILE_EXTENSION(filename, ext) (strcasecmp(&filename[strlen(filename) - strlen(ext)], ext) == 0)

/* Set HTTP response content type according to file extension */
static esp_err_t set_content_type_from_file(httpd_req_t *req, const char *filepath)
{
    const char *type = "text/plain";
    if (CHECK_FILE_EXTENSION(filepath, ".html")) {
        type = "text/html";
    } else if (CHECK_FILE_EXTENSION(filepath, ".js")) {
        type = "application/javascript";
    } else if (CHECK_FILE_EXTENSION(filepath, ".css")) {
        type = "text/css";
    } else if (CHECK_FILE_EXTENSION(filepath, ".png")) {
        type = "image/png";
    } else if (CHECK_FILE_EXTENSION(filepath, ".ico")) {
        type = "image/x-icon";
    } else if (CHECK_FILE_EXTENSION(filepath, ".svg")) {
        type = "text/xml";
    }
    return httpd_resp_set_type(req, type);
}

/* Send HTTP response with the contents of the requested file */
static esp_err_t rest_common_get_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];

    rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    strlcpy(filepath, rest_context->base_path, sizeof(filepath));
    if (req->uri[strlen(req->uri) - 1] == '/') {
        strlcat(filepath, "/index.html", sizeof(filepath));
    } else {
        strlcat(filepath, req->uri, sizeof(filepath));
    }
    int fd = open(filepath, O_RDONLY, 0);
    if (fd == -1) {
        ESP_LOGE(REST_TAG, "Failed to open file : %s", filepath);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
        return ESP_FAIL;
    }

    set_content_type_from_file(req, filepath);

    char *chunk = rest_context->scratch;
    ssize_t read_bytes;
    do {
        /* Read file in chunks into the scratch buffer */
        read_bytes = read(fd, chunk, SCRATCH_BUFSIZE);
        if (read_bytes == -1) {
            ESP_LOGE(REST_TAG, "Failed to read file : %s", filepath);
        } else if (read_bytes > 0) {
            /* Send the buffer contents as HTTP response chunk */
            if (httpd_resp_send_chunk(req, chunk, read_bytes) != ESP_OK) {
                close(fd);
                ESP_LOGE(REST_TAG, "File sending failed!");
                /* Abort sending file */
                httpd_resp_sendstr_chunk(req, NULL);
                /* Respond with 500 Internal Server Error */
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
                return ESP_FAIL;
            }
        }
    } while (read_bytes > 0);
    /* Close file after sending complete */
    close(fd);
    ESP_LOGI(REST_TAG, "File sending complete");
    /* Respond with an empty chunk to signal HTTP response completion */
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static char sliderValue1[5] = "0";
static char sliderValue2[5] = "0";
static char sliderValue3[5] = "0";

extern int dutyCycle1;
extern int dutyCycle2;
extern int dutyCycle3;

/*
 * Structure holding server handle
 * and internal socket fd in order
 * to use out of request send
 */
struct async_resp_text_arg {
    httpd_handle_t hd;
    int fd;
    char *text;
};

/*
 * async send function, which we put into the httpd work queue
 */
static void ws_async_send(void *arg)
{
    struct async_resp_text_arg *resp_arg = arg;
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));

    ws_pkt.payload = (uint8_t*)resp_arg->text;
    ws_pkt.len = strlen(resp_arg->text);
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    httpd_ws_send_frame_async(resp_arg->hd, resp_arg->fd, &ws_pkt);
    ESP_LOGV(TAG, "%s", resp_arg->text);

    free(resp_arg->text);
    resp_arg->text = NULL;
    free(resp_arg);
}

httpd_handle_t server = NULL;

extern void set_leds(void);
static void notifyClients(void)
{
    set_leds();

    // ws.textAll(sliderValues);
    size_t clients = CONFIG_LWIP_MAX_SOCKETS;
    int    client_fds[CONFIG_LWIP_MAX_SOCKETS];
    if (httpd_get_client_list(server, &clients, client_fds) == ESP_OK) {
        if (clients) {
            cJSON *record = cJSON_CreateObject();
            cJSON_AddStringToObject(record, "sliderValue1", sliderValue1);
            cJSON_AddStringToObject(record, "sliderValue2", sliderValue2);
            cJSON_AddStringToObject(record, "sliderValue3", sliderValue3);
            const char *serializedData = cJSON_PrintUnformatted(record);
            cJSON_Delete(record);
            if (strlen(serializedData) > 5) { // празни не пращаме
                // Serial.print(getSliderValues());
                ESP_LOGI(TAG, "Sending to all clients async message '%s'", serializedData);
                for (size_t i=0; i < clients; ++i) {
                    int sock = client_fds[i];
                    if (httpd_ws_get_fd_info(server, sock) == HTTPD_WS_CLIENT_WEBSOCKET) {
                        ESP_LOGI(TAG, "Active client (fd=%d) -> sending async message", sock);
                        struct async_resp_text_arg *resp_arg = malloc(sizeof(struct async_resp_text_arg));
                        assert(resp_arg != NULL);
                        resp_arg->hd = server;
                        resp_arg->fd = sock;
                        resp_arg->text = malloc(strlen(serializedData) + 1);
                        strcpy(resp_arg->text, serializedData);
                        if (httpd_queue_work(resp_arg->hd, ws_async_send, resp_arg) != ESP_OK) {
                            ESP_LOGE(TAG, "httpd_queue_work failed!");
                        }
                    }
                }
            }
            free((void *)serializedData);
        }
    } else {
        ESP_LOGE(TAG, "httpd_get_client_list failed!");
    }
}

/*
 * This handler echos back the received ws data
 * and triggers an async send if certain message received
 */
static esp_err_t echo_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "Handshake done, the new connection was opened");
        return ESP_OK;
    }
    httpd_ws_frame_t ws_pkt;
    uint8_t *buf = NULL;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;
    /* Set max_len = 0 to get the frame len */
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame failed to get frame len with %d", ret);
        return ret;
    }
    ESP_LOGI(TAG, "frame len is %d", ws_pkt.len);
    if (ws_pkt.len) {
        /* ws_pkt.len + 1 is for NULL termination as we are expecting a string */
        buf = calloc(1, ws_pkt.len + 1);
        if (buf == NULL) {
            ESP_LOGE(TAG, "Failed to calloc memory for buf");
            return ESP_ERR_NO_MEM;
        }
        ws_pkt.payload = buf;
        /* Set max_len = ws_pkt.len to get the frame payload */
        ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
            free(buf);
            return ret;
        }
        ESP_LOGI(TAG, "Got packet with message: %s", ws_pkt.payload);
    }
    ESP_LOGI(TAG, "Packet type: %d", ws_pkt.type);
    if (ws_pkt.type == HTTPD_WS_TYPE_TEXT) {
        char *message = (char*)ws_pkt.payload;
        ESP_LOGI(TAG, "message = %s", message);
        if (memcmp(message, "1s", 2) == 0) {
            // sliderValue1 = message.substring(2);
            strcpy(sliderValue1, message + 2);
            // dutyCycle1 = map(sliderValue1.toInt(), 0, 100, 0, 255);
            dutyCycle1 = atoi(sliderValue1) * 255 / 100;
            // Serial.println(dutyCycle1);
            ESP_LOGI(TAG, "sliderValue1 = %s, dutyCycle1 = %d", sliderValue1, dutyCycle1);
            // Serial.print(getSliderValues());
            // notifyClients(getSliderValues());
            notifyClients();
        }
        if (memcmp(message, "2s", 2) == 0) {
            strcpy(sliderValue2, message + 2);
            dutyCycle2 = atoi(sliderValue2) * 255 / 100;
            ESP_LOGI(TAG, "sliderValue2 = %s, dutyCycle2 = %d", sliderValue2, dutyCycle2);
            notifyClients();
        }
        if (memcmp(message, "3s", 2) == 0){
            strcpy(sliderValue3, message + 2);
            dutyCycle3 = atoi(sliderValue3) * 255 / 100;
            ESP_LOGI(TAG, "sliderValue3 = %s, dutyCycle3 = %d", sliderValue3, dutyCycle3);
            notifyClients();
        }
        if (strcmp(message, "getValues") == 0){
            notifyClients();
        }
        free(buf);
        return ESP_OK;
    }

    ret = httpd_ws_send_frame(req, &ws_pkt);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_send_frame failed with %d", ret);
    }
    free(buf);
    return ret;
}

// HTTP /
#ifdef ENABLE_OTA
static esp_err_t root_get_handler(httpd_req_t *req)
{
    extern const char wifi_start[] asm("_binary_ota_html_start");
    extern const char wifi_end[] asm("_binary_ota_html_end");
    const uint32_t wifi_len = wifi_end - wifi_start;
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, wifi_start, wifi_len);
    return ESP_OK;
}
#endif

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

esp_err_t start_rest_server(const char *base_path, const uint8_t *servercert, const uint8_t *prvtkey)
{
    REST_CHECK(base_path, "wrong base path", err);
    rest_server_context_t *rest_context = calloc(1, sizeof(rest_server_context_t));
    REST_CHECK(rest_context, "No memory for rest context", err);
    strlcpy(rest_context->base_path, base_path, sizeof(rest_context->base_path));

    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.httpd.uri_match_fn = httpd_uri_match_wildcard;
    config.user_cb = https_server_user_callback;

    if (servercert && prvtkey) {
        config.servercert = servercert;
        config.servercert_len = strlen((const char *)servercert) + 1;

        config.prvtkey_pem = prvtkey;
        config.prvtkey_len = strlen((const char *)prvtkey) + 1;
        ESP_LOGI(REST_TAG, "Starting HTTPS Server");
    } else {
        config.transport_mode = HTTPD_SSL_TRANSPORT_INSECURE;
        ESP_LOGI(REST_TAG, "Starting HTTP Server");
    }

    REST_CHECK(httpd_ssl_start(&server, &config) == ESP_OK, "Start server failed", err_start);

#ifdef ENABLE_OTA
    // Set URI handlers
    const httpd_uri_t root_uri = { 
        .uri = "/new_firmware",          
        .method = HTTP_GET,  
        .handler = root_get_handler 
    };
    httpd_register_uri_handler(server, &root_uri);

    // wifi_provision_care_updateota_post_handler POST handler from component uqfus/esp32-wifi-provision-care
    const httpd_uri_t updateota_uri = { 
        .uri = "/updateota", 
        .method = HTTP_POST, 
        .handler = wifi_provision_care_updateota_post_handler 
    };
    httpd_register_uri_handler(server, &updateota_uri);
#endif

    // Registering the ws handler
    httpd_uri_t ws = {
        .uri        = "/ws",
        .method     = HTTP_GET,
        .handler    = echo_handler,
        .user_ctx   = NULL,
        .is_websocket = true,
        .handle_ws_control_frames = true
    };
    httpd_register_uri_handler(server, &ws);

    /* URI handler for getting web server files */
    httpd_uri_t common_get_uri = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = rest_common_get_handler,
        .user_ctx = rest_context
    };
    httpd_register_uri_handler(server, &common_get_uri);

    return ESP_OK;
err_start:
    free(rest_context);
err:
    return ESP_FAIL;
}
