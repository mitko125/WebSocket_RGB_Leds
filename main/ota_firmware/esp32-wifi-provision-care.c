/*
    ESP-IDF examples code used
    Public domain
*/
#include <inttypes.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "esp_http_server.h"
#include "lwip/inet.h"
#include "nvs.h"
#include "cJSON.h"
#include "esp_app_format.h"

static const char *TAG = "esp32-wifi-provision-care";

static void esp_restart_after_3sec_task( void *param )
{
    vTaskDelay( 3000 / portTICK_PERIOD_MS );
    esp_restart();
    vTaskDelete(NULL); // Task functions should never return.
}
// Dealyed restart. Give some time to httpd server.
static void esp_restart_after_3sec(void)
{
    xTaskCreate(esp_restart_after_3sec_task, "delayed_restart_3s", 4096, NULL, tskIDLE_PRIORITY, NULL);
}

// MARK: ota handler
// todo CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE handling
// HTTP /updateota - Wi-Fi page
#define BUFSIZE 5800 // 5760 - receive chunk, got from httpd server logs
esp_err_t wifi_provision_care_updateota_post_handler(httpd_req_t *req)
{
    esp_err_t err;
    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    esp_ota_handle_t update_handle = 0 ;

    ESP_LOGI(TAG, "Starting update over the air.");

    const esp_partition_t *configured = esp_ota_get_boot_partition();
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (configured != running)
    {
        ESP_LOGW(TAG, "Configured OTA boot partition at offset 0x%08"PRIx32", but running from offset 0x%08"PRIx32,
                 configured->address, running->address);
        ESP_LOGW(TAG, "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    }

    if ( req->content_len == 0 )
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Firmware too short.");
        return ESP_OK;
    }
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if ( req->content_len > update_partition->size )
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Firmware too big.");
        return ESP_OK;
    }
    ESP_LOGI(TAG, "Begin writing %d bytes firmware to partition '%s'.", req->content_len,  update_partition->label);

    err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
        esp_ota_abort(update_handle);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_begin failed.");
        return ESP_OK;
    }

    char *buf = malloc(BUFSIZE+1);
    int received;
    int remaining = req->content_len;
    /*deal with all receive packet*/
    bool image_header_was_checked = false;
    while (remaining > 0)
    {
        ESP_LOGI(TAG, "Remaining size : %d", remaining);
        if ( (received = httpd_req_recv(req, buf, (remaining > BUFSIZE ? BUFSIZE : remaining) )) <= 0 )
        {
            if (received == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry if timeout occurred */
                continue;
            }
            ESP_LOGE(TAG, "Firmware reception failed!");
            esp_ota_abort(update_handle);
            free(buf);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive firmware.");
            return ESP_OK;
        }

        if (image_header_was_checked == false) {
            esp_app_desc_t new_app_info;
            if (received > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t)) {
                // check current version with downloading
                memcpy(&new_app_info, &buf[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
                ESP_LOGI(TAG, "New firmware version: %s", new_app_info.version);

                esp_app_desc_t running_app_info;
                if (esp_ota_get_partition_description(running, &running_app_info) == ESP_OK) {
                    ESP_LOGI(TAG, "Running firmware version: %s", running_app_info.version);
                }

                const esp_partition_t* last_invalid_app = esp_ota_get_last_invalid_partition();
                esp_app_desc_t invalid_app_info;
                if (esp_ota_get_partition_description(last_invalid_app, &invalid_app_info) == ESP_OK) {
                    ESP_LOGI(TAG, "Last invalid firmware version: %s", invalid_app_info.version);
                }

                // check current version with last invalid partition
                if (last_invalid_app != NULL) {
                    if (memcmp(invalid_app_info.version, new_app_info.version, sizeof(new_app_info.version)) == 0) {
                        ESP_LOGW(TAG, "New version is the same as invalid version.");
                        ESP_LOGW(TAG, "Previously, there was an attempt to launch the firmware with %s version, but it failed.", invalid_app_info.version);
                        ESP_LOGW(TAG, "The firmware has been rolled back to the previous version.");
                    }
                }
                if (memcmp(new_app_info.version, running_app_info.version, sizeof(new_app_info.version)) == 0) {
                    ESP_LOGW(TAG, "Current running version is the same as a new."); // We will not continue the update.");
                    // esp_ota_abort(update_handle);
                    // free(buf);
                    // httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Current running version is the same as a new. We will not continue the update.");
                    // return ESP_OK;
                }
            } else {
                ESP_LOGE(TAG, "received package is not fit len");
            }
            image_header_was_checked = true;
        }

        err = esp_ota_write( update_handle, (const void *)buf, received);
        if (err != ESP_OK)
        {
            esp_ota_abort(update_handle);
            free(buf);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_write failed.");
            return ESP_OK;
        }
        remaining -= received;
    }
    free(buf);

    err = esp_ota_end(update_handle);
    if (err != ESP_OK)
    {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED)
        {
            ESP_LOGE(TAG, "Image validation failed, image is corrupted!");
        } else {
            ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        }
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_end failed.");
        return ESP_OK;
    }
    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_set_boot_partition failed.");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Restart to new firmware.");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, "Update firmware over the air finished sucessfully.", HTTPD_RESP_USE_STRLEN);
    esp_restart_after_3sec(); // Give some time to httpd server
    return ESP_OK;
}