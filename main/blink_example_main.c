/* Blink Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "led_strip.h"
#include "sdkconfig.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_littlefs.h"
#include "mdns.h"
#include "lwip/apps/netbiosns.h"

#include "my_connect.h"

static const char *TAG = "main";

#define WEB_MOUNT_POINT "/littlefs"
// #define ACME_MOUNT_POINT "/undefined"
#define MDNS_HOST_NAME "RGB-Leds"
#define MDNS_INSTANCE "ELL test web server"

EventGroupHandle_t xEventTask;
int FTP_TASK_FINISH_BIT = BIT2;

extern esp_err_t start_rest_server(const char *base_path);

static led_strip_handle_t led_strip;

int dutyCycle1 = 0;
int dutyCycle2 = 0;
int dutyCycle3 = 0;
void set_leds(void)
{
    led_strip_set_pixel(led_strip, 0, dutyCycle1, dutyCycle2, dutyCycle3);
    led_strip_refresh(led_strip);
}

static void configure_led(void)
{
    ESP_LOGI(TAG, "Example configured to blink addressable LED!");
    /* LED strip initialization with the GPIO and pixels number*/
    led_strip_config_t strip_config = {
        .strip_gpio_num = CONFIG_BLINK_GPIO,
        .max_leds = 1, // at least one LED on board
    };

    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = 10 * 1000 * 1000, // 10MHz
        .flags.with_dma = false,
    };
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));
    /* Set all LED off to clear all pixels */
    led_strip_clear(led_strip);
    set_leds();
}

esp_err_t init_fs(void)
{
    esp_vfs_littlefs_conf_t conf = {
        .base_path = WEB_MOUNT_POINT,
        .partition_label = "storage",
        .format_if_mount_failed = false
    };
    esp_err_t ret = esp_vfs_littlefs_register(&conf);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find LITTLEFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize LITTLEFS (%s)", esp_err_to_name(ret));
        }
        return ESP_FAIL;
    }

    size_t total = 0, used = 0;
    ret = esp_littlefs_info(conf.partition_label, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get LITTLEFS partition information (%s)", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }

#ifdef ACME_MOUNT_POINT
    conf.base_path = ACME_MOUNT_POINT;
    conf.partition_label = "storage1";
    conf.format_if_mount_failed = true;
    ret = esp_vfs_littlefs_register(&conf);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find LITTLEFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize LITTLEFS (%s)", esp_err_to_name(ret));
        }
        return ESP_FAIL;
    }

    ret = esp_littlefs_info(conf.partition_label, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get LITTLEFS partition information (%s)", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }
#endif
    return ESP_OK;
}

static void initialise_mdns(void)
{
    mdns_init();
    mdns_hostname_set(MDNS_HOST_NAME);
    mdns_instance_name_set(MDNS_INSTANCE);

    mdns_txt_item_t serviceTxtData[] = {
        {"board", "esp32"},
        {"path", "/"}
    };

    ESP_ERROR_CHECK(mdns_service_add("ESP32-WebServer", "_http", "_tcp", 80, serviceTxtData,
                                     sizeof(serviceTxtData) / sizeof(serviceTxtData[0])));
}

void app_main(void)
{

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
        ESP_LOGE(TAG, "nvs_flash_init");
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    initialise_mdns();
    netbiosns_init();
    netbiosns_set_name(MDNS_HOST_NAME);

    ESP_ERROR_CHECK(init_fs());
    ESP_ERROR_CHECK(start_rest_server(WEB_MOUNT_POINT "/html"));

    ESP_LOGI(TAG, "Start my_connect");
    ESP_ERROR_CHECK(my_connect());

    /* Configure the peripheral according to the LED type */
    configure_led();

    if (1) {    // ftp сървър може да го забраним
        extern void ftp_task (void *pvParameters);
        // Create FTP server task
        xEventTask = xEventGroupCreate();
        xTaskCreate(ftp_task, "FTP", 1024*6, NULL, tskIDLE_PRIORITY + 2, NULL);
        // тези отдолу засега не ми трябват, те са за случай на изключване/превключване на ftp 
        // xEventGroupWaitBits( xEventTask,
        //         FTP_TASK_FINISH_BIT, /* The bits within the event group to wait for. */
        //         pdTRUE, /* BIT_0 should be cleared before returning. */
        //         pdFALSE, /* Don't wait for both bits, either bit will do. */
        //         portMAX_DELAY);/* Wait forever. */
        // ESP_LOGE(tag, "ftp_task finish");
    }

    // чака интернет връзка (от тук надолу не работят офлайн)
    while (!fl_connect)
        vTaskDelay(1000 / portTICK_PERIOD_MS);

    if (1) {    // може да го изключим
        extern void dynamic_dns_set(void);
        dynamic_dns_set();
    }
    
}