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
#include "esp_sntp.h"

#include "my_connect.h"
#include "secrets.h"    // вместо Konfig, ако липсва виж "secrets_demo.h"
#include "acmec_c.h"

static const char *TAG = "main";

#define MDNS_HOST_NAME "RGB-Leds"
#define MDNS_INSTANCE "ELL test web server"

EventGroupHandle_t xEventTask;
int FTP_TASK_FINISH_BIT = BIT2;

extern void StartWebServer(bool have_certificate);
extern void stop_rest_server(void);

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

    if (strcmp(WEB_MOUNT_POINT, ACME_MOUNT_POINT)) {
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
    }
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

#ifdef ENABLE_SNTP
static void time_sync_notification_cb(struct timeval *tv)
{
	ESP_LOGI(TAG, "Notification of a time synchronization event");
}
#endif

void app_main(void)
{
    // омръзна ми да замърсяват лога
    esp_log_level_set("wifi_init", ESP_LOG_WARN);
    esp_log_level_set("wifi", ESP_LOG_WARN);

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
    
    ESP_LOGI(TAG, "Start my_connect");
    ESP_ERROR_CHECK(my_connect());

    /* Configure the peripheral according to the LED type */
    configure_led();

#ifdef ENABLE_FTP
    extern void ftp_task (void *pvParameters);
    // Create FTP server task
    xEventTask = xEventGroupCreate();
    xTaskCreate(ftp_task, "FTP", 4095 * 2, NULL, tskIDLE_PRIORITY + 2, NULL);
    // тези отдолу засега не ми трябват, те са за случай на изключване/превключване на ftp 
    // xEventGroupWaitBits( xEventTask,
    //         FTP_TASK_FINISH_BIT, /* The bits within the event group to wait for. */
    //         pdTRUE, /* BIT_0 should be cleared before returning. */
    //         pdFALSE, /* Don't wait for both bits, either bit will do. */
    //         portMAX_DELAY);/* Wait forever. */
    // ESP_LOGE(tag, "ftp_task finish");
#endif

    // чака интернет връзка (от тук надолу не работят офлайн)
    while (!fl_connect)
        vTaskDelay(1000 / portTICK_PERIOD_MS);

#ifdef ENABLE_SNTP
    // obtain time over NTP
    ESP_LOGI(TAG, "Getting time over NTP.");
#define CONFIG_NTP_SERVER "pool.ntp.org"
    ESP_LOGI(TAG, "Initializing SNTP");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    ESP_LOGI(TAG, "Your NTP Server is %s", CONFIG_NTP_SERVER);
    esp_sntp_setservername(0, CONFIG_NTP_SERVER);
    sntp_set_time_sync_notification_cb(time_sync_notification_cb);
    esp_sntp_init();

	// wait for time to be set
	int retry = 0;
	const int retry_count = 10;
	while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET && ++retry < retry_count) {
		ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry, retry_count);
		vTaskDelay(2000 / portTICK_PERIOD_MS);
	}

    if (retry == retry_count) {
        ESP_LOGE(TAG, "Fail to getting time over NTP.");
        while(1) { vTaskDelay(1); }
    }

    // настройка на летен/зимен часови пояс за София
    setenv("TZ", "EET-2EEST,M3.5.0/3,M10.5.0/4", 1);	// Постановление 94 от 13 март 1997
    tzset();

    // Show current date & time
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];
    time(&now);
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The local date/time is: %s", strftime_buf);
#endif

#ifdef ENABLE_DDNS
    extern void dynamic_dns_set(void);
    dynamic_dns_set();
#endif

    bool have_certificate = false;
#ifdef ENABLE_ACME_CLIENT
#ifndef ENABLE_SNTP
#error We need exact time here. (ENABLE_SNTP)
#endif
    have_certificate = acme_client();
#endif

    StartWebServer(have_certificate);

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(100));
        int c = getchar();
        if (c > 0) {
            // за проби дали изтича памет при презапускане на http/https сървъри
            switch (c) {
            case 'h':
            case 'H':
                ESP_LOGI(TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
                break;
            case 'r':
            case 'R':
                stop_rest_server();
                StartWebServer(have_certificate);
                break;
            default:
                ESP_LOGI(TAG, "h - heap, r - restart web server");
                break;
            }
        }
    }
}