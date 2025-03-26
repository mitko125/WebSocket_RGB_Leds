#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "my_connect.h"
#include "dyndns_c.h"

static const char *TAG = "dyndns_c.c";

// за услугите на ClouDNS
// #define DDNS_PROVIDEF 2  // DD_CLOUDNS
// за услугите на NoIP
#define DDNS_PROVIDEF 1 // DD_NOIP

#include "secrets.h"

void dynamic_dns_set(void)
{
    esp_log_level_set("dyndns", ESP_LOG_VERBOSE);

    bool ddns_ok = false;
    do {
        // чака интернет връзка
        while (!fl_connect)
            vTaskDelay(1000 / portTICK_PERIOD_MS);

        vTaskDelay(1000 / portTICK_PERIOD_MS);

        dyndns_init(DDNS_PROVIDEF);
        dyndns_set_hostname(CONFIG_URL);
        dyndns_set_auth(CONFIG_DYNDNS_AUTH);
        ddns_ok = dyndns_update();
        if (ddns_ok)
            ESP_LOGI(TAG, "%s: DynDNS update ok (%s)", __FUNCTION__, CONFIG_URL);
        else
            ESP_LOGE(TAG, "%s: DynDNS update failed (%s)", __FUNCTION__, CONFIG_URL);
    }while(!ddns_ok);
    // някои повтарят на 24часа, но моя доставчик сменя по-често (но това е демо)
}