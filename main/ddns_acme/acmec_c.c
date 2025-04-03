#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include <esp_https_server.h>
#include "esp_tls.h"

#include "acmec_c.h"

static const char *TAG = "acmec_c.c";

void acme_client(void)
{
    ESP_LOGI(TAG, "Start ACME client");
}