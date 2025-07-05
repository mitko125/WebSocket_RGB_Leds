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

bool acme_client(void)
{
    // esp_log_level_set(TAG, ESP_LOG_VERBOSE);
    // esp_log_level_set("acme_c.cpp", ESP_LOG_VERBOSE);
    // esp_log_level_set("Acme", ESP_LOG_VERBOSE);

    ESP_LOGI(TAG, "Start ACME client");
    bool have_certificate = false;
    while (!have_certificate) {
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
            have_certificate = true;
        } else {
            ESP_LOGE(TAG, "%s: we don't have a valid cert", __FUNCTION__);

            // долните 3 реда могат да се махнат, когато сте готови
            ESP_LOGE(TAG, "Ако четеш това може с ftp да копираш изправен 'staging' или 'production'.");
            ESP_LOGE(TAG, "Или закоментирай 'return false;' на долния ред.");
            return false;

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

            // !!! да се направи и при обновяване на серитфика проблем #3
            httpd_handle_t simplews = acme_start_webserver();
            acme_set_webserver(simplews);

            // Simplistic loop - keep going until we get a cert, then start secure webserver
            // може да излезем по брояч и да минем на http
            int cou = 0;
            while (!acme_have_valid_certificate()) {
                struct timeval tv;
                gettimeofday(&tv, 0);

                if (acme_loop(tv.tv_sec)) {
                    // Aha, we do have one now
                    // Note : leak
                    have_certificate = true;
                } else
                    ESP_LOGE(TAG, "Unsuccessful attempt to obtain certificate #%d", ++cou);
                vTaskDelay(pdMS_TO_TICKS(10000)); // Don't retry too quickly, this is 10s (very quick)
            }
            // !!! да се направи и при обновяване на серитфика проблем #3
            acme_stop_webserver();
        }
    }

    return have_certificate;
}