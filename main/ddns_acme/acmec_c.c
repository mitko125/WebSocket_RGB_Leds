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

#define ACME_TEST_TIME (60 * 60) // на 1 час

extern void start_rest_web_server(bool have_certificate);
extern void stop_rest_web_server(void);

// вместо private: функция на Acme.cpp
static time_t TimeMbedToTimestamp(mbedtls_x509_time t)
{
    struct tm tms;
    tms.tm_year = t.year - 1900;
    tms.tm_mon = t.mon - 1;
    tms.tm_mday = t.day;
    tms.tm_hour = t.hour;
    tms.tm_min = t.min;
    tms.tm_sec = t.sec;
    tms.tm_isdst = false;

    return mktime(&tms);
}

// ТУКА САМО СЕ ОБНОВЯВА, НЕ СЕ ИЗДАВА СЕРИФИКАТ.
// симулираме до извесна степен техния acme_loop(.. защото няма критерий за запускане на техния
// http сървър, който пречи на други сървъри и викаме acme_loop(.. само при нужда от обновяване.
static void acme_client_task(void *pvParameters)
{
    httpd_handle_t simplews = NULL;
    // трябва да ресетваме ESP32 при неуспех по този брояч
    int cou = 0;
    vTaskDelay(pdMS_TO_TICKS(20000));

    while(true) {
        // проверява дали не е изтекъл ACME сертификата и го обновява 31 дена преди изтичането.
        struct timeval tv;
        gettimeofday(&tv, 0);

        time_t now = tv.tv_sec;
        // time_t month = 60 * 60 * 24 * 89 + 74000; // за тестове обновява на почти 28 минути (трябва да се сменят и 2бр. в Acme.cpp)
        time_t month = 60 * 60 * 24 * 31;
        const mbedtls_x509_crt *certificate = acme_get_certificate();
        time_t until = TimeMbedToTimestamp(certificate->valid_to);
        time_t end_time = (until - month) - now;
        ESP_LOGD(TAG, "to renewal certificate %d day %02d:%02d:%02d", (int)(end_time / (60 * 60 * 24)),
                 (int)(end_time % (60 * 60 * 24)) / (60 * 60), (int)(end_time % (60 * 60)) / 60, (int)(end_time % (60)));

        if ((end_time < 0) || simplews) {
            if (!simplews) { // пускаме http сървър без който не можем да обновим сертфиката (пречи на ftp и https)
                simplews = acme_start_webserver();
                acme_set_webserver(simplews);
            }
            if (acme_loop(tv.tv_sec)) {
                ESP_LOGI(TAG, "Certificate got updated, must restart secure web server");
                // При обнояване на сертификат трябва web клиента да се рефрешне след:
                // ресет на ESP32(ако можем да си го позволим на 2 месеца)
                // vTaskDelay(pdMS_TO_TICKS(10000));
                // esp_restart();

                // или рестартиран на веб сървъра
                stop_rest_web_server(); // презапускаме https сървъра
                start_rest_web_server(true);

                acme_stop_webserver();  // спираме http сървъра
                simplews = NULL;
                cou = 0;
            } else {
                ESP_LOGE(TAG, "Unsuccessful attempt to renewal certificate #%d", ++cou);
                if (cou > 100) {    // ресет след 100*10=1000 скунди ~ 17 минути и отиваме в acme_client_start 
                    // който е безкраен или http. Може да сме прекалили в production мод или заради пълно 
                    // изтичане на сертификата да е нужен нов. Тук само подноваваме.
                    ESP_LOGE(TAG, "Reset ESP32");
                    vTaskDelay(pdMS_TO_TICKS(10000));
                    esp_restart();
                }
            }
        }

        if (simplews)
            vTaskDelay(pdMS_TO_TICKS(10000)); // ускоряваме за обновяването, макар че казват 10sek е бързо, но демото е на 200ms
        else
            vTaskDelay(pdMS_TO_TICKS(1000 * ACME_TEST_TIME));
    }
}

bool acme_client_start(void)
{
    // esp_log_level_set(TAG, ESP_LOG_VERBOSE);
    // esp_log_level_set("Acme", ESP_LOG_VERBOSE);

    ESP_LOGI(TAG, "Start ACME client");
    bool have_certificate = false;
    while (!have_certificate) {
        acme_init(); // Without this, also not allowed to call have_valid_certificate()
        acme_set_fs_prefix(ACME_MOUNT_POINT);
#ifdef CONFIG_DO_PRODUCTION
        acme_set_filename_prefix(ACME_MOUNT_POINT "/acme/" PROVIDER_NAME "production");
#else
        acme_set_filename_prefix(ACME_MOUNT_POINT "/acme/" PROVIDER_NAME "staging");
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
            // ТУКА САМО СЕ ИЗДАВА, НЕ СЕ ОБНОВЯВА СЕРИФИКАТ.
            // АКО СЕРТИФИКАТА Е ИЗТЕКЪЛ ТРЯБВА ДА СЕ ИЗДАДЕ НОВ. НЕ СЕ ОБНОВЯВА ИЗТЕКЪЛ СЕРТИФИКАТ.
            ESP_LOGE(TAG, "%s: we don't have a valid cert", __FUNCTION__);

            // долните 5 реда могат да се махнат, когато сте готови
            ESP_LOGE(TAG, "Ако четеш това значи няма серификат или вече е изтекъл");
            ESP_LOGE(TAG, "Може с ftp да се копира изправен в 'staging' или 'production'.");
            ESP_LOGE(TAG, "Или да се стартира издаване на нов чрез:");
            ESP_LOGE(TAG, "Закоментиране 'return false;' на долния ред, който стартира http вместо https.");
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

            httpd_handle_t simplews = acme_start_webserver();
            acme_set_webserver(simplews);

            // Simplistic loop - keep going until we get a cert, then start secure webserver
            // може да излезем по брояч и да минем на http, не е желателен ресет на ESP32 не би помогнал.
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
            acme_stop_webserver();
        }
    }

    if (have_certificate)
        xTaskCreate(acme_client_task, "ACME_client", 4095 * 2, NULL, tskIDLE_PRIORITY, NULL);

    return have_certificate;
}