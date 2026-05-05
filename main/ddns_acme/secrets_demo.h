// ТОВА Е САМО ДЕМОНСТРАЦИЯ НА:
// #include "secrets.h"    // вместо Konfig, ако липсва виж "secrets_demo.h"

// ДЕМОТО Е ОТ ТОЗИ РЕД НАДОЛУ (copy&paste и поправете м/у %%% ... %%%):

// ### 1 . firmware-upload-ota
// #define ENABLE_OTA 1

// ### 2 . Dynamic DNS
// #define ENABLE_DDNS 1

// ### 3 . Добавен ftp сървър
// #define ENABLE_FTP 1

// ### 4 . Получване на точно време от SNTP сървър
// #define ENABLE_SNTP 1

// ### 5 . SSL/TLS сертификат
// #define ENABLE_ACME_CLIENT 1


// диск за интернет сайта
#define WEB_MOUNT_POINT "/html_fs"

// диск за ACME клиента
// може да изберем друга точка виж (/main/ddns_acme/README.md#забележка), или като WEB_MOUNT_POINT
#define ACME_MOUNT_POINT "/acme_fs"
// #define ACME_MOUNT_POINT WEB_MOUNT_POINT

// диск за ftp сървъра
#define FTP_MOUNT_POINT ACME_MOUNT_POINT
// #define FTP_MOUNT_POINT WEB_MOUNT_POINT
#define CONFIG_FTP_USER         "admin"
#define CONFIG_FTP_PASSWORD     "admin"


// за услугите на NoIP
// #define DDNS_PROVIDER 1 // DD_NOIP
// за услугите на ClouDNS
// #define DDNS_PROVIDER 2 // DD_CLOUDNS
// за услугите на DuckDNS
#define DDNS_PROVIDER 3 // DD_DUCKDNS

#undef CONFIG_DYNDNS_AUTH //за да не се бие с sdkconfig

#if DDNS_PROVIDER == 1    // DD_NOIP

#define PROVIDER_NAME "NoIP/"
// хоста или домейна, за който сме конфигурирали DynDNS IP то и сертифицирали ACME client 
#define CONFIG_URL "вашия.hopto.org"

// #define CONFIG_DYNDNS_AUTH "името ви(емайл):паволата ви"
// кодирано с https://www.base64encode.org/ (това не е шифроване, декодира се)
#define CONFIG_DYNDNS_AUTH "bW една дълга ала-бала xLg"

#elif DDNS_PROVIDER == 2  // DD_CLOUDNS

#define PROVIDER_NAME "ClouDNS/"
// хоста или домейна, за който сме конфигурирали DynDNS IP то и сертифицирали ACME client 
#define CONFIG_URL "it doesn't matter" //"iot.dns-cloud.net" няма значение при ClouDNS, но при ACME client е важно

#define CONFIG_DYNDNS_AUTH \
"OTE%%% ей този дълъг низ ще го получите от ClouDNS като се регистрирате и си създадете host тип A (в Active Dynamic URL)%%%I3Y2NhMg"\
"&notify=1"
// може да добавяме
// "&ip=192.168.1.106"  // ако искаме определено IP 
// "&proxy=1"              // Ако сте зад прокси и вашият истински IP е зададен в заглавката X-Forwarded-For, трябва да добавите &proxy=1 в края на DynamicURL. 
// "&notify=1"             // Ако искате да получавате известия по имейл за промени 
// "&update_fo_main_ip=1"

#elif DDNS_PROVIDER == 3  // DD_DUCKDNS

#define PROVIDER_NAME "DuckDNS/"
// хоста или домейна, за който сме конфигурирали DuckDNS IP то и сертифицирали ACME client 
#define CONFIG_URL "вашия.duckdns.org"

// token от регистрацията в https://www.duckdns.org/domains
#define CONFIG_DYNDNS_AUTH "%%% ... %%%"

#elifndef DDNS_PROVIDER

error ---> "DDNS_PROVIDER must be defined"

#endif  // DDNS_PROVIDER == ...


// ACME client
// тук трябва да пращат емейл, че изтича сертификата. Но май са спрели да пращат.
#define CONFIG_EMAIL "test@test-mail.com"


// за експирименто без него, ако е за реален сертификат с него. Сменя от staging в production при #define
#define CONFIG_DO_PRODUCTION 1