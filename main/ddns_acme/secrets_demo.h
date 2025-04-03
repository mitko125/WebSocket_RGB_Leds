ТОВА Е САМО ДЕМОНСТРАЦИЯ НА:
#include "secrets.h"    // вместо Konfig, ако липсва виж "secrets_demo.h"

ДЕМОТО Е ОТ ТОЗИ РЕД НАДОЛУ (copy&pasete и поправете м/у %%% ... %%%):
#define WEB_MOUNT_POINT "/littlefs"
// може да изберем друга точка виж (/main/ddns_acme/README.md#забележка), или като WEB_MOUNT_POINT
// #define ACME_MOUNT_POINT "/undefined"
#define ACME_MOUNT_POINT WEB_MOUNT_POINT

// за услугите на ClouDNS
#define DDNS_PROVIDEF 2 // DD_CLOUDNS
// за услугите на NoIP
// #define DDNS_PROVIDEF 1 // DD_NOIP

#if DDNS_PROVIDEF == 2  // DD_CLOUDNS

// хоста или домейна, за който сме конфигурирали DynDNS IP то и сертифицирали ACME client 
#define CONFIG_URL "it doesn't matter" //"iot.dns-cloud.net" няма значение при ClouDNS, но при ACME client е важно

#define CONFIG_DYNDNS_AUTH \
"OTE%%% ей този дълъг низ ще го получите от ClouDNS като се регистрирате и си създадете host тип A %%%I3Y2NhMg"\
"&notify=1"
// може да добавяме
// "&ip=192.168.1.106"  // ако искаме определено IP 
// "&proxy=1"              // Ако сте зад прокси и вашият истински IP е зададен в заглавката X-Forwarded-For, трябва да добавите &proxy=1 в края на DynamicURL. 
// "&notify=1"             // Ако искате да получавате известия по имейл за промени 
// "&update_fo_main_ip=1"

#elif DDNS_PROVIDEF == 1    // DD_NOIP

// хоста или домейна, за който сме конфигурирали DynDNS IP то и сертифицирали ACME client 
#define CONFIG_URL "вашия.hopto.org"

// #define CONFIG_DYNDNS_AUTH "името ви(емайл):паволата ви"
// кодирано с https://www.base64encode.org/ (това не е шифроване, декодира се)
#define CONFIG_DYNDNS_AUTH "bW една дълга ала-бала xLg"

#endif

// ACME client
// тук трябва да пращат емейл, че изтича сертификата. Но май са спрели да пращат.
#define CONFIG_EMAIL "test@test-mail.com"
// за експирименто без него, ако е за реален сертификат с него
#define CONFIG_DO_PRODUCTION 1