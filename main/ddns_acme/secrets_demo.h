ТОВА Е САМО ДЕМОНСТРАЦИЯ НА:
#include "secrets.h"

ДЕМОТО Е ОТ ТОЗИ РЕД НАДОЛУ (copy&pasete и поправете м/у %%% ... %%%):
#if DDNS_PROVIDEF == DD_CLOUDNS

#define CONFIG_URL "it doesn't matter" //"iot.dns-cloud.net" няма значение при ClouDNS

#define CONFIG_DYNDNS_AUTH \
"OTE%%% ей този дълъг низ ще го получите от ClouDNS като се регистрирате и си създадете host тип A %%%I3Y2NhMg"\
"&notify=1"
// може да добавяме
// "&ip=192.168.1.106"  // ако искаме определено IP 
// "&proxy=1"              // Ако сте зад прокси и вашият истински IP е зададен в заглавката X-Forwarded-For, трябва да добавите &proxy=1 в края на DynamicURL. 
// "&notify=1"             // Ако искате да получавате известия по имейл за промени 
// "&update_fo_main_ip=1"

#endif