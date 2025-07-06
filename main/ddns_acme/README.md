# Представяне на сървъра в интернет, чрез Dynamic DNS и получаване на SSL/TLS сертификат от Let's Encrypt, чрез ACME клиент

## Представяне на сървъра в интернет, чрез Dynamic

Налага се да го ползваме, когато интернет доставчика не ни осигурява статичен IP адрес за връзка. Ползвам го и за получване на безплатен домейн (в случая името е някакво производно).

Използва се [компонента](https://components.espressif.com/components/dannybackx/dyndns/versions/0.0.3) с доставчици [NoIP](https://www.noip.com/) или [ClouDNS](https://www.cloudns.net/main/). Ползван е [примера](https://sourceforge.net/p/esp32-acme-client/code/HEAD/tree/trunk/examples/standalone/) от [компонента](https://components.espressif.com/components/dannybackx/acmeclient/versions/0.1.0), като е отрязана ACME частта.

1. Трябва да се регистрираме в някой от двата доставчици (при ClouDNS, могат да се получат до 50 DNS имена) и да получим име на домейн. Тук е показана работата и с двата. Нужно е да създадем файла 'secrets.h', който не е публицуван в GitHub, но има 'secrets_demo.h';
2. Трябва да се зададе стаичен IP адрес на платката ESP32 в рутера;
3. Трафика от входа на рутера трябра да се пренасочи към IP то на ESP32, аз знам за 2 начина:
    - чрез Forwarding / DMZ (препращане към демилитаризирана зона) или:
    - Forwarding / Virtual Server. Но тук трябва за всеки порт поотделно. Порт 80 обикновено е зает от Security / Remoute Manavment и някой от двата трябва да стане на 8080.
4. В ESP32 трябва да се извика dynamic_dns_set(), която ще запише IP то на рутера в DNS сървърите и в скоро време името на домейна в цял свят ще сочи това IP, а рутера ще прехвърля трафика към ESP32.

IP то на рутера узнавам от [api.ipify.org](https://api.ipify.org/) и го въвеждам в `NoIP` или `ClouDNS`.  

И рутерите имат механизъм за `Dynamic DNS` но аз с `ClouDNS` не успях, а с `NoIP` не пробвах.

### Забележки

Този клон е добра основа за случай, че нямаме статично IP за ESP32. За `ComNET` се оказа безпредметно, понеже не пускат никой към рутерите (зад тяхната DMZ), ако IP то му не е статично.

В реална обстановка трябва след всяко отпадане на рутера, а и да кажем на 1 час да се проверява public_ip и да се вика dyndns_update() при нужда.

## Получаване на SSL/TLS сертификат от Let's Encrypt, чрез ACME клиент

Използва се [ACME клиент](https://components.espressif.com/components/dannybackx/acmeclient/versions/0.1.0).

### **ВАЖНО:**

Спазете препръката:

```text
Build notes :
- you may have to augment default stack sizes such as
    CONFIG_SYSTEM_EVENT_TASK_STACK_SIZE=6144
    CONFIG_MAIN_TASK_STACK_SIZE=6144
  in the ESP-IDF "make menuconfig".
```

### **ЗАБЕЛЕЖКА:**

Понеже `FLASH_IN_PROJECT` в `CMakeLists.txt` изтрива целия `storage`, изграждаме допълнителен `storage1`, където `ACME клиента` да записва сертификатите си, без да се изтриват. Избира се с `#define ACME_MOUNT_POINT` и губим 100K flash. Другата опция е без `FLASH_IN_PROJECT`, ако както в случая е завършила разработката на html файловете. Избирам втория вариант и с готови сертификати и html файлове си играя през `ftp`. Всичко това може да се реши и през `Konfig` (за ACME [пример1](/managed_components/dannybackx__acmeclient/examples/standalone/main/Kconfig), [пример2](/managed_components/dannybackx__acmeclient/examples/framework/main/Kconfig) са добри), но това е учебен проект.

1. Ползван е [пример1](https://sourceforge.net/p/esp32-acme-client/code/HEAD/tree/trunk/examples/standalone/), като е отрязана `DynDNS` частта. Файловете `acmec.*` са поизрязани и преименувани в `acmec_c.*`. Добавен е и `acmec_c.c`, където е преобразувана оригинална логика от примера.
2. Преобразуваме `start_rest_server(...)` да работи като `start_webserver(..)` от горния `пример`. Това доведе до промени в `script.js` и трябва да се внимава с горната `ЗАБЕЛЕЖКА`. Вече сайта работи по `http` и `https`, в зависимост от наличието на сертификати.
3. От [пример2](/managed_components/dannybackx__acmeclient/examples/framework/) е взимствано обновяването на получен сертификат. Понеже не можех да чакам 2 месеца в `Acme.cpp` промених и двата `month` от `60 * 60 * 24 * 31` на `(60 * 60 * ( 24 * 89 ) + 74000)` и получих няколо самообновявания на ~28 минути. *МАЙТАП* понеже не си играх в [Сценична среда](https://letsencrypt.org/docs/staging-environment/) получих и [наказание](https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-hostnames) да чакам над 34 часа. В [пример2](/managed_components/dannybackx__acmeclient/examples/framework/) има и други интересни неща, като бял и черен списък на IP та и други, но е много суров.

## **Извод**

На ~2 месеца обновява сертификата. През това време ~10-20 секунди може да има проблеми с https и ftp сървърите, но е поносимо. След това презапуска https сървъра, може и да прересетваме ако искаме.  
`ACME` клиента е напълно работоспособен и може да се прилага в реални проекти.  
`ВНИМАНИЕ` Ей това `static int process_count = 5;` в `Acme.cpp` означава до 6 сполучливи или не, получен/удължен серификата на 1 вкючване. Ако всчко е наред, не пречи (това е 1 година без ресет).
