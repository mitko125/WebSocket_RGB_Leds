# WebSocket_RGB_Leds

За управление на RGB светодиод чрез WebSocket.  
Проекта е учебен и тестови.  
Използва [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) **v5.3.1** на кит с процесор ESP32-S3-N16R8 и трицветен светодиод WS2812B, към извод GPIO48.

- за основа послужи примера [Blink Example](https://github.com/espressif/esp-idf/tree/master/examples/get-started/blink);
- добавен е примера [ESP32 Web Server (WebSocket) with Multiple Sliders: Control LEDs Brightness (PWM)](https://randomnerdtutorials.com/esp32-web-server-websocket-sliders/);
  - за съжаление примера е за [Arduino IDE](https://www.arduino.cc/). Затова първо го запуснах със симулиране на [node js](https://nodejs.org/en/download). След изтгляне и исталиране изисква еднократно запускане в 'cmd' : 'npm install'. Стартиране на сървъра в 'cmd' : 'node webserver.js'. Стартиране на клиент в Web Browser : <http://localhost/>, могат да се запуснат няколко клиента и да се види, че се променят едновременно. Стоиностите на светодиодите в %(0-100) се виждат в 'cmd' козолата;
  - директорито 'html' е с оригиналните html файлове от цитирания проект (ще се използват и в ESP-IDF). Създаден е само имитатора на сървъра 'webserver.js'.
- етапи по влючването на горниия [пример](https://randomnerdtutorials.com/esp32-web-server-websocket-sliders/) към кита ESP32-S3 по [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html):
  - добавяне на WiFi връзка към кита. Задайте вашите 'WiFi SSID' и 'WiFi Password'. Връзката е чрез файловете 'my_config.*', възможни са много опции на връзката чрез 'Konfig_inthenet'. В 'sdkconfig.defaults' вече е включена и поддръжката на WebSocket, за да не се налага ново преконфигуриране и пълно компилиране. Вече кита може да се пингва по IP то показано в 'I (5319) my_connect: - IPv4 address: 192.168.1.101,';
  - добавяне на WebServer, взетo е само необходимото от [HTTP Restful API Server Example](https://github.com/espressif/esp-idf/tree/master/examples/protocols/http_server/restful_server). Интерисува ни само съкратен 'rest_server.c'. Папката 'html' е добавена в ESP-IDF като "/spiffs". Вече е възможно стартиране на клиент в Web Browser : <http://192.168.1.101> (сложете вашето IP). Светодиода още само мига, не се управлява от плъзгачите;
  - добавяне на [mDNS](https://components.espressif.com/components/espressif/mdns/versions/1.8.0) рекламиране.  Вече е възможно стартиране на клиент в Web Browser по име : <http://rgb-leds/>
  - добавен WebSocket сървър от примера [Websocket echo server](https://github.com/espressif/esp-idf/tree/master/examples/protocols/http_server/ws_echo_server). Засега само успешно се свързва с клиентите и приема тяхни съобщения.
  - преобразуване [Arduino файла](https://raw.githubusercontent.com/RuiSantosdotme/Random-Nerd-Tutorials/master/Projects/ESP32/ESP32_Multiple_Sliders_Web_Server/ESP32_Multiple_Sliders_Web_Server.ino) от примера [ESP32 Web Server (WebSocket) with Multiple Sliders: Control LEDs Brightness (PWM)](https://randomnerdtutorials.com/esp32-web-server-websocket-sliders/) по правилата на [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) и управление на RGB светодиода.  

**Проекта е завършен успешно, до 5 клиента работят заедно.**  

## Ако има нови експерименти, ще бъдат описани по-долу:

### 1 . firmware-upload-ota

За смяна на софтуера през мрежата:

- за основа послужи примера [esp32-firmware-upload-ota-example](https://github.com/uqfus/esp32-wifi-provision-care/tree/main/examples/esp32-firmware-upload-ota-example). Файловете на примера са прехвърлени от 'managed_components' в директори 'ota_firmware' и имат собствена [документация](main/ota_firmware/README.md). Смяната се извършва през Web Browser : <http://rgb-leds/new_firmware> или чрез **curl** :

```bash
curl --data-binary @WebSocket_RGB_Leds.bin http://rgb-leds/updateota
```

### 2 . Dynamic DNS

Представяне на сървъра в интернет, чрез [Dynamic DNS](https://en.wikipedia.org/wiki/Dynamic_DNS).

Файловете са събрани в [директори](/main/ddns_acme/) и имат [документация](/main/ddns_acme/README.md#представяне-на-сървъра-в-интернет-чрез-dynamic).

### 3 . Добавен ftp сървър

Потребител и паролата по подразбиране `admin`. Сървъра е взет от [esp-idf-ftpServer](https://github.com/nopnop2002/esp-idf-ftpServer), но вместо с `FAT` го ползвам с `littlefs`.

### 4 . Получване на точно време от SNTP сървър

Важно е за ftp сървъра и SSL/TLS сертификатите. Добра [статия](https://kotyara12.ru/iot/esp-time/) на Руски език. Ако разполагаме с някакъв RTC часовник, може да го сверяваме но този сървър.

### 5 . SSL/TLS сертификат

Полуаване на сертифика, чрез [ACME client](https://letsencrypt.org/docs/client-options/).

Файловете са събрани в [директори](/main/ddns_acme/) и имат [документация](/main/ddns_acme/README.md#получаване-на-ssltls-сертификат-от-lets-encrypt-чрез-acme-клиент).
