# WebSocket_RGB_Leds

За управление на RGB светодиод чрез WebSocket.  
Проекта е учебен и тестови.  
Използва [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) на кит с процесор ESP32-S3 и трицветен светодиод WS2812B, към извод GPIO48.

- за основа послужи примера [Blink Example](https://github.com/espressif/esp-idf/tree/master/examples/get-started/blink);
- добавен е примера [ESP32 Web Server (WebSocket) with Multiple Sliders: Control LEDs Brightness (PWM)](https://randomnerdtutorials.com/esp32-web-server-websocket-sliders/);
  - за съжаление примера е за [Arduino IDE](https://www.arduino.cc/). Затова първо го запуснах със симулиране на [node js](https://nodejs.org/en/download). След изтгляне и исталиране изисква еднократно запускане в 'cmd' : 'npm install'. Стартиране на сървъра в 'cmd' : 'node webserver.js'. Стартиране на клиент в Web Browser : <http://localhost/>, могат да се запуснат няколко клиента и да се види, че се променят едновременно. Стоиностите на светодиодите в %(0-100) се виждат в 'cmd' козолата;
  - директорито 'html' е с оригиналните html файлове от цитирания проект (ще се използват и в ESP-IDF). Създаден е само имитатора на сървъра 'webserver.js'.
- етапи по влючването на горниия [пример](https://randomnerdtutorials.com/esp32-web-server-websocket-sliders/) към кита ESP32-S3 по [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html):
  - добавяне на WiFi връзка към кита. Задайте вашите 'WiFi SSID' и 'WiFi Password'. Връзката е чрез файловете 'my_config.*', възможни са много опции на връзката чрез 'Konfig_inthenet'. В 'sdkconfig.defaults' вече е включена и поддръжката на WebSocket, за да не се налага ново преконфигуриране и пълно компилиране. Вече кита може да се пингва по IP то показано в 'I (5319) my_connect: - IPv4 address: 192.168.1.101,';
  - добавяне на WebServer, взетo е само необходимото от [HTTP Restful API Server Example](https://github.com/espressif/esp-idf/tree/master/examples/protocols/http_server/restful_server). Интерисува ни само съкратен 'rest_server.c'. Папката 'html' е добавена в ESP-IDF като "/spiffs". Вече е възможно стартиране на клиент в Web Browser : <http://192.168.1.101> (сложете вашето IP). Светодиода още само мига, не се управлява от плъзгачите;
  - добавяне на [mDNS](https://components.espressif.com/components/espressif/mdns/versions/1.8.0) рекламиране.  Вече е възможно стартиране на клиент в Web Browser по име : <http://rgb-leds/>
  - добавен WebSocket сървър от примера [Websocket echo server](https://github.com/espressif/esp-idf/tree/master/examples/protocols/http_server/ws_echo_server). Засега само успешно се свързва с клиентите и приема тяхни съобщения.
