# WebSocket_RGB_Leds

За управление на RGB светодиод чрез WebSocet.  
Проекта е учебен и тестови.  
Използва [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) на кит с процесор ESP32-S3 и трицветен светодиод WS2812B, към извод GPIO48.

- за основа послужи примера [Blink Example](https://github.com/espressif/esp-idf/tree/master/examples/get-started/blink);
- добавен е примера [ESP32 Web Server (WebSocket) with Multiple Sliders: Control LEDs Brightness (PWM)](https://randomnerdtutorials.com/esp32-web-server-websocket-sliders/);
  - за съжаление примера е за [Arduino IDE](https://www.arduino.cc/). Затова първо го запуснах със симулиране на [node js](https://nodejs.org/en/download). След изтгляне и исталиране изисква еднократно запускане в 'cmd' : 'npm install'. Стартиране на сървъра в 'cmd' : 'node webserver.js'. Стартиране на клиент в Web Browser : <http://localhost/>, могат да се запуснат няколко клиента и да се види, че се променят едновременно. Стоиностите на светодиодите в %(0-100) се виждат в 'cmd' козолата;
  - директорито 'html' е с оригиналните html файлове от цитирания проект (ще се използват и в ESP-IDF). Създаден е само имитатора на сървъра 'webserver.js'.
