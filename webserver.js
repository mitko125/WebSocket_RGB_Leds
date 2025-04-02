"use strict";
const app = require('express')();
const http = require('http');
const fs = require('fs'); //require filesystem module

const host = 'localhost';
const port = 80;
const server = http.createServer(app);
server.listen(port, host, () => {
    console.log(`http server is running on http://${host}:${port}`);
});

// не се използват няма POST, GET value всичко е през WebSocket
const bodyParser = require('body-parser');
app.use(bodyParser.json()) // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded

app.get('/*', (req, res) => {
    let need_file = req.url;
    if (need_file == "/")
        need_file = "/index.html"
    need_file = __dirname + '/storage_dirs/html' + need_file;
    console.log(`get('/*' req.url = ${req.url}`);
    fs.readFile(need_file, function (err, data) {
        if (err) {
            console.error(`Error read file = ${req.url}`);
            res.writeHead(404, { 'Content-Type': 'text/html' }); //display 404 on error
            return res.end("404 Not Found");
        }
        if (need_file.match(/\.html/)) {
            res.setHeader("Content-Type", "text/html");
        } else if (need_file.match(/\.js/)) {
            res.setHeader("Content-Type", "application/javascript");
        } else if (need_file.match(/\.css/)) {
            res.setHeader("Content-Type", "text/css");
        } else if (need_file.match(/\.png/)) {
            res.setHeader("Content-Type", "image/png");
        } else if (need_file.match(/\.ico/)) {
            res.setHeader("Content-Type", "image/x-icon");
        } else if (need_file.match(/\.svg/)) {
            res.setHeader("Content-Type", "text/xml");
        } else if (need_file.match(/\.jpeg/)) {
            res.setHeader("Content-Type", "image/jpeg");
        } else if (need_file.match(/\.pdf/)) {
            res.setHeader("Content-Type", "application/pdf");
        } else {
            res.setHeader("Content-Type", "text/plain");
        }
        res.write(data); //write data from index.html
        return res.end();
    });
})

/******************************
 * 
 * WebSocket (ws) сървър
 * 
 ******************************/
const WebSocket = require('ws');
const wss = new WebSocket.Server({ server });
let id = 0; // да знаем кой е клиента
wss.on('connection', function connection(ws) {
    console.log('ws: New client  (fd=%d) connected!', ws.id = id++);

    ws.on('message', function message(data) {
        try {
            let rec_json = JSON.parse(data);
            console.log(`ws: from client (fd=${ws.id}) received JSON : ${rec_json}`);
        } catch (err) {
            // имитация на ESP32_Multiple_Sliders_Web_Server.ino от 
            // https://randomnerdtutorials.com/esp32-web-server-websocket-sliders/
            let message = data;
            // console.log(`ws: from client (fd=${ws.id}) received string : ${message}`);
            if (message.indexOf("1s") >= 0) {
                sliderValue1 = message.slice(2);
                // dutyCycle1 = map(sliderValue1.toInt(), 0, 100, 0, 255);
                // Serial.println(dutyCycle1);
                // Serial.print(getSliderValues());
                notifyClients(getSliderValues());
            }
            if (message.indexOf("2s") >= 0) {
                sliderValue2 = message.slice(2);
                // dutyCycle2 = map(sliderValue2.toInt(), 0, 100, 0, 255);
                // Serial.println(dutyCycle2);
                // Serial.print(getSliderValues());
                notifyClients(getSliderValues());
              }    
              if (message.indexOf("3s") >= 0) {
                sliderValue3 = message.slice(2);
                // dutyCycle3 = map(sliderValue3.toInt(), 0, 100, 0, 255);
                // Serial.println(dutyCycle3);
                // Serial.print(getSliderValues());
                notifyClients(getSliderValues());
              }
              if (message == "getValues") {
                notifyClients(getSliderValues());
              }
        }
    });

    ws.on('close', () => console.log('ws: Client (fd=%d) has disconnected!', ws.id));
    ws.onerror = function () {
        console.log('ws websocket error')
    }
});

/*************
 * имитация на ESP32_Multiple_Sliders_Web_Server.ino от 
 * https://randomnerdtutorials.com/esp32-web-server-websocket-sliders/
 *************/
let sliderValue1 = "0";
let sliderValue2 = "0";
let sliderValue3 = "0";

let sliderValues = {};

//Get Slider Values
function getSliderValues() {
    sliderValues["sliderValue1"] = String(sliderValue1);
    sliderValues["sliderValue2"] = String(sliderValue2);
    sliderValues["sliderValue3"] = String(sliderValue3);

    let jsonString = JSON.stringify(sliderValues);
    return jsonString;
}

function notifyClients(sliderValues) {
    // ws.textAll(sliderValues);
    wss.clients.forEach(ws => {
        console.log(`ws: to client (fd=${ws.id}) send : ${sliderValues}`)
        ws.send(sliderValues);
    })
}