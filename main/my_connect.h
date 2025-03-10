/*
 * my_connect.h
 *
 *  Created on: 23.06.2023 г.
 *      Author: Mitko
 */

#ifndef MAIN_MY_CONNECT_H_
#define MAIN_MY_CONNECT_H_

//Това са преправени файове от examples/common_components/protocol_examples_common/ от IDF V5.0.1

#pragma once

#include  "sdkconfig.h"
#include  "esp_err.h"
#include  "esp_netif.h"
#if CONFIG_USE_INTERNAL_ETHERNET
#include "esp_eth_driver.h"
#endif

#ifdef  __cplusplus
extern  "C" {
#endif

// Ако е само един INTERFACE (esp_netif_t) може да се ползва този флаг за проверка на връзка
// иначе се управлява от всички връзки без IPv6
extern bool fl_connect;

#if  CONFIG_CONNECT_WIFI
#define  NETIF_DESC_STA "netif_sta"
#endif

#if  CONFIG_USE_INTERNAL_ETHERNET
#define  NETIF_DESC_ETH "netif_eth"
#endif

#if  CONFIG_USE_SPI_ETHERNET
#define  NETIF_DESC_SPI "netif_spi"
#endif


/* Примерен интерфейс по подразбиране, предпочитайте ethernet, ако работите в конфигурация за примерен тест (CI) */

// Направих го първо търси "netif_eth", после "netif_spi" независимо от номера spi(x),
//ако искаме конкрето spi да търсим "netif_spi2" и накрая "netif_sta"

#if  CONFIG_USE_INTERNAL_ETHERNET
#define  INTERFACE get_netif_from_desc(NETIF_DESC_ETH)
#define  get_netif() get_netif_from_desc(NETIF_DESC_ETH)
#elif CONFIG_USE_SPI_ETHERNET
#define  INTERFACE get_netif_from_desc(NETIF_DESC_SPI)
#define  get_netif() get_netif_from_desc(NETIF_DESC_SPI)
#elif  CONFIG_CONNECT_WIFI
#define  INTERFACE get_netif_from_desc(NETIF_DESC_STA)
#define  get_netif() get_netif_from_desc(NETIF_DESC_STA)
#endif


/**
* @brief Конфигурирайте Wi-Fi или Ethernet, свържете се, изчакайте IP
*
* Тази помощна функция "всичко в едно" се използва в примери за протоколи
* намалете количеството шаблон в примера.
*
* Не е предназначен за използване в реални приложения.
* Вижте примери под examples/wifi/getting_started/ и examples/ethernet/
* за по-пълен код за инициализация на Wi-Fi или Ethernet.
*
* Прочетете раздела „Установяване на Wi-Fi или Ethernet връзка“ в
* examples/protocols/README.md за повече информация относно тази функция.
*
* @return ESP_OK при успешна връзка
*/

//Взето е най-доброто от examples/wifi/getting_started/ и examples/ethernet/

esp_err_t  my_connect( void );

/**
* Противопоставяне на my_connect, деинициализира Wi-Fi или Ethernet
*/
esp_err_t  my_disconnect( void );

/**
* @brief Конфигурирайте stdin и stdout за използване на блокиращ I/O
*
* Тази помощна функция се използва в ASIO примери. Той завършва инсталирането на
* UART драйвер и конфигуриране на VFS слой за използване на UART драйвер за конзолен I/O.
*/
esp_err_t  configure_stdin_stdout( void );

/**
* @brief Връща esp-netif указател, създаден от my_connect(), описан от
* предоставеното поле desc
*
* @param desc Текстов интерфейс на създаден мрежов интерфейс, например "sta"
* посочва WiFi станцията по подразбиране, Ethernet интерфейсът по подразбиране е "eth"
* 		Добавих "spi" за Ethernet интерфейси по spi.
*
*/
esp_netif_t  * get_netif_from_desc( const  char  * desc );

#if  CONFIG_PROVIDE_WIFI_CONSOLE_CMD
/**
* @brief Регистрирайте команди за wifi свързване
*
* Осигурете проста команда wifi_connect в esp_console.
* Тази функция може да се използва след инициализиране на esp_console.
*/
void  register_wifi_connect_commands( void );
#endif

#if  CONFIG_USE_INTERNAL_ETHERNET
/**
* @brief Вземете примерния манипулатор на драйвера за Ethernet
*
*			Да се помисли за spi интерфейсите
*
* @return esp_eth_handle_t
*/
esp_eth_handle_t  get_eth_handle( void );
#endif  // CONFIG_USE_INTERNAL_ETHERNET

#ifdef  __cplusplus
}
#endif


#endif /* MAIN_MY_CONNECT_H_ */
