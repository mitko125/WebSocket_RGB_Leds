/*
 * my_connect.c
 *
 *  Created on: 23.06.2023 г.
 *      Author: Mitko
 */

//Това са преправени файове от examples/common_components/protocol_examples_common/ от IDF V5.0.1

#include <string.h>
#include "sdkconfig.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_default.h"
#include "esp_eth.h"
#include "esp_eth_driver.h"
#if CONFIG_ETH_USE_SPI_ETHERNET
#include "driver/spi_master.h"
#endif // CONFIG_ETH_USE_SPI_ETHERNET
#include "esp_log.h"
#include "esp_netif.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/inet.h"

#include "my_connect.h"

static const char *TAG = "my_connect";

// Ако е само един INTERFACE (esp_netif_t) може да се ползва този флаг за проверка на връзка
// иначе се управлява от всички връзки без IPv6
bool fl_connect = false;

// Тези са от #include "common_private.h"
#if CONFIG_CONNECT_IPV6
#define MAX_IP6_ADDRS_PER_NETIF (5)

#if defined(CONFIG_CONNECT_IPV6_PREF_LOCAL_LINK)
#define CONNECT_PREFERRED_IPV6_TYPE ESP_IP6_ADDR_IS_LINK_LOCAL
#elif defined(CONFIG_CONNECT_IPV6_PREF_GLOBAL)
#define CONNECT_PREFERRED_IPV6_TYPE ESP_IP6_ADDR_IS_GLOBAL
#elif defined(CONFIG_CONNECT_IPV6_PREF_SITE_LOCAL)
#define CONNECT_PREFERRED_IPV6_TYPE ESP_IP6_ADDR_IS_SITE_LOCAL
#elif defined(CONFIG_CONNECT_IPV6_PREF_UNIQUE_LOCAL)
#define CONNECT_PREFERRED_IPV6_TYPE ESP_IP6_ADDR_IS_UNIQUE_LOCAL
#endif // if-elif CONFIG_CONNECT_IPV6_PREF_...

extern const char *ipv6_addr_types_to_str[6];

#endif	//CONFIG_CONNECT_IPV6

static bool is_our_netif(const char *prefix, esp_netif_t *netif);





// Тези са от eth_connect.c
static SemaphoreHandle_t s_semph_get_ip_addrs_eth = NULL;
#if CONFIG_CONNECT_IPV6
static SemaphoreHandle_t s_semph_get_ip6_addrs_eth = NULL;
#endif

#if CONFIG_USE_INTERNAL_ETHERNET
static esp_eth_handle_t s_eth_handle = NULL;
static esp_eth_netif_glue_handle_t s_eth_glue = NULL;
static esp_netif_t *eth_netif = NULL;
static esp_eth_mac_t *s_mac = NULL;
static esp_eth_phy_t *s_phy = NULL;
#endif
#if CONFIG_USE_SPI_ETHERNET
static esp_eth_handle_t eth_handle_spi[CONFIG_SPI_ETHERNETS_NUM] = { NULL };
static esp_eth_netif_glue_handle_t s_eth_glue_spi[CONFIG_SPI_ETHERNETS_NUM] = { NULL };
static esp_netif_t *eth_netif_spi[CONFIG_SPI_ETHERNETS_NUM] = { NULL };
static esp_eth_mac_t *mac_spi[CONFIG_SPI_ETHERNETS_NUM];
static esp_eth_phy_t *phy_spi[CONFIG_SPI_ETHERNETS_NUM];
#endif

/** Event handler for Ethernet events */

static void eth_disconnect(void *arg, esp_event_base_t event_base,
    int32_t event_id, void *event_data)
{
	switch (event_id) {
	case ETHERNET_EVENT_DISCONNECTED:
		fl_connect = false;
#if CONFIG_USE_INTERNAL_ETHERNET || CONFIG_USE_SPI_ETHERNET
		esp_eth_handle_t eth_handle = *(esp_eth_handle_t *)event_data;
#endif
		esp_netif_t *esp_netif = NULL;
#if CONFIG_USE_INTERNAL_ETHERNET
		if( eth_handle == s_eth_handle )
			esp_netif = eth_netif;
#endif
#if CONFIG_USE_SPI_ETHERNET
		for (int i = 0; i < CONFIG_SPI_ETHERNETS_NUM; i++) {
			if( eth_handle == eth_handle_spi[i] ){
				esp_netif = eth_netif_spi[i];
				break;
			}
		}
#endif
		if( esp_netif )
			ESP_LOGI(TAG, "Disconnect event: Interface \"%s\"", esp_netif_get_desc(esp_netif));
		else
			ESP_LOGE(TAG, "Disconnect event: Unknow Interface");
		break;
	}
}

static void eth_on_got_ip(void *arg, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{
	fl_connect = true;

	bool fl_my_netif = false;

	ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;

#if  CONFIG_USE_INTERNAL_ETHERNET
	if(is_our_netif(NETIF_DESC_ETH, event->esp_netif))
		fl_my_netif = true;
#endif
#if  CONFIG_USE_SPI_ETHERNET
	if(is_our_netif(NETIF_DESC_SPI, event->esp_netif))
		fl_my_netif = true;
#endif
	if( fl_my_netif == false ){
		ESP_LOGE(TAG, "Got IPv4 event: Unknow Interface");
		return;
	}
	ESP_LOGI(TAG, "Got IPv4 event: Interface \"%s\" address: " IPSTR, esp_netif_get_desc(event->esp_netif), IP2STR(&event->ip_info.ip));
	xSemaphoreGive(s_semph_get_ip_addrs_eth);
}

#if CONFIG_CONNECT_IPV6

static void eth_on_got_ipv6(void *arg, esp_event_base_t event_base,
                        int32_t event_id, void *event_data)
{
	bool fl_my_netif = false;
	ip_event_got_ip6_t *event = (ip_event_got_ip6_t *)event_data;

//	ESP_LOGD(TAG, "eth_on_got_ipv6 arg=%p, event_base \"%s\" event_id=%ld, event_data(ip_event_got_ip6_t netif) \"%s\"",
//			arg, event_base, event_id, esp_netif_get_desc(event->esp_netif));

#if  CONFIG_USE_INTERNAL_ETHERNET
	if(is_our_netif(NETIF_DESC_ETH, event->esp_netif))
		fl_my_netif = true;
#endif
#if  CONFIG_USE_SPI_ETHERNET
	if(is_our_netif(NETIF_DESC_SPI, event->esp_netif))
		fl_my_netif = true;
#endif
	if( fl_my_netif == false ){
		// може да засече и от WiFi ESP_LOGE(TAG, "Got IPv6 event: Unknow Interface");
		return;
	}

	esp_ip6_addr_type_t ipv6_type = esp_netif_ip6_get_addr_type(&event->ip6_info.ip);
	ESP_LOGI(TAG, "Got IPv6 event: Interface \"%s\" address: " IPV6STR ", type: %s", esp_netif_get_desc(event->esp_netif),
					 IPV62STR(event->ip6_info.ip), ipv6_addr_types_to_str[ipv6_type]);
	if (ipv6_type == CONNECT_PREFERRED_IPV6_TYPE) {
			xSemaphoreGive(s_semph_get_ip6_addrs_eth);
	}
}

static void on_eth_event_ipv6(void *esp_netif, esp_event_base_t event_base,
                         int32_t event_id, void *event_data)
{
	switch (event_id) {
	case ETHERNET_EVENT_CONNECTED:
		esp_eth_handle_t eth_handle = *(esp_eth_handle_t *)event_data;
		esp_netif_t *esp_netif = NULL;
#if CONFIG_USE_INTERNAL_ETHERNET
		if( eth_handle == s_eth_handle )
			esp_netif = eth_netif;
#endif
#if CONFIG_USE_SPI_ETHERNET
		for (int i = 0; i < CONFIG_SPI_ETHERNETS_NUM; i++) {
			if( eth_handle == eth_handle_spi[i] ){
				esp_netif = eth_netif_spi[i];
				break;
			}
		}
#endif
		if( esp_netif ){
			ESP_LOGI(TAG, "Ethernet IPv6 Link Up: Interface \"%s\"", esp_netif_get_desc(esp_netif));
			ESP_ERROR_CHECK(esp_netif_create_ip6_linklocal(esp_netif));
		}else
			ESP_LOGE(TAG, "Ethernet IPv6 Link Up: Unknow Interface");
		break;
	}
}

#endif // CONFIG_CONNECT_IPV6

#if CONFIG_USE_SPI_ETHERNET

#define INIT_SPI_ETH_MODULE_CONFIG(eth_module_config, num)                                      \
    do {                                                                                        \
        eth_module_config[num].spi_cs_gpio = CONFIG_ETH_SPI_CS ##num## _GPIO;           \
        eth_module_config[num].int_gpio = CONFIG_ETH_SPI_INT ##num## _GPIO;             \
        eth_module_config[num].phy_reset_gpio = CONFIG_ETH_SPI_PHY_RST ##num## _GPIO;   \
        eth_module_config[num].phy_addr = CONFIG_ETH_SPI_PHY_ADDR ##num;                \
    } while(0)

typedef struct {
    uint8_t spi_cs_gpio;
    uint8_t int_gpio;
    int8_t phy_reset_gpio;
    uint8_t phy_addr;
}spi_eth_module_config_t;
#endif

static void eth_start(void)
{
#if CONFIG_USE_INTERNAL_ETHERNET
    esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_ETH();
    // Warning: the interface desc is used in tests to capture actual connection details (IP, gw, mask)
    esp_netif_config.if_desc = NETIF_DESC_ETH;
    esp_netif_config.route_prio = 64;

    esp_netif_config_t netif_config = {
        .base = &esp_netif_config,
        .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH
    };
    eth_netif = esp_netif_new(&netif_config);
    assert(eth_netif);

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
//    mac_config.rx_task_stack_size = CONFIG_ETHERNET_EMAC_TASK_STACK_SIZE;
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = CONFIG_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = CONFIG_ETH_PHY_RST_GPIO;

#if CONFIG_ETH_PHY_ENABLE_GPIO > (-1)
   	gpio_config_t bk_gpio_config = {
   			.mode = GPIO_MODE_OUTPUT,
				.pin_bit_mask = 1ULL << CONFIG_ETH_PHY_ENABLE_GPIO
    };
   	ESP_ERROR_CHECK(gpio_config(&bk_gpio_config));
    ESP_ERROR_CHECK(gpio_set_level(CONFIG_ETH_PHY_ENABLE_GPIO, 1));
    vTaskDelay(pdMS_TO_TICKS(10));
#endif

    eth_esp32_emac_config_t esp32_emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    esp32_emac_config.smi_mdc_gpio_num = CONFIG_ETH_MDC_GPIO;
    esp32_emac_config.smi_mdio_gpio_num = CONFIG_ETH_MDIO_GPIO;
    s_mac = esp_eth_mac_new_esp32(&esp32_emac_config, &mac_config);
#if CONFIG_ETH_PHY_IP101
    s_phy = esp_eth_phy_new_ip101(&phy_config);
#elif CONFIG_ETH_PHY_RTL8201
    s_phy = esp_eth_phy_new_rtl8201(&phy_config);
#elif CONFIG_ETH_PHY_LAN87XX
    s_phy = esp_eth_phy_new_lan87xx(&phy_config);
#elif CONFIG_ETH_PHY_DP83848
    s_phy = esp_eth_phy_new_dp83848(&phy_config);
#elif CONFIG_ETH_PHY_KSZ80XX
    s_phy = esp_eth_phy_new_ksz80xx(&phy_config);
#endif

    // Install Ethernet driver
		esp_eth_config_t config = ETH_DEFAULT_CONFIG(s_mac, s_phy);
		ESP_ERROR_CHECK(esp_eth_driver_install(&config, &s_eth_handle));
#ifdef CONFIG_STATIC_IP
    esp_netif_dhcpc_stop(eth_netif);
    esp_netif_ip_info_t IP_settings_sta;
    IP_settings_sta.ip.addr=ipaddr_addr( CONFIG_IP_ADDRESS );
    IP_settings_sta.netmask.addr=ipaddr_addr( CONFIG_SUBNET_MASK );
    IP_settings_sta.gw.addr=ipaddr_addr( CONFIG_DEFAUT_GATEWAY );
    esp_netif_set_ip_info(eth_netif, &IP_settings_sta);
#endif
		/* attach Ethernet driver to TCP/IP stack */
		s_eth_glue = esp_eth_new_netif_glue(s_eth_handle);
		ESP_ERROR_CHECK(esp_netif_attach(eth_netif, s_eth_glue));
#endif	//CONFIG_USE_INTERNAL_ETHERNET

#if CONFIG_USE_SPI_ETHERNET
	// Create instance(s) of esp-netif for SPI Ethernet(s)
	esp_netif_inherent_config_t esp_netif_config_spi = ESP_NETIF_INHERENT_DEFAULT_ETH();
	esp_netif_config_t cfg_spi = {
		 .base = &esp_netif_config_spi,
		 .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH
	};
	char if_key_str[10];
	char if_desc_str[10];
	char num_str[3];
//	asprintf(&desc, "%s: %s", TAG, esp_netif_config_spi.if_desc);
	for (int i = 0; i < CONFIG_SPI_ETHERNETS_NUM; i++) {
		 itoa(i, num_str, 10);
		 strcat(strcpy(if_key_str, "ETH_SPI_"), num_str);
		 strcat(strcpy(if_desc_str, NETIF_DESC_SPI), num_str);
		 esp_netif_config_spi.if_key = if_key_str;
		 esp_netif_config_spi.if_desc = if_desc_str;
		 esp_netif_config_spi.route_prio = 30 - i;
		 eth_netif_spi[i] = esp_netif_new(&cfg_spi);
	}

	// Init MAC and PHY configs to default
	eth_mac_config_t mac_config_spi = ETH_MAC_DEFAULT_CONFIG();
	eth_phy_config_t phy_config_spi = ETH_PHY_DEFAULT_CONFIG();

	// Install GPIO ISR handler to be able to service SPI Eth modlues interrupts
    // Ако някой е извикал gpio_install_isr_service преди това не си пречат без ESP_ERROR_CHECK(..
	// !!! ако никой не го е викал SPI ETHERNET от 1ms ping става ~1000ms !!!
	gpio_install_isr_service(0);

	// Init SPI bus
	spi_bus_config_t buscfg = {
		 .miso_io_num = CONFIG_ETH_SPI_MISO_GPIO,
		 .mosi_io_num = CONFIG_ETH_SPI_MOSI_GPIO,
		 .sclk_io_num = CONFIG_ETH_SPI_SCLK_GPIO,
		 .quadwp_io_num = -1,
		 .quadhd_io_num = -1,
	};
	ESP_ERROR_CHECK(spi_bus_initialize(CONFIG_ETH_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

	// Init specific SPI Ethernet module configuration from Kconfig (CS GPIO, Interrupt GPIO, etc.)
	spi_eth_module_config_t spi_eth_module_config[CONFIG_SPI_ETHERNETS_NUM];
	INIT_SPI_ETH_MODULE_CONFIG(spi_eth_module_config, 0);
	#if CONFIG_SPI_ETHERNETS_NUM > 1
	INIT_SPI_ETH_MODULE_CONFIG(spi_eth_module_config, 1);
	#endif

	// Configure SPI interface and Ethernet driver for specific SPI module
	spi_device_interface_config_t spi_devcfg = {
		 .mode = 0,
		 .clock_speed_hz = CONFIG_ETH_SPI_CLOCK_MHZ * 1000 * 1000,
		 .queue_size = 20
	};
	for (int i = 0; i < CONFIG_SPI_ETHERNETS_NUM; i++) {
		 // Set SPI module Chip Select GPIO
		 spi_devcfg.spics_io_num = spi_eth_module_config[i].spi_cs_gpio;
		 // Set remaining GPIO numbers and configuration used by the SPI module
		 phy_config_spi.phy_addr = spi_eth_module_config[i].phy_addr;
		 phy_config_spi.reset_gpio_num = spi_eth_module_config[i].phy_reset_gpio;
	#if CONFIG_USE_KSZ8851SNL
		 eth_ksz8851snl_config_t ksz8851snl_config = ETH_KSZ8851SNL_DEFAULT_CONFIG(CONFIG_ETH_SPI_HOST, &spi_devcfg);
		 ksz8851snl_config.int_gpio_num = spi_eth_module_config[i].int_gpio;
		 mac_spi[i] = esp_eth_mac_new_ksz8851snl(&ksz8851snl_config, &mac_config_spi);
		 phy_spi[i] = esp_eth_phy_new_ksz8851snl(&phy_config_spi);
	#elif CONFIG_USE_DM9051
		 eth_dm9051_config_t dm9051_config = ETH_DM9051_DEFAULT_CONFIG(CONFIG_ETH_SPI_HOST, &spi_devcfg);
		 dm9051_config.int_gpio_num = spi_eth_module_config[i].int_gpio;
		 mac_spi[i] = esp_eth_mac_new_dm9051(&dm9051_config, &mac_config_spi);
		 phy_spi[i] = esp_eth_phy_new_dm9051(&phy_config_spi);
	#elif CONFIG_USE_W5500
		 eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(CONFIG_ETH_SPI_HOST, &spi_devcfg);
		 w5500_config.int_gpio_num = spi_eth_module_config[i].int_gpio;
		 mac_spi[i] = esp_eth_mac_new_w5500(&w5500_config, &mac_config_spi);
		 phy_spi[i] = esp_eth_phy_new_w5500(&phy_config_spi);
	#endif
		 esp_eth_config_t eth_config_spi = ETH_DEFAULT_CONFIG(mac_spi[i], phy_spi[i]);
		 ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config_spi, &eth_handle_spi[i]));

		 /* The SPI Ethernet module might not have a burned factory MAC address, we cat to set it manually.
		02:00:00 is a Locally Administered OUI range so should not be used except when testing on a LAN under your control.
		 */
		 ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle_spi[i], ETH_CMD_S_MAC_ADDR, (uint8_t[]) {
				 0x02, 0x00, 0x00, 0x12, 0x34, 0x56 + i
		 }));
#ifdef CONFIG_STATIC_IP
    esp_netif_dhcpc_stop(eth_netif_spi[i]);
    esp_netif_ip_info_t IP_settings_sta_spi;
    IP_settings_sta_spi.ip.addr=ipaddr_addr( CONFIG_IP_ADDRESS );
    IP_settings_sta_spi.netmask.addr=ipaddr_addr( CONFIG_SUBNET_MASK );
    IP_settings_sta_spi.gw.addr=ipaddr_addr( CONFIG_DEFAUT_GATEWAY );
    esp_netif_set_ip_info(eth_netif_spi[i], &IP_settings_sta_spi);
#endif
		// attach Ethernet driver to TCP/IP stack
		s_eth_glue_spi[i] = esp_eth_new_netif_glue(eth_handle_spi[i]);
		ESP_ERROR_CHECK(esp_netif_attach(eth_netif_spi[i], s_eth_glue_spi[i]));
	}
#endif	//CONFIG_USE_SPI_ETHERNET

    // Register user defined event handers
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_on_got_ip, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &eth_disconnect, NULL));
#ifdef CONFIG_CONNECT_IPV6
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_CONNECTED, &on_eth_event_ipv6, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &eth_on_got_ipv6, NULL));
#endif

    /* start Ethernet driver state machine */
#if CONFIG_USE_INTERNAL_ETHERNET
    ESP_ERROR_CHECK(esp_eth_start(s_eth_handle));
#endif // CONFIG_USE_INTERNAL_ETHERNET
#if CONFIG_USE_SPI_ETHERNET
    for (int i = 0; i < CONFIG_SPI_ETHERNETS_NUM; i++) {
        ESP_ERROR_CHECK(esp_eth_start(eth_handle_spi[i]));
    }
#endif // CONFIG_USE_SPI_ETHERNET

}

static void eth_stop(void)
{
	ESP_ERROR_CHECK(esp_event_handler_unregister(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &eth_disconnect));
  ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_on_got_ip));
#if CONFIG_CONNECT_IPV6
  ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_GOT_IP6, &eth_on_got_ipv6));
  ESP_ERROR_CHECK(esp_event_handler_unregister(ETH_EVENT, ETHERNET_EVENT_CONNECTED, &on_eth_event_ipv6));
#endif

#if CONFIG_USE_INTERNAL_ETHERNET
	esp_netif_t *netif = get_netif_from_desc(NETIF_DESC_ETH);
	ESP_ERROR_CHECK(esp_eth_stop(s_eth_handle));
	ESP_ERROR_CHECK(esp_eth_del_netif_glue(s_eth_glue));
	ESP_ERROR_CHECK(esp_eth_driver_uninstall(s_eth_handle));
	s_eth_handle = NULL;
	ESP_ERROR_CHECK(s_phy->del(s_phy));
	ESP_ERROR_CHECK(s_mac->del(s_mac));
	esp_netif_destroy(netif);
#endif	//CONFIG_USE_INTERNAL_ETHERNET

#if CONFIG_USE_SPI_ETHERNET
	for (int i = 0; i < CONFIG_SPI_ETHERNETS_NUM; i++) {
		esp_netif_t *netif = get_netif_from_desc(NETIF_DESC_SPI);
		ESP_ERROR_CHECK(esp_eth_stop(eth_handle_spi[i]));
		ESP_ERROR_CHECK(esp_eth_del_netif_glue(s_eth_glue_spi[i]));
		ESP_ERROR_CHECK(esp_eth_driver_uninstall(eth_handle_spi[i]));
		eth_handle_spi[i] = NULL;
		ESP_ERROR_CHECK(phy_spi[i]->del(phy_spi[i]));
		ESP_ERROR_CHECK(mac_spi[i]->del(mac_spi[i]));
		esp_netif_destroy(netif);
	}
#endif	//CONFIG_USE_SPI_ETHERNET
}

#if CONFIG_USE_INTERNAL_ETHERNET
esp_eth_handle_t get_eth_handle(void)
{
    return s_eth_handle;
}
#endif	//CONFIG_USE_INTERNAL_ETHERNET

/* tear down connection, release resources */
void ethernet_shutdown(void)
{
    if (s_semph_get_ip_addrs_eth == NULL) {
        return;
    }
    vSemaphoreDelete(s_semph_get_ip_addrs_eth);
    s_semph_get_ip_addrs_eth = NULL;
#if CONFIG_CONNECT_IPV6
    vSemaphoreDelete(s_semph_get_ip6_addrs_eth);
    s_semph_get_ip6_addrs_eth = NULL;
#endif
    eth_stop();
}

esp_err_t ethernet_connect(void)
{
    s_semph_get_ip_addrs_eth = xSemaphoreCreateBinary();
    if (s_semph_get_ip_addrs_eth == NULL) {
        return ESP_ERR_NO_MEM;
    }
#if CONFIG_CONNECT_IPV6
    s_semph_get_ip6_addrs_eth = xSemaphoreCreateBinary();
    if (s_semph_get_ip6_addrs_eth == NULL) {
        vSemaphoreDelete(s_semph_get_ip_addrs_eth);
        return ESP_ERR_NO_MEM;
    }
#endif	//CONFIG_CONNECT_IPV6
    eth_start();
    ESP_LOGI(TAG, "Waiting for IP(s).");
#if CONFIG_LAUNCH_WITH_ESTABLISHED_CONNECTION
    xSemaphoreTake(s_semph_get_ip_addrs_eth, portMAX_DELAY);
#if CONFIG_CONNECT_IPV6
    xSemaphoreTake(s_semph_get_ip6_addrs_eth, portMAX_DELAY);
#endif	//CONFIG_CONNECT_IPV6
#endif	//CONFIG_LAUNCH_WITH_ESTABLISHED_CONNECTION
    return ESP_OK;
}





// Тези са от wifi_connect.c
#if CONFIG_CONNECT_WIFI

static esp_netif_t *s_sta_netif = NULL;
static SemaphoreHandle_t s_semph_get_ip_addrs_sta = NULL;
#if CONFIG_CONNECT_IPV6
static SemaphoreHandle_t s_semph_get_ip6_addrs_sta = NULL;
#endif	//CONFIG_CONNECT_IPV6

#if CONFIG_WIFI_SCAN_METHOD_FAST
#define WIFI_SCAN_METHOD WIFI_FAST_SCAN
#elif CONFIG_WIFI_SCAN_METHOD_ALL_CHANNEL
#define WIFI_SCAN_METHOD WIFI_ALL_CHANNEL_SCAN
#endif

#if CONFIG_WIFI_CONNECT_AP_BY_SIGNAL
#define WIFI_CONNECT_AP_SORT_METHOD WIFI_CONNECT_AP_BY_SIGNAL
#elif CONFIG_WIFI_CONNECT_AP_BY_SECURITY
#define WIFI_CONNECT_AP_SORT_METHOD WIFI_CONNECT_AP_BY_SECURITY
#endif

#if CONFIG_WIFI_AUTH_OPEN
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_OPEN
#elif CONFIG_WIFI_AUTH_WEP
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WEP
#elif CONFIG_WIFI_AUTH_WPA_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_PSK
#elif CONFIG_WIFI_AUTH_WPA2_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_PSK
#elif CONFIG_WIFI_AUTH_WPA_WPA2_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_WPA2_PSK
#elif CONFIG_WIFI_AUTH_WPA2_ENTERPRISE
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_ENTERPRISE
#elif CONFIG_WIFI_AUTH_WPA3_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA3_PSK
#elif CONFIG_WIFI_AUTH_WPA2_WPA3_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_WPA3_PSK
#elif CONFIG_WIFI_AUTH_WAPI_PSK
#define WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WAPI_PSK
#endif

//static int s_retry_num = 0;

static void handler_on_wifi_disconnect(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{

	fl_connect = false;

	/*
    s_retry_num++;
    if (s_retry_num > CONFIG_WIFI_CONN_MAX_RETRY) {
        ESP_LOGI(TAG, "WiFi Connect failed %d times, stop reconnect.", s_retry_num);
        // let wifi_sta_do_connect() return
        if (s_semph_get_ip_addrs_sta) {
            xSemaphoreGive(s_semph_get_ip_addrs_sta);
        }
#if CONFIG_CONNECT_IPV6
        if (s_semph_get_ip6_addrs_sta) {
            xSemaphoreGive(s_semph_get_ip6_addrs_sta);
        }
#endif
        return;
    }
*/
    ESP_LOGI(TAG, "Wi-Fi disconnected, trying to reconnect...");
    esp_err_t err = esp_wifi_connect();
    if (err == ESP_ERR_WIFI_NOT_STARTED) {
        return;
    }
    ESP_ERROR_CHECK(err);
}

static void handler_on_wifi_connect(void *esp_netif, esp_event_base_t event_base,
                            int32_t event_id, void *event_data)
{
#if CONFIG_CONNECT_IPV6
    esp_netif_create_ip6_linklocal(esp_netif);
#endif // CONFIG_CONNECT_IPV6
}

static void handler_on_sta_got_ip(void *arg, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{

	fl_connect = true;

//    s_retry_num = 0;
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    if (!is_our_netif(NETIF_DESC_STA, event->esp_netif)) {
        return;
    }
    ESP_LOGI(TAG, "Got IPv4 event: Interface \"%s\" address: " IPSTR, esp_netif_get_desc(event->esp_netif), IP2STR(&event->ip_info.ip));
    if (s_semph_get_ip_addrs_sta) {
        xSemaphoreGive(s_semph_get_ip_addrs_sta);
    } else {
        ESP_LOGI(TAG, "- IPv4 address: " IPSTR ",", IP2STR(&event->ip_info.ip));
    }
}

#if CONFIG_CONNECT_IPV6
static void handler_on_sta_got_ipv6(void *arg, esp_event_base_t event_base,
                        int32_t event_id, void *event_data)
{
    ip_event_got_ip6_t *event = (ip_event_got_ip6_t *)event_data;
    if (!is_our_netif(NETIF_DESC_STA, event->esp_netif)) {
        return;
    }
    esp_ip6_addr_type_t ipv6_type = esp_netif_ip6_get_addr_type(&event->ip6_info.ip);
    ESP_LOGI(TAG, "Got IPv6 event: Interface \"%s\" address: " IPV6STR ", type: %s", esp_netif_get_desc(event->esp_netif),
             IPV62STR(event->ip6_info.ip), ipv6_addr_types_to_str[ipv6_type]);

    if (ipv6_type == CONNECT_PREFERRED_IPV6_TYPE) {
        if (s_semph_get_ip6_addrs_sta) {
            xSemaphoreGive(s_semph_get_ip6_addrs_sta);
        } else {
            ESP_LOGI(TAG, "- IPv6 address: " IPV6STR ", type: %s", IPV62STR(event->ip6_info.ip), ipv6_addr_types_to_str[ipv6_type]);
        }
    }
}
#endif // CONFIG_CONNECT_IPV6

static void wifi_start(void)
{

	vTaskDelay(pdMS_TO_TICKS(200));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
    // Warning: the interface desc is used in tests to capture actual connection details (IP, gw, mask)
    esp_netif_config.if_desc = NETIF_DESC_STA;
    esp_netif_config.route_prio = 128;
    s_sta_netif = esp_netif_create_wifi(WIFI_IF_STA, &esp_netif_config);
    esp_wifi_set_default_wifi_sta_handlers();

#ifdef CONFIG_STATIC_IP
    esp_netif_dhcpc_stop(s_sta_netif);
    esp_netif_ip_info_t IP_settings_sta;
    IP_settings_sta.ip.addr=ipaddr_addr( CONFIG_IP_ADDRESS );
    IP_settings_sta.netmask.addr=ipaddr_addr( CONFIG_SUBNET_MASK );
    IP_settings_sta.gw.addr=ipaddr_addr( CONFIG_DEFAUT_GATEWAY );
    esp_netif_set_ip_info(s_sta_netif, &IP_settings_sta);
#endif

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static void wifi_stop(void)
{
    esp_err_t err = esp_wifi_stop();
    if (err == ESP_ERR_WIFI_NOT_INIT) {
        return;
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_wifi_deinit());
    ESP_ERROR_CHECK(esp_wifi_clear_default_wifi_driver_and_handlers(s_sta_netif));
    esp_netif_destroy(s_sta_netif);
    s_sta_netif = NULL;
}

static esp_err_t wifi_sta_do_connect(wifi_config_t wifi_config, bool wait)
{
    if (wait) {
        s_semph_get_ip_addrs_sta = xSemaphoreCreateBinary();
        if (s_semph_get_ip_addrs_sta == NULL) {
            return ESP_ERR_NO_MEM;
        }
#if CONFIG_CONNECT_IPV6
        s_semph_get_ip6_addrs_sta = xSemaphoreCreateBinary();
        if (s_semph_get_ip6_addrs_sta == NULL) {
            vSemaphoreDelete(s_semph_get_ip_addrs_sta);
            return ESP_ERR_NO_MEM;
        }
#endif
    }
//    s_retry_num = 0;
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &handler_on_wifi_disconnect, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &handler_on_sta_got_ip, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &handler_on_wifi_connect, s_sta_netif));
#if CONFIG_CONNECT_IPV6
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &handler_on_sta_got_ipv6, NULL));
#endif

    ESP_LOGI(TAG, "Connecting to %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    esp_err_t ret = esp_wifi_connect();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "WiFi connect failed! ret:%x", ret);
        return ret;
    }
    if (wait) {
        ESP_LOGI(TAG, "Waiting for IP(s)");
        xSemaphoreTake(s_semph_get_ip_addrs_sta, portMAX_DELAY);
#if CONFIG_CONNECT_IPV6
        xSemaphoreTake(s_semph_get_ip6_addrs_sta, portMAX_DELAY);
#endif
/*
        if (s_retry_num > CONFIG_WIFI_CONN_MAX_RETRY) {
            return ESP_FAIL;
        }
        */
    }
    return ESP_OK;
}

static esp_err_t wifi_sta_do_disconnect(void)
{
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &handler_on_wifi_disconnect));
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &handler_on_sta_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &handler_on_wifi_connect));
#if CONFIG_CONNECT_IPV6
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_GOT_IP6, &handler_on_sta_got_ipv6));
#endif
    if (s_semph_get_ip_addrs_sta) {
        vSemaphoreDelete(s_semph_get_ip_addrs_sta);
    }
#if CONFIG_CONNECT_IPV6
    if (s_semph_get_ip6_addrs_sta) {
        vSemaphoreDelete(s_semph_get_ip6_addrs_sta);
    }
#endif
    return esp_wifi_disconnect();
}

static void wifi_shutdown(void)
{
    wifi_sta_do_disconnect();
    wifi_stop();
}

static esp_err_t wifi_connect(void)
{
    ESP_LOGI(TAG, "Start connect.");
    wifi_start();
    wifi_config_t wifi_config = {
        .sta = {
#if !CONFIG_WIFI_SSID_PWD_FROM_STDIN
            .ssid = CONFIG_WIFI_SSID,
            .password = CONFIG_WIFI_PASSWORD,
#endif
            .scan_method = WIFI_SCAN_METHOD,
            .sort_method = WIFI_CONNECT_AP_SORT_METHOD,
            .threshold.rssi = CONFIG_WIFI_SCAN_RSSI_THRESHOLD,
            .threshold.authmode = WIFI_SCAN_AUTH_MODE_THRESHOLD,
        },
    };
#if CONFIG_WIFI_SSID_PWD_FROM_STDIN
    configure_stdin_stdout();
    char buf[sizeof(wifi_config.sta.ssid)+sizeof(wifi_config.sta.password)+2] = {0};
    ESP_LOGI(TAG, "Please input ssid password:");
    fgets(buf, sizeof(buf), stdin);
    int len = strlen(buf);
    buf[len-1] = '\0'; /* removes '\n' */
    memset(wifi_config.sta.ssid, 0, sizeof(wifi_config.sta.ssid));

    char *rest = NULL;
    char *temp = strtok_r(buf, " ", &rest);
    strncpy((char*)wifi_config.sta.ssid, temp, sizeof(wifi_config.sta.ssid));
    memset(wifi_config.sta.password, 0, sizeof(wifi_config.sta.password));
    temp = strtok_r(NULL, " ", &rest);
    if (temp) {
        strncpy((char*)wifi_config.sta.password, temp, sizeof(wifi_config.sta.password));
    } else {
        wifi_config.sta.threshold.authmode = WIFI_AUTH_OPEN;
    }
#endif
#if CONFIG_LAUNCH_WITH_ESTABLISHED_CONNECTION
    return wifi_sta_do_connect(wifi_config, true);
#else
    return wifi_sta_do_connect(wifi_config, false);//true);
#endif
}

#endif /* CONFIG_CONNECT_WIFI */




// Тези са от connect.c
#if CONFIG_CONNECT_IPV6
/* types of ipv6 addresses to be displayed on ipv6 events */
const char *ipv6_addr_types_to_str[6] = {
    "ESP_IP6_ADDR_IS_UNKNOWN",
    "ESP_IP6_ADDR_IS_GLOBAL",
    "ESP_IP6_ADDR_IS_LINK_LOCAL",
    "ESP_IP6_ADDR_IS_SITE_LOCAL",
    "ESP_IP6_ADDR_IS_UNIQUE_LOCAL",
    "ESP_IP6_ADDR_IS_IPV4_MAPPED_IPV6"
};
#endif

/**
 * @brief Checks the netif description if it contains specified prefix.
 * All netifs created withing common connect component are prefixed with the module TAG,
 * so it returns true if the specified netif is owned by this module
 */
bool is_our_netif(const char *prefix, esp_netif_t *netif)
{
    return strncmp(prefix, esp_netif_get_desc(netif), strlen(prefix) - 1) == 0;
}

esp_netif_t *get_netif_from_desc(const char *desc)
{
    esp_netif_t *netif = NULL;
    while ((netif = esp_netif_next_unsafe(netif)) != NULL) {
        if (strncmp(esp_netif_get_desc(netif), desc, strlen(desc)) == 0) {
            return netif;
        }
    }
    return netif;
}

void print_all_netif_ips(const char *prefix)
{
    // iterate over active interfaces, and print out IPs of "our" netifs
    esp_netif_t *netif = NULL;
    esp_netif_ip_info_t ip;
    for (int i = 0; i < esp_netif_get_nr_of_ifs(); ++i) {
        netif = esp_netif_next_unsafe(netif);
        if (is_our_netif(prefix, netif)) {
            ESP_LOGI(TAG, "Connected to %s", esp_netif_get_desc(netif));
            ESP_ERROR_CHECK(esp_netif_get_ip_info(netif, &ip));

            ESP_LOGI(TAG, "- IPv4 address: " IPSTR ",", IP2STR(&ip.ip));
#if CONFIG_CONNECT_IPV6
            esp_ip6_addr_t ip6[MAX_IP6_ADDRS_PER_NETIF];
            int ip6_addrs = esp_netif_get_all_ip6(netif, ip6);
            for (int j = 0; j < ip6_addrs; ++j) {
                esp_ip6_addr_type_t ipv6_type = esp_netif_ip6_get_addr_type(&(ip6[j]));
                ESP_LOGI(TAG, "- IPv6 address: " IPV6STR ", type: %s", IPV62STR(ip6[j]), ipv6_addr_types_to_str[ipv6_type]);
            }
#endif
        }
    }
}

esp_err_t my_connect(void)
{
	esp_err_t ret = ESP_FAIL;

#if CONFIG_CONNECT_ETHERNET
    if (ethernet_connect() != ESP_OK) {
        return ESP_FAIL;
    }
    ret = ESP_OK;
    ESP_ERROR_CHECK(esp_register_shutdown_handler(&ethernet_shutdown));
#endif
#if CONFIG_CONNECT_WIFI
    if (wifi_connect() != ESP_OK) {
        return ESP_FAIL;
    }
    ret = ESP_OK;
    ESP_ERROR_CHECK(esp_register_shutdown_handler(&wifi_shutdown));
#endif

#if CONFIG_USE_INTERNAL_ETHERNET
    print_all_netif_ips(NETIF_DESC_ETH);
#endif

#if CONFIG_USE_SPI_ETHERNET
    print_all_netif_ips(NETIF_DESC_SPI);
#endif

#if CONFIG_CONNECT_WIFI
    print_all_netif_ips(NETIF_DESC_STA);
#endif

    return ret;
}

esp_err_t my_disconnect(void)
{
#if CONFIG_CONNECT_ETHERNET
    ethernet_shutdown();
    ESP_ERROR_CHECK(esp_unregister_shutdown_handler(&ethernet_shutdown));
#endif
#if CONFIG_CONNECT_WIFI
    wifi_shutdown();
    ESP_ERROR_CHECK(esp_unregister_shutdown_handler(&wifi_shutdown));
#endif
    return ESP_OK;
}
