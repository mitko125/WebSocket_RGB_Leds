/*
 * Networking class
 *
 * Copyright (c) 2023, 2024 by Danny Backx
 *   but loosely based on Espressif connection example.
 *
 * This module can connect to a number of SSIDs (whichever it finds, obviously).
 * It's possible to provide it with a predefined IP address for your host.
 * Should reconnect after a failure.
 *
 * License (GNU Lesser General Public License) :
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 3 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <App.h>
#include <Network.h>

// Store info about networks we can use
struct connect_wifi_t {
  const char *ssid, *pass, *bssid;
  const char *eap_identity, *eap_password;	// FIX ME currently unsupported
  bool discard;
  int counter;
};

static connect_wifi_t _connect_wifi[] = {
#if 0
 { "debug", "no", 0, 0, 0, false, 0 },
#endif
#ifdef CONFIG_CONNECT_WIFI_SSID
 { CONFIG_CONNECT_WIFI_SSID, CONFIG_CONNECT_WIFI_PASSWORD, 0, 0, 0, false, 0 },
#endif
#ifdef CONFIG_CONNECT_WIFI_2_SSID
 { CONFIG_CONNECT_WIFI_2_SSID, CONFIG_CONNECT_WIFI_2_PASSWORD, 0, 0, 0, false, 0 },
#endif
#ifdef CONFIG_CONNECT_WIFI_3_SSID
 { CONFIG_CONNECT_WIFI_3_SSID, CONFIG_CONNECT_WIFI_3_PASSWORD, 0, 0, 0, false, 0 },
#endif
#ifdef CONFIG_CONNECT_WIFI_4_SSID
 { CONFIG_CONNECT_WIFI_4_SSID, CONFIG_CONNECT_WIFI_4_PASSWORD, 0, 0, 0, false, 0 },
#endif
};

static Network *network = 0;	// Easy access for static member functions

Network::Network() {
  network = this;

  /*
   * Dual mode : we can pick up hardwired configuration (_connect_wifi) but we can
   * also be configured by calls. In the latter case, connect_wifi won't point to
   * the hardwired config any more, and will be dynamically allocated.
   */
  connect_wifi = _connect_wifi;
  n_connect_wifi = sizeof(_connect_wifi) / sizeof(struct connect_wifi_t);
  max_connect_wifi = 0;

  wifi_ix = -1;
  s_retry_num = 0;
  sta_netif = NULL;

  preset_ip = 0;
  preset_dns = 0;

  ESP_ERROR_CHECK(esp_netif_init());
}

Network::~Network() {
  for (int i=0; i < n_connect_wifi; i++) {
    free((void *) connect_wifi[i].ssid);
    free((void *) connect_wifi[i].pass);
  }
  free((void *)connect_wifi);
  n_connect_wifi = 0;
  max_connect_wifi = 0;
  connect_wifi = 0;
  if (preset_ip) free((void *)preset_ip);
  preset_ip = 0;
  if (preset_dns) free((void *)preset_dns);
  preset_dns = 0;
  if (get_ip_addrs) vSemaphoreDelete(get_ip_addrs);
  get_ip_addrs = 0;
}

void Network::setPreset(esp_netif_ip_info_t *pip, esp_netif_dns_info_t *pdns) {
  // Don't copy, just use pointers provided
  preset_ip = pip;
  preset_dns = pdns;
}

void Network::onStaGotIP(void *arg, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{
  ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;

  ESP_LOGD(network->tag, "%s, IPv4 address " IPSTR, __FUNCTION__, IP2STR(&event->ip_info.ip));

  if (network->get_ip_addrs)
    xSemaphoreGive(network->get_ip_addrs);
  network->s_retry_num = 0;

  // Again - workaround for esp-idf framework deficiency : call handlers in the app.
  list<module_registration>::iterator mp;
  for (mp = network->modules.begin(); mp != network->modules.end(); mp++) {
    ESP_LOGI(network->tag, "%s: call module %s", __FUNCTION__, mp->module);
    mp->NetworkConnected(arg, event_base, event_id, event_data);
  }
}

void Network::onStaLostIP(void *arg, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{
  ESP_LOGE(network->tag, "%s", __FUNCTION__);
}

void Network::onWifiConnect(void *arg, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{
  ESP_LOGI(network->tag, "%s", __FUNCTION__);
}

void Network::start_internal(void)
{
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
  esp_netif_config.if_desc = "wifi";
  esp_netif_config.route_prio = 128;
  sta_netif = esp_netif_create_wifi(WIFI_IF_STA, &esp_netif_config);

  esp_wifi_set_default_wifi_sta_handlers();

  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &onStaGotIP, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_LOST_IP, &onStaLostIP, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &onWifiDisconnect, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &onWifiConnect, NULL));
}

/*
 * Note some of this code is duplicated in onWifiDisconnect()
 * for trying subsequent SSIDs.
 */
esp_err_t Network::connect(void)
{
  ESP_LOGI(tag, "Start %s (%d options)", __FUNCTION__, n_connect_wifi);
  start_internal();

  wifi_ix++;
  if (wifi_ix >= n_connect_wifi) {
    ESP_LOGE(tag, "%s: fail, %d > %d", __FUNCTION__, wifi_ix, n_connect_wifi);
    return ESP_FAIL;
  }
  get_ip_addrs = xSemaphoreCreateBinary();

  if (preset_ip) {
    esp_err_t err;

    // Stop DHCP client before setting IPv4 address
    if ((err = esp_netif_dhcpc_stop(sta_netif)) != ESP_OK)
      ESP_LOGE(tag, "%s: failed to stop DHCP, error %d %s", __FUNCTION__,
	err, esp_err_to_name(err));

    // Set IP addresses
    if ((err = esp_netif_set_ip_info(sta_netif, preset_ip)) != ESP_OK) {
      ESP_LOGE(tag, "%s: failed to set preset IP, error %d %s", __FUNCTION__,
	err, esp_err_to_name(err));
    }
    // Set DNS server
    if ((err = esp_netif_set_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, preset_dns)) != ESP_OK) {
      ESP_LOGE(tag, "%s: failed to set DNS info, error %d %s", __FUNCTION__,
	err, esp_err_to_name(err));
    }
  } else {
      ESP_LOGE(tag, "%s: no preset IP", __FUNCTION__);
  }

  memset(&wifi_config, 0, sizeof(wifi_config));
  wifi_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
  wifi_config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
  wifi_config.sta.threshold.rssi = CONFIG_CONNECT_WIFI_SCAN_RSSI_THRESHOLD;
  wifi_config.sta.threshold.authmode = WIFI_AUTH_OPEN;
  strcpy((char *)wifi_config.sta.ssid, connect_wifi[wifi_ix].ssid);
  strcpy((char *)wifi_config.sta.password, connect_wifi[wifi_ix].pass);

  s_retry_num = 0;

  ESP_LOGI(tag, "Connecting to %s", wifi_config.sta.ssid);
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
  esp_err_t ret = esp_wifi_connect();
  if (ret != ESP_OK) {
      ESP_LOGE(tag, "WiFi connect failed! ret:%x", ret);
      return ret;
  }

  ESP_LOGD(tag, "Waiting for IP(s)");
  xSemaphoreTake(get_ip_addrs, portMAX_DELAY);		// Wait for it ..
  // Ok, now onStaGotIP() has been called
  return ESP_OK;
}

void Network::onWifiDisconnect(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
#ifdef CONFIG_NETWORK_VERBOSE
  wifi_event_sta_disconnected_t *disc = (wifi_event_sta_disconnected_t *)event_data;
  ESP_LOGE(network->tag, "Failed to connect to SSID %.*s (reason %d %s)",
      sizeof(disc->ssid), disc->ssid, disc->reason, network->WifiReason2String(disc->reason));
#endif
  network->s_retry_num++;
  ESP_LOGI(network->tag, "%s: retry %d", __FUNCTION__, network->s_retry_num);

  if (network->s_retry_num > CONFIG_CONNECT_WIFI_CONN_MAX_RETRY) {
    ESP_LOGI(network->tag, "WiFi Connect to %s failed, moving on..", network->wifi_config.sta.ssid);
    /* Unless we fail and have no more SSIDs to try .. */
    network->wifi_ix++;
    network->s_retry_num = 0;
    if (network->wifi_ix >= network->n_connect_wifi) {
      ESP_LOGI(network->tag, "Out of options for WiFi Connect, stop trying");
      if (network->get_ip_addrs) {
        xSemaphoreGive(network->get_ip_addrs);
      }
      return;
    }

    /* Retry with next SSID */
    strcpy((char *)network->wifi_config.sta.ssid, network->connect_wifi[network->wifi_ix].ssid);
    strcpy((char *)network->wifi_config.sta.password, network->connect_wifi[network->wifi_ix].pass);

    ESP_LOGI(network->tag, "Connecting to %s...", network->wifi_config.sta.ssid);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &network->wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());
    return;
  }

  ESP_LOGD(network->tag, "Wi-Fi disconnected, trying to reconnect...");
  esp_err_t err = esp_wifi_connect();
  if (err == ESP_ERR_WIFI_NOT_STARTED) {
    return;
  }
  ESP_ERROR_CHECK(err);
}

/*
 * Very simplistic API to add a list of SSIDs instead of the statically compiled list
 */
void Network::connect_ssid_clear() {
  if (connect_wifi != _connect_wifi) {
    // Free allocations, if this is not the static stuff. (Just clear in the else case.)
    for (int i=0; i < n_connect_wifi; i++) {
      free((void *) connect_wifi[i].ssid);
      free((void *) connect_wifi[i].pass);
    }
    free(connect_wifi);
  }
  connect_wifi = 0;
  max_connect_wifi = 0;
  n_connect_wifi = 0;
}

void Network::connect_ssid_add(const char *ssid, const char *pass) {
  // Simple way to avoid havoc
  if (connect_wifi == _connect_wifi)
    connect_ssid_clear();

  // Add mem in chunks
  if (n_connect_wifi == max_connect_wifi) {
    max_connect_wifi += 4;
    connect_wifi = (struct connect_wifi_t *)realloc((void *)connect_wifi,
      sizeof(struct connect_wifi_t) * max_connect_wifi);
  }

  connect_wifi[n_connect_wifi].ssid = strdup(ssid);
  connect_wifi[n_connect_wifi].pass = strdup(pass);

  n_connect_wifi++;
}

#ifdef CONFIG_NETWORK_VERBOSE
const char *Network::WifiReason2String(int r) {
  switch (r) {
  case WIFI_REASON_UNSPECIFIED:                 return "UNSPECIFIED";
  case WIFI_REASON_AUTH_EXPIRE:                 return "AUTH_EXPIRE";
  case WIFI_REASON_AUTH_LEAVE:                  return "AUTH_LEAVE";
  case WIFI_REASON_ASSOC_EXPIRE:                return "ASSOC_EXPIRE";
  case WIFI_REASON_ASSOC_TOOMANY:               return "ASSOC_TOOMANY";
  case WIFI_REASON_NOT_AUTHED:                  return "NOT_AUTHED";
  case WIFI_REASON_NOT_ASSOCED:                 return "NOT_ASSOCED";
  case WIFI_REASON_ASSOC_LEAVE:                 return "ASSOC_LEAVE";
  case WIFI_REASON_ASSOC_NOT_AUTHED:            return "ASSOC_NOT_AUTHED";
  case WIFI_REASON_DISASSOC_PWRCAP_BAD:         return "DISASSOC_PWRCAP_BAD";
  case WIFI_REASON_DISASSOC_SUPCHAN_BAD:        return "DISASSOC_SUPCHAN_BAD";
  case WIFI_REASON_IE_INVALID:                  return "IE_INVALID";
  case WIFI_REASON_MIC_FAILURE:                 return "MIC_FAILURE";
  case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:      return "4WAY_HANDSHAKE_TIMEOUT";
  case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT:    return "GROUP_KEY_UPDATE_TIMEOUT";
  case WIFI_REASON_IE_IN_4WAY_DIFFERS:          return "IE_IN_4WAY_DIFFERS";
  case WIFI_REASON_GROUP_CIPHER_INVALID:        return "GROUP_CIPHER_INVALID";
  case WIFI_REASON_PAIRWISE_CIPHER_INVALID:     return "PAIRWISE_CIPHER_INVALID";
  case WIFI_REASON_AKMP_INVALID:                return "AKMP_INVALID";
  case WIFI_REASON_UNSUPP_RSN_IE_VERSION:       return "UNSUPP_RSN_IE_VERSION";
  case WIFI_REASON_INVALID_RSN_IE_CAP:          return "INVALID_RSN_IE_CAP";
  case WIFI_REASON_802_1X_AUTH_FAILED:          return "802_1X_AUTH_FAILED";
  case WIFI_REASON_CIPHER_SUITE_REJECTED:       return "CIPHER_SUITE_REJECTED";
  case WIFI_REASON_BEACON_TIMEOUT:              return "BEACON_TIMEOUT";
  case WIFI_REASON_NO_AP_FOUND:                 return "NO_AP_FOUND";
  case WIFI_REASON_AUTH_FAIL:                   return "AUTH_FAIL";
  case WIFI_REASON_ASSOC_FAIL:                  return "ASSOC_FAIL";
  case WIFI_REASON_HANDSHAKE_TIMEOUT:           return "HANDSHAKE_TIMEOUT";
  case WIFI_REASON_CONNECTION_FAIL:             return "CONNECTION_FAIL";
  default:                                      return "?";
  }
}
#endif

module_registration::module_registration(const char *name,
    esp_event_handler_t nc, esp_event_handler_t nd) {
  module = name;
  NetworkConnected = nc;
  NetworkDisconnected = nd;
}

void Network::registerModule(const char *name, esp_event_handler_t nc, esp_event_handler_t nd) {
  ESP_LOGI(tag, "%s(%s)", __FUNCTION__, name);
  struct module_registration *mr = new module_registration(name, nc, nd);

  registerModule(mr);
}

void Network::registerModule(module_registration *mp) {
  modules.push_back(*mp);
}

void Network::registerModule(module_registration m) {
  modules.push_back(m);
}
