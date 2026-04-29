/*
 * Networking class
 *
 * Copyright (c) 2023, 2024 by Danny Backx
 *   but loosely based on Espressif connection example.
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

#ifndef	__NETWORK_H_
#define	__NETWORK_H_

#include "sdkconfig.h"
#include <esp_log.h>
#include <esp_err.h>
#include <esp_event.h>

#include <esp_netif.h>
#include <esp_wifi_types.h>
#include <esp_event.h>

#include <list>
using namespace std;

struct module_registration {
  const char	*module;
  esp_event_handler_t	NetworkConnected, NetworkDisconnected;

  module_registration(const char *name,
    esp_event_handler_t NetworkConnected,
    esp_event_handler_t NetworkDisconnected);
};

class Network {
public:
			Network();		// ctor
			~Network();		// dtor
  // Have some Arduino-style methods
  void			setup(void);
  void			loop(time_t now);

  bool			isInitialized(),
			initialized;

  // Networking framework
  void			registerModule(const char *, esp_event_handler_t, esp_event_handler_t);
  void			registerModule(module_registration);
  void			registerModule(module_registration *);
  void			WebServerStarted(httpd_handle_t, httpd_handle_t);

  void			setPreset(esp_netif_ip_info_t *pip, esp_netif_dns_info_t *pdns);

  // Start
  esp_err_t		connect(void);

  // API for providing a SSID list
  void			connect_ssid_clear();
  void			connect_ssid_add(const char *ssid, const char *pass);

private:
  const char		*tag = "Network";

  esp_netif_t		*sta_netif = NULL;
  wifi_config_t		wifi_config;
  int			wifi_ix;
  int			s_retry_num;
  SemaphoreHandle_t	get_ip_addrs;

  // Work around esp-idf event issue
  list<module_registration>	modules;

  // This points to the statically initialized version but can be overwritten.
  struct connect_wifi_t	*connect_wifi;
  int			n_connect_wifi;
  int			max_connect_wifi;

  esp_netif_ip_info_t	*preset_ip;
  esp_netif_dns_info_t	*preset_dns;

  void			start_internal(void);

  static void		onWifiDisconnect(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
  static void		onStaGotIP(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

  // These two may not be necessary
  static void		onStaLostIP(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
  static void		onWifiConnect(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

  // Debugging
  const char		*WifiReason2String(int);
};
#endif	//	__NETWORK_H_
