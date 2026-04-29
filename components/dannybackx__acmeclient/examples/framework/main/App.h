/*
 * Application include file, contain all includes and "global" variables
 *
 * Copyright (c) 2023, 2024 by Danny Backx
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

#ifndef	__APP_H_
#define	__APP_H_

enum ModuleType {
  mt_unknown,	// unknown device type (e.g. can't parse json)
  mt_cyd,	// so-called cheap yellow display (esp32s3-4827s043)
  mt_zx_tr,	// four GPIO pins exported on J2 pins 5..8
  mt_zx_ar,	// with or without temperature sensor, but J2 pins 5..8 NC (no GPIO exported)
  mt_custom	// Not implemented yet, fully configurable from config
};

#ifdef __cplusplus

#include "sdkconfig.h"

#include <esp_log.h>
#include <esp_err.h>
#include <esp_event.h>

#include <nvs_flash.h>

#include <esp_wifi_types.h>
#include <esp_event.h>
#include <esp_http_server.h>

#include "Network.h"
#include "WebServer.h"

#include <driver/gptimer.h>

#include <Acme.h>
#include <Dyndns.h>

class App {
public:
			App();		// ctor
			~App();		// dtor
  // Have some Arduino-style methods
  void			setup(void);
  void			loop(time_t);

  bool			isInitialized(),
			initialized;

  // Networking framework
  void			WebServerStarted(httpd_handle_t, httpd_handle_t);

  // Global variables
  const char		*build;
  bool			ota_busy;
  time_t		now, boot_time;

  // Stuff we learn from the network, just for easy access
  esp_netif_t		*netif;
  esp_netif_ip_info_t	ip_info;

  // Other application classes
  Network		*network;
  WebServer		*ws;
  Acme			*acme;

  // 
  bool			isPeerSecure(int);
  bool			isPeerSecure(struct sockaddr_in *);
  bool			isPeerSecure(int, struct sockaddr_in *);
  bool			isConnected();

  //
  void			report(const char *);
  char			*timeString(void);
  char			*timeString(time_t);
  void			timeString(time_t, const char *, char *, int);
  void			timeString(time_t t, char *buffer, int len);
  void			timeString(const char *format, char *buffer, int len);
  const char		*http_method2string(const int);

  void			installHandler(httpd_handle_t srv, const char *srv_s, httpd_method_t method,
				const char *uri, esp_err_t (*hdl)(httpd_req_t *r),
				const char *tag, const char *fn);

  void			otaOngoing(bool busy);
  void			setReconnect(time_t then);
  void			setReboot(time_t then);

  void			sendInfoMessage(char *);
  void			sendAlarmMessage(char *);

  ModuleType		String2ModuleType(const char *s);
  const char		*ModuleType2String(ModuleType m);

private:
  const char		*tag = "App";

  bool			connected,
			ftp_started;
  httpd_handle_t	web_server;		

  // Networking framework
  static void		connect(void *, esp_event_base_t, int32_t, void *);
  static void		disconnect(void *, esp_event_base_t, int32_t, void *);
  static void		sntp_sync_notify(struct timeval *);
  esp_netif_ip_info_t	*preset_ip;
  esp_netif_dns_info_t	*preset_dns;
  in_addr_t		whitelist_filter;

  // Time
  struct timeval	tv;
  char			ts[24];

  // Logging to file
  static int		redirectLogToFile(const char *fmt, va_list args);

  // ACME & DynDNS
  void			DoDynDNS();

  // Timers
  time_t		time_reboot, time_reconnect;

  const char		*json_module_type	= "module_type",
			*json_module_type_cyd	= "cheap yellow display",
			*json_module_type_zx_ar = "ZX AR",
			*json_module_type_zx_tr = "ZX TR";

  // UI tick handler
  static void		increase_lvgl_tick(void *);

  static void		failed_alloc_hook(size_t, uint32_t, const char *);
};

extern App		*app;

#endif	// __cplusplus
#endif	//	__APP_H_
