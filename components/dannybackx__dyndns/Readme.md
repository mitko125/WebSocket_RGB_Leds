Dynamic DNS client library for ESP32

Copyright &copy; 2019, 2020, 2021, 2023, 2025 by Danny Backx

The supporting functions for DynDNS allow you to have active FQDN, even on more than one name for a single device :
      dyndns = new Dyndns(config->dyndns_provider());
      dyndns->setHostname(config->dyndns_url());
      dyndns->setAuth(config->dyndns_auth());

      dyndns2 = new Dyndns(DD_CLOUDNS);
      dyndns2->setHostname(DYNDNS2_URL);
      dyndns2->setAuth(DYNDNS2_AUTH);

  and then run code like this periodically both on dyndns and dyndns2 :

    if (dyndns && (nowts > 1000000L)) {
      if ((dyndns_timeout == 0) || (nowts > dyndns_timeout)) {
	if (dyndns->update()) {
	  ESP_LOGI(app_tag, "DynDNS update succeeded");
	  // On success, repeat after a day
	  dyndns_timeout = nowts + 86400;
	} else {
	  ESP_LOGE(app_tag, "DynDNS update failed");
	  // On failure, retry after a minute
	  dyndns_timeout = nowts + 65;
	}
      }
    }
