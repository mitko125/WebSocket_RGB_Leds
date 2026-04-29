idf_component_register(
  SRCS "webserver.cpp" "main.c" "acmec.cpp" "acmec.h"
  INCLUDE_DIRS "."
  REQUIRES littlefs nvs_flash esp_wifi esp_netif protocol_examples_common ftpserver
# EMBED_TXTFILES "certs/servercert.pem" "certs/prvtkey.pem"
)
