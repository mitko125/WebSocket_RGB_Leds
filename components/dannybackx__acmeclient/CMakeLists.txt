idf_component_register(
  SRCS "Acme.cpp"
  INCLUDE_DIRS "include"
  REQUIRES arduinojson esp_https_server esp_http_client mbedtls esp_event esp_wifi
)

idf_component_get_property(acmeclient_version dannybackx__acmeclient COMPONENT_VERSION)

target_compile_options(${COMPONENT_LIB} PRIVATE "-D_ACMECLIENT_VERSION=\"${acmeclient_version}\"")
target_compile_options(${COMPONENT_LIB} PUBLIC "-DACMECLIENT_VERSION=\"${acmeclient_version}\"")
