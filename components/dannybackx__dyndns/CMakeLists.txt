idf_component_register(
  SRCS "Dyndns.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp_http_client esp_event
)
