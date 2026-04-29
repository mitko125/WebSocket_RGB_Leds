set(SOURCES
	App.cpp Network.cpp WebServer.cpp
	App.h Network.h WebServer.h
)

idf_component_register(
    SRC_DIRS ${DIRS} "."
    INCLUDE_DIRS "." ${DIRS} ${BUILD_DIR}
    REQUIRES driver esp_timer
      esp_event nvs_flash esp_wifi esp_timer esp_netif
      esp_http_server esp_https_server
      ftpserver
)

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")

add_custom_command(OUTPUT ${BUILD_DIR}/build.h
        COMMAND ${COMPONENT_DIR}/generate_build_date ${BUILD_DIR}/build.h
        DEPENDS ${SOURCES} ${BUILD_DIR}/config/sdkconfig.h
        VERBATIM)

add_custom_target(buildh DEPENDS ${BUILD_DIR}/build.h)
add_dependencies(${COMPONENT_LIB} buildh)
