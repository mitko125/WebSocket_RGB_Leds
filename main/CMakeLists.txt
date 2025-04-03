set(OTA_FIRMWARE ota_firmware)
file(GLOB_RECURSE OTA_FIRMWARE_SOURCES ${OTA_FIRMWARE}/*.c)

set(DDNS_ACME ddns_acme)
file(GLOB_RECURSE DDNS_ACME_SOURCES ${DDNS_ACME}/*.cpp ${DDNS_ACME}/*.c)

idf_component_register(
    SRCS "rest_server.c" "my_connect.c" "blink_example_main.c" "ftp.c"
        ${OTA_FIRMWARE_SOURCES} ${DDNS_ACME_SOURCES}
    INCLUDE_DIRS "."  ${OTA_FIRMWARE} ${DDNS_ACME}
    REQUIRES esp_wifi esp_eth nvs_flash app_update esp_driver_gpio 
        esp_https_server json
    EMBED_FILES ${OTA_FIRMWARE}/ota.html
)

# littlefs_create_partition_image(storage ../storage_dirs FLASH_IN_PROJECT)
littlefs_create_partition_image(storage ../storage_dirs)