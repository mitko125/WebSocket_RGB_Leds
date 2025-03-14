set(OTA_FIRMWARE ota_firmware)
file(GLOB_RECURSE OTA_FIRMWARE_SOURCES ${OTA_FIRMWARE}/*.c)

idf_component_register(
    SRCS "rest_server.c" "my_connect.c" "blink_example_main.c"
        ${OTA_FIRMWARE_SOURCES}
    INCLUDE_DIRS "."  ${OTA_FIRMWARE}
    EMBED_FILES ${OTA_FIRMWARE}/ota.html
)

spiffs_create_partition_image(storage ../html FLASH_IN_PROJECT)