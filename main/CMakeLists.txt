idf_component_register(SRCS "rest_server.c" "my_connect.c" "blink_example_main.c"
                       INCLUDE_DIRS ".")

spiffs_create_partition_image(storage ../html FLASH_IN_PROJECT)