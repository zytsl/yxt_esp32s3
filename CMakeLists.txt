# For more information about build system see
# https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/build-system.html
# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

set(PROJECT_VER "1.6.0")

# Add this line to disable the specific warning
add_compile_options(-Wno-missing-field-initializers)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(xiaozhi)

if(NOT IDF_TARGET STREQUAL "esp32s3")
    message(FATAL_ERROR
        "This project is configured for ESP32-S3 boards, but the current ESP-IDF target is '${IDF_TARGET}'. "
        "Run 'idf.py set-target esp32s3', or delete sdkconfig/build and select esp32s3 in the ESP-IDF extension."
    )
endif()

