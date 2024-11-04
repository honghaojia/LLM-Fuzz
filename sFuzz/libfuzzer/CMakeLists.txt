find_package(CURL REQUIRED)
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CURL_INCLUDE_DIRS})
include_directories(${Python3_INCLUDE_DIRS})

file(GLOB sources "*.cpp")
file(GLOB headers "*.h")
file(GLOB tools "*.hpp")

add_library(libfuzzer ${sources} ${headers} ${tools})

target_link_libraries(libfuzzer ${Boost_LIBRARIES} ethereum evm ethashseal devcore liboracle)
target_link_libraries(libfuzzer ${CURL_LIBRARIES} ${Python3_LIBRARIES})