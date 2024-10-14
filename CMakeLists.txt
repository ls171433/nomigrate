cmake_minimum_required(VERSION 3.27)
project(nomigrate)

add_library(nomig-crypto SHARED src/sha.c)
target_include_directories(nomig-crypto PUBLIC include)
target_link_libraries(nomig-crypto PUBLIC bcrypt)

add_executable(test-sha test/test-sha.cpp)
target_include_directories(test-sha PUBLIC include)
target_link_libraries(test-sha PUBLIC gtest)
target_link_libraries(test-sha PUBLIC gtest_main)
target_link_libraries(test-sha PUBLIC nomig-crypto)
