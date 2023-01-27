cmake_minimum_required (VERSION 3.16)

project(training-aes)

add_executable(aes-test aes_test.cpp)
target_compile_features(aes-test PUBLIC cxx_std_20)
target_include_directories(aes-test PRIVATE ./bytes-literals)

add_executable(aes-test-x86 aes_test_x86.cpp)
target_compile_features(aes-test-x86 PUBLIC cxx_std_20)
target_include_directories(aes-test-x86 PRIVATE ./bytes-literals)

if (UNIX)
  set(ARCH "-maes;-mssse3" CACHE STRING "CPU architecture options")
  target_compile_options(aes-test PRIVATE -Wall ${ARCH})
  target_compile_options(aes-test-x86 PRIVATE -Wall ${ARCH})
endif ()

enable_testing()
add_test(NAME aes-test COMMAND aes-test)
add_test(NAME aes-test-x86 COMMAND aes-test-x86)
