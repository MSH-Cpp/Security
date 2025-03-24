set(AES_CRYPTO_TESTS_TARGET tinyaes_crypto_test)

add_executable(${AES_CRYPTO_TESTS_TARGET} tinyaes_crypto_test.cpp)
target_link_libraries(${AES_CRYPTO_TESTS_TARGET}
    PRIVATE
        msh::crypto_aes
        Catch2::Catch2WithMain
)

# target_include_directories(${AES_CRYPTO_TESTS_TARGET}
#     PRIVATE
#         ${PROJECT_SOURCE_DIR}/tinyaes_impl/include
# )

# include(CTest)
# add_test(NAME ${AES_CRYPTO_TESTS_TARGET} COMMAND ${AES_CRYPTO_TESTS_TARGET}) 
# add_test(NAME ${AES_CRYPTO_TESTS_TARGET} COMMAND ${AES_CRYPTO_TESTS_TARGET} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
# message(">>>>>>>>> ${CMAKE_CURRENT_BINARY_DIR}")


include(Catch)
catch_discover_tests(${AES_CRYPTO_TESTS_TARGET})

# Configure coverage if enabled
if(ENABLE_COVERAGE)
    configure_opencppcoverage(${AES_CRYPTO_TESTS_TARGET} "${PROJECT_SOURCE_DIR}/tinyaes_impl/include/msh/crypto/*.h" "${PROJECT_SOURCE_DIR}/tinyaes_impl/src/*.cpp")
endif()