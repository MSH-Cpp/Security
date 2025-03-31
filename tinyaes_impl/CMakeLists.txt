set(MSH_CRYPTO_AES_TARGET msh_crypto_aes)

set(SRCS
    src/tiny_aes.cpp
    src/tiny_aes128.cpp
    src/tiny_aes192.cpp
    src/tiny_aes256.cpp
)

add_library(${MSH_CRYPTO_AES_TARGET} STATIC ${SRCS})
add_library(msh::crypto_aes ALIAS ${MSH_CRYPTO_AES_TARGET})

target_include_directories(${MSH_CRYPTO_AES_TARGET}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(${MSH_CRYPTO_AES_TARGET}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include/msh/crypto
    ${PROJECT_SOURCE_DIR}/interface
)

target_link_libraries(${MSH_CRYPTO_AES_TARGET}
    PUBLIC
    msh::crypto_interface
)
target_link_libraries(${MSH_CRYPTO_AES_TARGET}
    PUBLIC
    $<IF:$<CONFIG:Debug>,${TINY_AES_C_LIBRARY_DEBUG},${TINY_AES_C_LIBRARY}>
)

if(ENABLE_STATIC_ANALYSIS)
    configure_cppcheck(${MSH_CRYPTO_AES_TARGET} "${CMAKE_CURRENT_SOURCE_DIR}/include/msh/crypto" "${CMAKE_CURRENT_SOURCE_DIR}/src")
endif()

# Installation
# install(TARGETS ${MSH_CRYPTO_AES_TARGET}
#     EXPORT ${MSH_CRYPTO_AES_TARGET}Targets
#     LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#     ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
#     RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#     INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
# )

# install(DIRECTORY include/
#     DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
#     FILES_MATCHING PATTERN "*.hpp"
# )

# install(EXPORT ${MSH_CRYPTO_AES_TARGET}Targets
#     FILE ${MSH_CRYPTO_AES_TARGET}Targets.cmake
#     NAMESPACE msh_crypto::
#     DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${MSH_CRYPTO_AES_TARGET}
# )