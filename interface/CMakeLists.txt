# Set targets
set(MSH_CRYPTO_INTERFACE_TARGET msh_crypto_interface)

# Create interface target
add_library(${MSH_CRYPTO_INTERFACE_TARGET} INTERFACE)
add_library(msh::crypto_interface ALIAS ${MSH_CRYPTO_INTERFACE_TARGET})

target_include_directories(${MSH_CRYPTO_INTERFACE_TARGET}
    INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PREBUILT_INCLUDE_DIR}
)
