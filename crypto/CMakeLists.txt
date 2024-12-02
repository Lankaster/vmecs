# crypto

if(BUILD_SHARED_LIBS)
    add_lib_batch(vmecs-crypto SHARED "*.c")
else()
    add_lib_batch(vmecs-crypto STATIC "*.c")
endif()

target_link_libraries(vmecs-crypto ssl crypto)
