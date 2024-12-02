# proto

if(BUILD_SHARED_LIBS)
    add_lib_batch(vmecs-proto SHARED "*.c" "vmess/*.c" "native/*.c" "relay/*.c" "socks/*.c" "dokodemo/*.c")
else()
    add_lib_batch(vmecs-proto STATIC "*.c" "vmess/*.c" "native/*.c" "relay/*.c" "socks/*.c" "dokodemo/*.c")
endif()

target_link_libraries(vmecs-proto vmecs-crypto vmecs-pub)
