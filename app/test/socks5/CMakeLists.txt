# app/test/socks5

if(BUILD_SHARED_LIBS)
    add_exe_batch(socks5-client SHARED "client.c")
else()
    add_exe_batch(socks5-client STATIC "client.c")
endif()
target_link_libraries(socks5-client vmecs-crypto vmecs-proto pthread)

if(BUILD_SHARED_LIBS)
    add_exe_batch(socks5-server SHARED "server.c")
else()
    add_exe_batch(socks5-server STATIC "server.c")
endif()

target_link_libraries(socks5-server vmecs-crypto vmecs-proto pthread)
