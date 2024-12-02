# app/vhook

if(BUILD_SHARED_LIBS)
    add_lib_batch(vhook-core SHARED "hook.c")
else()
    add_lib_batch(vhook-core STATIC "hook.c")
endif()
target_link_libraries(vhook-core vmecs-crypto vmecs-proto dl)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVHOOK_CORE=\\\"libvhook-core.so\\\"")

add_exe_batch(vhook STATIC "main.c")
target_link_libraries(vhook)
