# app/vmecs

if(BUILD_SHARED_LIBS)
    add_exe_batch(vmecs SHARED "*.c")
else()
    add_exe_batch(vmecs STATIC "*.c")
endif()
target_link_libraries(vmecs toml vmecs-crypto vmecs-proto pthread)
