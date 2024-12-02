# pub

if(BUILD_SHARED_LIBS)
    add_lib_batch(vmecs-pub SHARED "*.c")
else()
    add_lib_batch(vmecs-pub STATIC "*.c")
endif()

