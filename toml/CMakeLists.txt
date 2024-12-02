# toml

if(BUILD_SHARED_LIBS)
    add_exe_batch(toml-test SHARED "*.c")
    add_lib_batch(toml SHARED "*.c")
else()
    add_exe_batch(toml-test STATIC "*.c")
    add_lib_batch(toml STATIC "*.c")
endif()

