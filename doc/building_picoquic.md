# Building PicoQUIC

See the 'Building Picoquic' section [README](../README.md) for building picoquic for the first time and installing the dependencies.

## Dependencies

Direct dependencies
- [Picotls implementation of TLS 1.3](https://github.com/h2o/picotls)

Inherited dependencies
- [OpenSSL through PicoTLS]()

TODO: Current issues and ongoing work

There is a current issue trying to enable the use

## Picoquic as a Dependency

When using CMake [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html) can be used to fetch the `picoquic` repository from github.
A snipped that does this can be seen in the [quicrq](https://github.com/Quicr/quicrq) directory in the `dependencies` subdirectory and is shown below.

```cmake
# Enable fetching content
include(FetchContent)

# Fetch the picoquic library, which brings in picotls with it
FetchContent_Declare(
    picoquic
    GIT_REPOSITORY  https://github.com/private-octopus/picoquic.git
    GIT_TAG         master
)

# Set the option to force picoquic to fetch the picotls
set(PICOQUIC_FETCH_PTLS ON)

# Make dependencies available
FetchContent_MakeAvailable(picoquic)
```

FetchContent can be used to fetch a specific release or tag.

## Targets

Targets are anything that is defined as an executable in `CMakeLists.txt`.
Avaialable targets:

- picoquicdemo
- picolog_t
- picoquic_ct
- picohttp_ct
- pico_baton
- picoquic_sample
- thread_test

All of these targets are built when the `make .` or `cmake --build .` commands are used to build the project. After which the test program `picoquic_ct` can be used to verify the port.

`picoquicdemo` ([found in picoquicfirst/picoquicdemo.c](../picoquicfirst/picoquicdemo.c)) and `picoquic_sample` ([sample documentation](../sample/README.md)) are a good starting point for developing an application on top of this QUIC implementation.


## (Re)Building a Single Target

Targets defined in the `CMakeLists.txt`, listed above for convenience, can be build individually using cmake's `--target` option. The command `cmake --build . --target <target_name>` can be used to build a specific target and all it's dependcies. For example `cmake --build . --target picoquic_sample` will build the sample file transfer application in [sample/](../sample/README.md) as defined in the `CMakeLists.txt`. All the required components will also be built. This works if the command is issued in the top-level directory of the repository. This is useful for recompiling test programs and programs like `picoquic_sample` and `picoquicdemo` if they have been modified. Therefore reducing build times when making small changes.

This also works if `picoquic` has not been built as a whole before.
