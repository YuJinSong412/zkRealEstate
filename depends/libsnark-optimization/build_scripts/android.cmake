

set ( ANDROID_NDK_HOME        ${ANDROID_SYSROOT}/../../../../../ )

set ( TOOLCHAIN_ABS_PATH      ${ANDROID_SYSROOT}/../bin/ )
set ( COMPILER_PREFIX         ${TOOLCHAIN_ABS_PATH}${ARCH}-linux-android${ANDROID_API_LEVEL}-)
set ( BINUTILS_PREFIX         ${TOOLCHAIN_ABS_PATH}${ARCH}-linux-android-)

set ( CMAKE_C_COMPILER        ${COMPILER_PREFIX}clang )
set ( CMAKE_CXX_COMPILER      ${COMPILER_PREFIX}clang++ )
set ( CMAKE_LINKER            ${TOOLCHAIN_ABS_PATH}llvm-link )
set ( CMAKE_AR                ${BINUTILS_PREFIX}ar )
set ( CMAKE_RANLIB            /usr/bin/true )
set ( CMAKE_SYSTEM_PROCESSOR  ${ARCH} )
set ( CMAKE_SYSTEM_NAME       Android )
set ( CMAKE_SYSROOT           ${ANDROID_SYSROOT} )
set ( CMAKE_CXX_FLAGS         "${CXX_FLAGS}" )

include_directories( ${LIBSNARK_SRC_DIR}/../depends/include/android )