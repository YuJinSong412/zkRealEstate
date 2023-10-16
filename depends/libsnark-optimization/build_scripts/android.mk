
ANDROID_SYSROOT 	:=${HOME}/Library/Android/sdk/ndk/20.0.5594570/toolchains/llvm/prebuilt/darwin-x86_64/sysroot
ANDROID_API_LEVEL   :=23

CXX_ARGUMENTS       += -DUSING_ANDROID_JNI_WRAPPER -DUSING_JNI_WRAPPER 
CXX_ARGUMENTS       += -DNO_PROCPS  -DMULTICORE=1 -fopenmp 

CXX_ARGUMENTS_ARM64    	:= ${CXX_ARGUMENTS}  -DCS_BINARY_FORMAT=ANDROID_ARM64
CXX_ARGUMENTS_x86_64    := ${CXX_ARGUMENTS}  -DCS_BINARY_FORMAT=ANDROID_x86_64

ifeq ($(strip $(CPU)),x86_64)
configure_Snark : configure_Snark_arm64 configure_Snark_x86_64 ;
make_Snark : make_Snark_arm64 make_Snark_x86_64 ;
else
configure_Snark : configure_Snark_arm64 ;
make_Snark : make_Snark_arm64 ;
endif


configure_Snark_arm64 :  ;
	mkdir -p ${BUILD_DIR}_arm64
	cd ${BUILD_DIR}_arm64 ; cmake  \
	-D CXX_FLAGS=" ${CXX_ARGUMENTS_ARM64} " \
	-D ANDROID_SYSROOT="${ANDROID_SYSROOT}" \
	-D ANDROID_API_LEVEL="${ANDROID_API_LEVEL}" \
	-D LIBSNARK_SRC_DIR="${LIBSNARK_SRC_DIR}" \
	-D INSTALL_DIR="${INSTALL_DIR}/lib/" \
	-D TARGET="${target}" \
	-D LIB_NAME="Snark_arm64" \
	-D ARCH=aarch64 \
	-S ${PWD}/build_scripts/  

configure_Snark_x86_64 :  ;
	mkdir -p ${BUILD_DIR}_x86_64
	cd ${BUILD_DIR}_x86_64 ; cmake  \
	-D CXX_FLAGS=" ${CXX_ARGUMENTS_x86_64} " \
	-D ANDROID_SYSROOT="${ANDROID_SYSROOT}" \
	-D ANDROID_API_LEVEL="${ANDROID_API_LEVEL}" \
	-D LIBSNARK_SRC_DIR="${LIBSNARK_SRC_DIR}" \
	-D INSTALL_DIR="${INSTALL_DIR}/lib/" \
	-D TARGET="${target}" \
	-D LIB_NAME="Snark_x86_64" \
	-D ARCH=x86_64 \
	-S ${PWD}/build_scripts/  


make_Snark_arm64 : ;
	cd ${BUILD_DIR}_arm64 ; make ${MAKE_JOBS}
	cd ${BUILD_DIR}_arm64 ; make install

make_Snark_x86_64 : ;
	cd ${BUILD_DIR}_x86_64 ; make ${MAKE_JOBS}
	cd ${BUILD_DIR}_x86_64 ; make install
