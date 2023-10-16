
SDK_DIR             :=$(shell xcrun --show-sdk-path --sdk macosx)

#
#   - following provided by homebrew
#
GMP_INSTALL_LOCATION :=${GMP}
SSL_INSTALL_LOCATION :=${OpenSSL}
OMP_INSTALL_LOCATION :=${OMP}
JDK_INSTALL_LOCATION :=${OpenJDK}


#
# 	Configure and Build static libsnark
#

ifeq ($(strip $(CPU)),x86_64)
CXX_ARGUMENTS 	+= -DCS_BINARY_FORMAT=MACOS_X86_64 
else
CXX_ARGUMENTS 	+= -DCS_BINARY_FORMAT=MACOS_APPLE_SILICON 
endif


CXX_ARGUMENTS 	+= -fPIC -DNO_PROCPS 
CXX_ARGUMENTS   += -DMULTICORE=1 -Xpreprocessor -fopenmp
CXX_ARGUMENTS 	+= -DUSING_JNI_WRAPPER
CXX_ARGUMENTS   += -I${GMP_INSTALL_LOCATION}/include
CXX_ARGUMENTS   += -I${SSL_INSTALL_LOCATION}/include
CXX_ARGUMENTS   += -I${OMP_INSTALL_LOCATION}/include
CXX_ARGUMENTS   += -I${JDK_INSTALL_LOCATION}/include


configure_Snark : 
	source build_workspace/darwin_path.info ; \
	make target=${target} ${BUILD_TYPE} configure_Snark_next 

configure_Snark_next : 
	cd ${BUILD_DIR} ; cmake  \
	-D SDK_DIR="${SDK_DIR}" \
	-D CXX_FLAGS=" ${CXX_ARGUMENTS} " \
	-D LIBSNARK_SRC_DIR="${LIBSNARK_SRC_DIR}" \
	-D INSTALL_DIR="${INSTALL_DIR}/lib/" \
	-D TARGET="${target}" \
	-D HostCPU=${CPU} \
	-D LIB_NAME="Snark" \
	-S ${PWD}/build_scripts/  

make_Snark : 
	cd ${BUILD_DIR} ; make ${MAKE_JOBS} 
	cd ${BUILD_DIR} ; make install
