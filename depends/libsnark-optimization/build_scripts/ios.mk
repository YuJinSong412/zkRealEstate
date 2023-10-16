
SDK_DIR             :=$(shell xcrun --show-sdk-path --sdk iphoneos)
SIM_SDK_DIR         :=$(shell xcrun --show-sdk-path --sdk iphonesimulator)

CXX_ARGUMENTS       += -DCS_BINARY_FORMAT=IOS_ARM64 -fembed-bitcode
CXX_ARGUMENTS       += -DNO_PROCPS  -DMULTICORE=1 -Xpreprocessor -fopenmp 


#
# 	Configure and Build static libsnark
#
configure_Snark : configure_Snark_iphoneos some_space configure_Snark_iphonesimulator ;
make_Snark : make_Snark_iphoneos some_space make_Snark_iphonesimulator  ;

# configure_Snark : configure_Snark_iphoneos  ;
# make_Snark : make_Snark_iphoneos  ;

# configure_Snark : configure_Snark_iphonesimulator ;
# make_Snark : make_Snark_iphonesimulator  ;

configure_Snark_iphoneos : 
	mkdir -p ${BUILD_DIR}_iphoneos
	cd ${BUILD_DIR}_iphoneos ; cmake  \
	-D SDK_DIR="${SDK_DIR}" \
	-D CXX_FLAGS=" ${CXX_ARGUMENTS} " \
	-D LIBSNARK_SRC_DIR="${LIBSNARK_SRC_DIR}" \
	-D INSTALL_DIR="${INSTALL_DIR}/lib/" \
	-D TARGET=${target} \
	-D iPhoneOS=1 \
	-D LIB_NAME="Snark_iphoneos" \
	-S ${PWD}/build_scripts/  

configure_Snark_iphonesimulator : 
	mkdir -p ${BUILD_DIR}_iphonesimulator
	cd ${BUILD_DIR}_iphonesimulator ; cmake  \
	-D SDK_DIR="${SIM_SDK_DIR}" \
	-D CXX_FLAGS=" ${CXX_ARGUMENTS} " \
	-D LIBSNARK_SRC_DIR="${LIBSNARK_SRC_DIR}" \
	-D INSTALL_DIR="${INSTALL_DIR}/lib/" \
	-D TARGET=${target} \
	-D iPhoneSimulator=1 \
	-D HostCPU=${CPU} \
	-D LIB_NAME="Snark_iphonesimulator" \
	-S ${PWD}/build_scripts/  

make_Snark_iphoneos : 
	cd ${BUILD_DIR}_iphoneos ; make ${MAKE_JOBS} 
	cd ${BUILD_DIR}_iphoneos ; make install

make_Snark_iphonesimulator : 
	cd ${BUILD_DIR}_iphonesimulator ; make ${MAKE_JOBS} 
	cd ${BUILD_DIR}_iphonesimulator ; make install



some_space :
	@echo ; echo ; echo 