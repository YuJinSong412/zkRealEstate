
 

#
# 	Configure and Build shared libsnark
#
CXX_ARGUMENTS     += -fPIC -DCS_BINARY_FORMAT=LINUX_X86_64 
CXX_ARGUMENTS     += -I/usr/lib/llvm-12/include/c++/v1
CXX_ARGUMENTS     += -DMULTICORE=1 -fopenmp
CXX_ARGUMENTS     += -DUSING_JNI_WRAPPER
CXX_ARGUMENTS     += -I/usr/lib/jvm/java-11-openjdk-amd64/include/linux 
CXX_ARGUMENTS     += -I/usr/lib/jvm/java-11-openjdk-amd64/include/

configure_Snark : 
	cd ${BUILD_DIR} ; cmake  \
	-D CXX_FLAGS=" ${CXX_ARGUMENTS} " \
	-D LIBSNARK_SRC_DIR="${LIBSNARK_SRC_DIR}" \
	-D INSTALL_DIR="${INSTALL_DIR}/lib/" \
	-D TARGET="${target}" \
	-D LIB_NAME="Snark" \
	-S ${PWD}/build_scripts/  

make_Snark : 
	cd ${BUILD_DIR} ; make -j 8 
	cd ${BUILD_DIR} ; make install
	llvm-ranlib-12 ${INSTALL_DIR}/lib/libSnark.a
