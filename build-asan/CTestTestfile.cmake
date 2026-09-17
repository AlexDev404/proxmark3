# CMake generated Testfile for 
# Source directory: /home/runner/work/libnxpsc/libnxpsc
# Build directory: /home/runner/work/libnxpsc/libnxpsc/build-asan
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(crypto "/home/runner/work/libnxpsc/libnxpsc/build-asan/nxpsc_test_crypto")
set_tests_properties(crypto PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/libnxpsc/libnxpsc/CMakeLists.txt;100;add_test;/home/runner/work/libnxpsc/libnxpsc/CMakeLists.txt;0;")
add_test(protocol "/home/runner/work/libnxpsc/libnxpsc/build-asan/nxpsc_test_protocol")
set_tests_properties(protocol PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/libnxpsc/libnxpsc/CMakeLists.txt;112;add_test;/home/runner/work/libnxpsc/libnxpsc/CMakeLists.txt;0;")
