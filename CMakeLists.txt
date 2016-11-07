cmake_minimum_required(VERSION 3.3)
set (CMAKE_BUILD_TYPE Release)
enable_language (C)
include ("GNUInstallDirs")

project (libife)
set (LIBIFE_MAJOR_VERSION 1)
set (LIBIFE_MINOR_VERSION 0)
set (LIBIFE_API_VERSION 1)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_BINARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

## libife library
add_library (ife SHARED src/ife.c)
target_include_directories (ife PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties (ife PROPERTIES
	VERSION ${LIBIFE_MAJOR_VERSION}.${LIBIFE_MINOR_VERSION}
	SOVERSION ${LIBIFE_API_VERSION}
)

## test executable
add_executable (iferead iferead/iferead.c)
target_include_directories (iferead PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries (iferead ife)

## install
install (TARGETS ife DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (TARGETS iferead DESTINATION ${CMAKE_INSTALL_BINDIR})
install (FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/ife.h DESTINATION
	${CMAKE_INSTALL_INCLUDEDIR})

