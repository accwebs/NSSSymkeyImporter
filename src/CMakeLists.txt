# locate NSS & NSPR
find_package(NSPR REQUIRED)
find_package(NSS REQUIRED)

SET(header_files  NSSSymkeyImporter.h)
SET(SOURCES       NSSSymkeyImporter.cpp
                  ${header_files})
source_group("Headers" FILES ${header_files})

#include NSS & NSPR
INCLUDE_DIRECTORIES(${NSPR_INCLUDE_DIRS} ${NSS_INCLUDE_DIRS})

ADD_EXECUTABLE(NSSSymkeyImporter ${SOURCES})

# link against NSS & NSPR
TARGET_LINK_LIBRARIES(NSSSymkeyImporter ${NSPR_LIBRARIES} ${NSS_LIBRARIES})

INSTALL(TARGETS NSSSymkeyImporter DESTINATION bin)
