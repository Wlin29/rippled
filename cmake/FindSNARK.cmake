# Locate libsnark
# This module defines
# SNARK_LIBRARY, the name of the library to link against
# SNARK_FOUND, if false, do not try to link against libsnark
# SNARK_INCLUDE_DIR, where to find the headers

find_path(SNARK_INCLUDE_DIR
    NAMES libsnark
    PATHS
    /usr/local/include
    /usr/include
)

find_library(SNARK_LIBRARY
    NAMES snark
    PATHS
    /usr/local/lib
    /usr/lib
)

find_library(FF_LIBRARY
    NAMES ff
    PATHS
    /usr/local/lib
    /usr/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SNARK DEFAULT_MSG SNARK_LIBRARY SNARK_INCLUDE_DIR)

mark_as_advanced(SNARK_INCLUDE_DIR SNARK_LIBRARY)