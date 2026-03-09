cmake_minimum_required(VERSION 3.10)
project(webside-backend VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# NOTE: The webside server targets (webside_egg) are built from
# the top-level project via examples/CMakeLists.txt.  This standalone
# CMakeLists is kept for reference but is not the primary build entry point.
