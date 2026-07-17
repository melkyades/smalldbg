// Single translation unit that provides doctest's main(). All other unit-test
// translation units include <doctest/doctest.h> without this define.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
