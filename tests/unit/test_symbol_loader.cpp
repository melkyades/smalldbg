#include <doctest/doctest.h>

#include "smalldbg/Debugger.h"
#include "smalldbg/symbols/SymbolLoader.h"

#include <string>

using namespace smalldbg;

namespace {

#ifdef _WIN32
const std::string separator = ";";
#else
const std::string separator = ":";
#endif

} // namespace

TEST_CASE("the directory beside a file is searched after the ones given") {
    Debugger dbg(Mode::External);
    SymbolLoader loader(dbg);
    loader.setSearchPath("pdbs" + separator + "more");
    loader.useSymbolsBeside("dumps/crash.dmp");
    loader.useSymbolsBeside("dumps/other.dmp");

    CHECK(loader.searchPath() == "pdbs" + separator + "more" + separator + "dumps");
}

TEST_CASE("a file with no directory adds nothing to search") {
    Debugger dbg(Mode::External);
    SymbolLoader loader(dbg);
    loader.useSymbolsBeside("crash.dmp");
    CHECK(loader.searchPath().empty());
}
