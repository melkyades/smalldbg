#include "EggWebsideServer.h"
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

namespace {

bool parseNonNegativeInt(const char* text, int& value) {
    if (text == nullptr || *text == '\0')
        return false;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p)
        if (!std::isdigit(*p))
            return false;
    value = std::atoi(text);
    return true;
}

void printUsage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " <egg_exe_path> [port] [--pause-ms N] [-- egg_args...]" << std::endl;
}

} // namespace

int main(int argc, char** argv) {
    std::string eggPath = argc > 1 ? argv[1] : "";
    if (eggPath.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    int port = 7000;
    bool shouldPause = false;
    int pauseMs = 0;
    bool portParsed = false;
    std::vector<std::string> eggArgs;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--") {
            for (++i; i < argc; ++i)
                eggArgs.push_back(argv[i]);
            break;
        }

        if (arg == "--pause-ms") {
            if (i + 1 >= argc || !parseNonNegativeInt(argv[++i], pauseMs)) {
                printUsage(argv[0]);
                return 1;
            }
            shouldPause = true;
            continue;
        }

        constexpr const char* pausePrefix = "--pause-ms=";
        if (arg.rfind(pausePrefix, 0) == 0) {
            if (!parseNonNegativeInt(arg.c_str() + std::strlen(pausePrefix), pauseMs)) {
                printUsage(argv[0]);
                return 1;
            }
            shouldPause = true;
            continue;
        }

        if (!portParsed && eggArgs.empty() && parseNonNegativeInt(argv[i], port)) {
            portParsed = true;
            continue;
        }

        eggArgs.push_back(arg);
    }

    webside::EggWebsideServer server(port);
    if (!server.launch(eggPath, eggArgs)) {
        std::cerr << "Failed to launch Egg VM: " << eggPath << std::endl;
        return 1;
    }

    if (!server.resume()) {
        std::cerr << "Failed to resume Egg VM after launch" << std::endl;
        return 1;
    }

    if (shouldPause) {
        std::cerr << "[egg] waiting " << pauseMs << "ms before suspend..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(pauseMs));
        if (!server.suspend()) {
            std::cerr << "Failed to suspend Egg VM after launch" << std::endl;
            return 1;
        }
    }

    std::cout << "Egg Webside server running on port " << port << std::endl;
    server.run();
    return 0;
}
