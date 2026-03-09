#include "EggWebsideServer.h"
#include <iostream>
#include <cstdlib>

int main(int argc, char** argv) {
    std::string eggPath;
    int port = 7000;

    if (argc > 1) eggPath = argv[1];
    if (argc > 2) port = std::atoi(argv[2]);

    if (eggPath.empty()) {
        std::cerr << "Usage: " << argv[0] << " <egg_exe_path> [port]" << std::endl;
        return 1;
    }

    // Collect remaining args to pass to the egg executable
    std::vector<std::string> eggArgs;
    for (int i = 3; i < argc; i++)
        eggArgs.push_back(argv[i]);

    webside::EggWebsideServer server(port);
    if (!server.launch(eggPath, eggArgs)) {
        std::cerr << "Failed to launch Egg VM: " << eggPath << std::endl;
        return 1;
    }

    std::cout << "Egg Webside server running on port " << port << std::endl;
    server.run();
    return 0;
}
