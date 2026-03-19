#include <smalldbg/Debugger.h>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: test_attach <pid>" << std::endl;
        return 1;
    }
    
    int pid = std::atoi(argv[1]);
    std::cout << "Attempting to attach to PID: " << pid << std::endl;
    
    smalldbg::Debugger debugger(smalldbg::Mode::External, smalldbg::X64::instance());
    debugger.setLogCallback([](const std::string& msg) {
        std::cout << "[LOG] " << msg << std::endl;
    });
    
    auto status = debugger.attach(pid);
    if (status == smalldbg::Status::Ok) {
        std::cout << "Successfully attached to process " << pid << std::endl;
        
        // Try to suspend it
        std::cout << "Suspending process..." << std::endl;
        if (debugger.suspend() == smalldbg::Status::Ok) {
            std::cout << "Process suspended successfully" << std::endl;
            
            // Detach
            std::cout << "Detaching..." << std::endl;
            debugger.detach();
            std::cout << "Detached successfully" << std::endl;
        } else {
            std::cout << "Failed to suspend" << std::endl;
        }
    } else {
        std::cerr << "Failed to attach to process " << pid << std::endl;
        std::cerr << "Status code: " << static_cast<int>(status) << std::endl;
        return 1;
    }
    
    return 0;
}
