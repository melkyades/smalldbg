// SmallDBG test target program
// Designed to be launched under the test harness. It exposes several
// functions and clearly identifiable code locations so the debugger tests
// can set breakpoints, step in/out/over, and inspect memory/registers.

#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <stdexcept>

#include "platform/Platform.h"

volatile int g_test_value = 42;

static void break_here() {
    // Intentionally empty — tests can set a breakpoint on this function
    // to pause the program at a well-known address.
    volatile int x = 0;
    (void)x;
}

static int inner_work(int a) {
    int b = a * 2;
    b += 3;
    return b;
}

static int more_work(int x) {
    // A call chain that tests can step through
    int v = inner_work(x);
    v += inner_work(7);
    return v;
}

static void workload_loop(int iterations) {
    for (int i = 0; i < iterations; ++i) {
        // touch global memory so tests can read/write it
        g_test_value += i;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

static void do_a_crash() {
    // intentionally cause an unhandled exception (only used explicitly)
    throw std::runtime_error("test-app: intentional crash");
}

int main(int argc, char **argv) {
    std::string mode;
    if (argc > 1) mode = argv[1];

    // Print PID on startup to let tests display or attach to it if they want
    auto pid = smalldbg_internal::current_pid();
    std::cout << "TEST_TARGET PID=" << pid << std::endl;

    // Pause briefly so a launcher/attacher has time to catch up
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Offer an explicit waiting mode so tests can prepare breakpoints
    if (mode == "wait") {
        std::cout << "TEST_TARGET: waiting for debugger input (press ENTER to continue)" << std::endl;
        std::string line;
        std::getline(std::cin, line);
    }

    // Clear and reuse global value so memory read/write tests have deterministic state
    g_test_value = 100;

    // Known function to place a breakpoint on
    break_here();

    // A little computation chain — tests can step into these functions
    int r = more_work(5);
    (void)r;

    // A predictable loop the tests can break inside and single-step through
    workload_loop(5);

    // Option to raise a handled exception for tests that exercise exception events
    if (mode == "throw") {
        try {
            throw std::runtime_error("test-app: thrown error (caught)");
        } catch (const std::exception &e) {
            std::cout << "caught: " << e.what() << std::endl;
        }
    }

    // Option to crash without catching
    if (mode == "crash") {
        do_a_crash();
    }

    // Keep running a short while to let the debugger continue / single-step
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::cout << "TEST_TARGET: exiting cleanly" << std::endl;
    return 0;
}
