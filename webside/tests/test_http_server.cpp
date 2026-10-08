#include <doctest/doctest.h>

#include "HttpServer.h"

#include <httplib/httplib.h>

#include <chrono>
#include <future>
#include <thread>

using webside::HttpRequest;
using webside::HttpResponse;
using webside::HttpServer;

namespace {

constexpr int kPort = 47231;

// Asks the server on kPort for `path`, retrying while it starts. Returns an
// empty result when it never answers.
httplib::Result getWhenUp(const std::string& path) {
    httplib::Client client("127.0.0.1", kPort);
    for (int attempt = 0; attempt < 50; attempt++) {
        if (auto result = client.Get(path)) return result;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return client.Get(path);
}

// A server answering "first" on kPort, running on its own thread until the
// test ends.
struct RunningServer {
    HttpServer server{kPort};
    std::thread thread;

    RunningServer() {
        server.route("GET", "/who", [](const HttpRequest&) {
            HttpResponse answer;
            answer.body = "first";
            answer.headers["X-Webside-Warning"] = "partial";
            return answer;
        });
        thread = std::thread([this] { server.run(); });
    }

    ~RunningServer() {
        server.stop();
        thread.join();
    }
};

} // namespace

TEST_CASE("a server sends the extra headers of an answer, and exposes them") {
    RunningServer running;
    auto result = getWhenUp("/who");
    REQUIRE(result);
    CHECK(result->body == "first");
    CHECK(result->get_header_value("X-Webside-Warning") == "partial");
    CHECK(result->get_header_value("Access-Control-Expose-Headers") ==
          "X-Webside-Warning");
}

TEST_CASE("a second server cannot take a port that is in use") {
    RunningServer running;
    REQUIRE(getWhenUp("/who"));

    HttpServer second(kPort);
    second.route("GET", "/who", [](const HttpRequest&) {
        HttpResponse answer;
        answer.body = "second";
        return answer;
    });
    auto attempt = std::async(std::launch::async, [&] { second.run(); });
    bool refused =
        attempt.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    if (!refused) second.stop();
    CHECK(refused);

    for (int i = 0; i < 10; i++) {
        auto result = getWhenUp("/who");
        REQUIRE(result);
        CHECK(result->body == "first");
    }
}
