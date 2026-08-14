#pragma once

#include <string>
#include <functional>
#include <map>
#include <memory>
#include <mutex>

namespace httplib { class Server; }

namespace webside {

// Simple HTTP request
struct HttpRequest {
    std::string method;      // GET, POST, etc.
    std::string path;        // /api/debug/launch, still percent-encoded
    std::string body;        // Request body
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> params; // Query parameters
};

// Simple HTTP response
struct HttpResponse {
    int statusCode = 200;
    std::string statusMessage = "OK";
    std::string body;
    std::string contentType = "application/json";
};

// HTTP request handler
using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;

// Simple HTTP server
class HttpServer {
public:
    HttpServer(int port);
    ~HttpServer();

    // Register a route handler (exact match)
    void route(const std::string& method, const std::string& path, HttpHandler handler);

    // Register a prefix route handler (matches all paths starting with prefix)
    void routePrefix(const std::string& method, const std::string& pathPrefix, HttpHandler handler);

    // Start the server (blocking)
    void run();

    // Stop the server
    void stop();

    static std::string urlDecode(const std::string& encoded);

private:
    HttpResponse dispatch(const HttpRequest& request);
    std::string getRouteKey(const std::string& method, const std::string& path);

    int port;
    std::unique_ptr<httplib::Server> server;
    std::map<std::string, HttpHandler> routes; // key: "METHOD /path"
    std::map<std::string, HttpHandler> prefixRoutes; // key: "METHOD /pathprefix"

    // Connections are read on their own thread so a silent or half-open client
    // cannot stall the accept loop, but handlers stay strictly serialized:
    // the debug session they drive serves one request at a time.
    std::mutex handlerMutex;
};

} // namespace webside
