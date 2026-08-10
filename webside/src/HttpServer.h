#pragma once

#include <string>
#include <functional>
#include <map>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace webside {

// Simple HTTP request
struct HttpRequest {
    std::string method;      // GET, POST, etc.
    std::string path;        // /api/debug/launch
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
    int port;
    std::atomic<bool> running_{false};
    std::map<std::string, HttpHandler> routes; // key: "METHOD /path"
    std::map<std::string, HttpHandler> prefixRoutes; // key: "METHOD /pathprefix"

    // Connections are read on their own thread so a silent or half-open client
    // cannot stall the accept loop, but handlers stay strictly serialized:
    // the debug session they drive serves one request at a time.
    std::mutex handlerMutex;
    std::atomic<int> activeConnections{0};

    void serveConnection(uintptr_t clientSocket);
    void handleClient(uintptr_t clientSocket);
    bool receiveRequest(uintptr_t clientSocket, std::string& raw);
    HttpRequest parseRequest(const std::string& rawRequest);
    std::string buildResponse(const HttpResponse& response);
    std::string getRouteKey(const std::string& method, const std::string& path);
};

} // namespace webside
