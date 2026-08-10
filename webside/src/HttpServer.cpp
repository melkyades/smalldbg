#include "HttpServer.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <cctype>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define closesocket close
#endif

namespace webside {

namespace {

// A client that connects but never completes a request must not be able to
// stall the server; browsers routinely open speculative connections that sit
// silent. Cap how long we wait, how big a request may be, and how many
// connections may be in flight.
constexpr int    kRecvTimeoutMs   = 15000;
constexpr size_t kMaxRequestBytes = 8 * 1024 * 1024;
constexpr int    kMaxConnections  = 64;

void setRecvTimeout(SOCKET s, int ms) {
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// Offset just past the blank line ending the headers, or npos.
size_t findBodyStart(const std::string& raw) {
    size_t p = raw.find("\r\n\r\n");
    if (p != std::string::npos) return p + 4;
    p = raw.find("\n\n");
    if (p != std::string::npos) return p + 2;
    return std::string::npos;
}

// send() may write short; class lists and frame dumps are well past one segment.
void sendAll(SOCKET s, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        int n = send(s, data.data() + sent, (int)(data.size() - sent), 0);
        if (n <= 0) return;
        sent += static_cast<size_t>(n);
    }
}

size_t parseContentLength(const std::string& headers) {
    std::istringstream stream(headers);
    std::string line;
    while (std::getline(stream, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = line.substr(0, colon);
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        if (key != "content-length") continue;
        try { return static_cast<size_t>(std::stoull(line.substr(colon + 1))); }
        catch (...) { return 0; }
    }
    return 0;
}

} // namespace

HttpServer::HttpServer(int port) : port(port) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

HttpServer::~HttpServer() {
    stop();
#ifdef _WIN32
    WSACleanup();
#endif
}

void HttpServer::route(const std::string& method, const std::string& path, HttpHandler handler) {
    routes[getRouteKey(method, path)] = handler;
}

void HttpServer::routePrefix(const std::string& method, const std::string& pathPrefix, HttpHandler handler) {
    prefixRoutes[getRouteKey(method, pathPrefix)] = handler;
}

void HttpServer::run() {
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        return;
    }

    // Allow reuse of address
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        closesocket(serverSocket);
        return;
    }

    if (listen(serverSocket, 5) < 0) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(serverSocket);
        return;
    }

    std::cout << "Webside backend server listening on port " << port << std::endl;
    running_ = true;

    while (running_) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);
        
        if (clientSocket == INVALID_SOCKET) {
            if (running_) {
                std::cerr << "Accept failed" << std::endl;
            }
            continue;
        }

        if (activeConnections.load() >= kMaxConnections) {
            closesocket(clientSocket);
            continue;
        }

        serveConnection(static_cast<uintptr_t>(clientSocket));
    }

    closesocket(serverSocket);
}

// Reading and serving happen off the accept loop, so a client that stalls
// mid-request only stalls itself. handleClient still serializes the dispatch.
void HttpServer::serveConnection(uintptr_t clientSocket) {
    activeConnections++;
    std::thread([this, clientSocket]{
        handleClient(clientSocket);
        closesocket(static_cast<SOCKET>(clientSocket));
        activeConnections--;
    }).detach();
}

void HttpServer::stop() {
    running_ = false;
}

// Read until the headers and the declared body have arrived. Returns false if
// the client timed out, disconnected, or overran the size cap.
bool HttpServer::receiveRequest(uintptr_t clientSocketRaw, std::string& raw) {
    SOCKET clientSocket = static_cast<SOCKET>(clientSocketRaw);
    setRecvTimeout(clientSocket, kRecvTimeoutMs);

    char buffer[4096];
    size_t bodyStart = std::string::npos;
    size_t contentLength = 0;

    for (;;) {
        if (bodyStart == std::string::npos) {
            bodyStart = findBodyStart(raw);
            if (bodyStart != std::string::npos)
                contentLength = parseContentLength(raw.substr(0, bodyStart));
        }
        if (bodyStart != std::string::npos && raw.size() >= bodyStart + contentLength)
            return true;

        int n = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (n <= 0) return false;
        raw.append(buffer, static_cast<size_t>(n));
        if (raw.size() > kMaxRequestBytes) return false;
    }
}

void HttpServer::handleClient(uintptr_t clientSocketRaw) {
    SOCKET clientSocket = static_cast<SOCKET>(clientSocketRaw);

    std::string rawRequest;
    if (!receiveRequest(clientSocketRaw, rawRequest)) {
        return;
    }

    HttpRequest request = parseRequest(rawRequest);

    // Handle OPTIONS preflight for any route (touches no debugger state)
    if (request.method == "OPTIONS") {
        HttpResponse response;
        response.body = "";
        std::string responseStr = buildResponse(response);
        sendAll(clientSocket, responseStr);
        return;
    }

    // Handlers drive the debug session, which serves one request at a time.
    std::lock_guard<std::mutex> serialize(handlerMutex);

    // Find handler
    std::string routeKey = getRouteKey(request.method, request.path);
    HttpResponse response;
    
    auto it = routes.find(routeKey);
    if (it != routes.end()) {
        try {
            response = it->second(request);
        } catch (const std::exception& e) {
            response.statusCode = 500;
            response.statusMessage = "Internal Server Error";
            response.body = "{\"error\":\"" + std::string(e.what()) + "\"}";
        }
    } else {
        // Try prefix route matching (longest prefix first)
        std::string bestMatch;
        for (auto& [key, handler] : prefixRoutes) {
            if (routeKey.length() >= key.length() &&
                routeKey.substr(0, key.length()) == key &&
                key.length() > bestMatch.length()) {
                // Ensure match is at path boundary
                if (routeKey.length() == key.length() ||
                    routeKey[key.length()] == '/') {
                    bestMatch = key;
                }
            }
        }
        if (!bestMatch.empty()) {
            auto pit = prefixRoutes.find(bestMatch);
            try {
                response = pit->second(request);
            } catch (const std::exception& e) {
                response.statusCode = 500;
                response.statusMessage = "Internal Server Error";
                response.body = "{\"error\":\"" + std::string(e.what()) + "\"}";
            }
        } else {
            response.statusCode = 404;
            response.statusMessage = "Not Found";
            response.body = "{\"error\":\"Route not found\"}";
        }
    }

    std::string responseStr = buildResponse(response);
    sendAll(clientSocket, responseStr);
}

HttpRequest HttpServer::parseRequest(const std::string& rawRequest) {
    HttpRequest request;
    std::istringstream stream(rawRequest);
    std::string line;

    // Parse request line
    if (std::getline(stream, line)) {
        std::istringstream lineStream(line);
        std::string pathWithParams;
        lineStream >> request.method >> pathWithParams;
        
        // Split path and query params
        size_t qPos = pathWithParams.find('?');
        if (qPos != std::string::npos) {
            request.path = pathWithParams.substr(0, qPos);
            std::string query = pathWithParams.substr(qPos + 1);
            // Parse query parameters: key=value&key2=value2
            std::istringstream queryStream(query);
            std::string param;
            while (std::getline(queryStream, param, '&')) {
                size_t eqPos = param.find('=');
                if (eqPos != std::string::npos) {
                    std::string key = param.substr(0, eqPos);
                    std::string value = param.substr(eqPos + 1);
                    request.params[key] = urlDecode(value);
                } else if (!param.empty()) {
                    request.params[param] = "true";
                }
            }
        } else {
            request.path = pathWithParams;
        }
    }

    // Parse headers
    while (std::getline(stream, line) && line != "\r" && !line.empty()) {
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 2); // Skip ": "
            if (!value.empty() && value.back() == '\r') {
                value.pop_back();
            }
            request.headers[key] = value;
        }
    }

    // Body: everything past the blank line, verbatim (newlines preserved).
    size_t bodyStart = findBodyStart(rawRequest);
    if (bodyStart != std::string::npos)
        request.body = rawRequest.substr(bodyStart);

    return request;
}

std::string HttpServer::buildResponse(const HttpResponse& response) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << response.statusCode << " " << response.statusMessage << "\r\n";
    oss << "Content-Type: " << response.contentType << "\r\n";
    oss << "Content-Length: " << response.body.length() << "\r\n";
    oss << "Access-Control-Allow-Origin: *\r\n";
    oss << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
    oss << "Access-Control-Allow-Headers: *\r\n";
    oss << "Access-Control-Max-Age: 86400\r\n";
    oss << "Connection: close\r\n";
    oss << "\r\n";
    oss << response.body;
    return oss.str();
}

std::string HttpServer::getRouteKey(const std::string& method, const std::string& path) {
    return method + " " + path;
}

std::string HttpServer::urlDecode(const std::string& encoded) {
    std::string decoded;
    decoded.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); i++) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            int hex = 0;
            std::istringstream iss(encoded.substr(i + 1, 2));
            if (iss >> std::hex >> hex) {
                decoded += static_cast<char>(hex);
                i += 2;
                continue;
            }
        }
        if (encoded[i] == '+')
            decoded += ' ';
        else
            decoded += encoded[i];
    }
    return decoded;
}

} // namespace webside
