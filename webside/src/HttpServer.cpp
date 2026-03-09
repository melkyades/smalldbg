#include "HttpServer.h"
#include <iostream>
#include <sstream>
#include <algorithm>

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

        handleClient(clientSocket);
        closesocket(clientSocket);
    }

    closesocket(serverSocket);
}

void HttpServer::stop() {
    running_ = false;
}

void HttpServer::handleClient(int clientSocket) {
    char buffer[4096] = {0};
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesRead <= 0) {
        return;
    }

    std::string rawRequest(buffer, bytesRead);
    HttpRequest request = parseRequest(rawRequest);
    
    // Handle OPTIONS preflight for any route
    if (request.method == "OPTIONS") {
        HttpResponse response;
        response.body = "";
        std::string responseStr = buildResponse(response);
        send(clientSocket, responseStr.c_str(), (int)responseStr.length(), 0);
        return;
    }
    
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
    send(clientSocket, responseStr.c_str(), (int)responseStr.length(), 0);
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
                    // Basic URL decoding: replace + with space
                    for (auto& c : value) { if (c == '+') c = ' '; }
                    request.params[key] = value;
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

    // Read body
    std::string body;
    while (std::getline(stream, line)) {
        body += line;
    }
    request.body = body;

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
    oss << "\r\n";
    oss << response.body;
    return oss.str();
}

std::string HttpServer::getRouteKey(const std::string& method, const std::string& path) {
    return method + " " + path;
}

} // namespace webside
