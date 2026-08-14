#include "HttpServer.h"

#include <httplib/httplib.h>

#include <iostream>
#include <sstream>

namespace webside {

namespace {

// A client that connects but never completes a request must not be able to
// stall the server; browsers routinely open speculative connections that sit
// silent. Cap how long we wait and how big a request may be.
constexpr time_t kTimeoutSeconds  = 15;
constexpr size_t kMaxRequestBytes = 8 * 1024 * 1024;

// The path is left percent-encoded. Callers decode the segments they care
// about, so decoding here would decode them twice; the query is decoded,
// which is what a value is expected to arrive as.
void splitTarget(const std::string& target, HttpRequest& request) {
    size_t query = target.find('?');
    if (query == std::string::npos) {
        request.path = target;
        return;
    }
    request.path = target.substr(0, query);

    std::istringstream fields(target.substr(query + 1));
    std::string field;
    while (std::getline(fields, field, '&')) {
        size_t equals = field.find('=');
        if (equals != std::string::npos)
            request.params[field.substr(0, equals)] =
                HttpServer::urlDecode(field.substr(equals + 1));
        else if (!field.empty())
            request.params[field] = "true";
    }
}

HttpRequest toRequest(const httplib::Request& incoming) {
    HttpRequest request;
    request.method = incoming.method;
    request.body = incoming.body;
    for (const auto& [name, value] : incoming.headers)
        request.headers[name] = value;
    splitTarget(incoming.target, request);
    return request;
}

} // namespace

HttpServer::HttpServer(int port)
    : port(port), server(std::make_unique<httplib::Server>()) {
}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::route(const std::string& method, const std::string& path, HttpHandler handler) {
    routes[getRouteKey(method, path)] = handler;
}

void HttpServer::routePrefix(const std::string& method, const std::string& pathPrefix, HttpHandler handler) {
    prefixRoutes[getRouteKey(method, pathPrefix)] = handler;
}

void HttpServer::setHandlerWrapper(HandlerWrapper wrapper) {
    handlerWrapper = std::move(wrapper);
}

void HttpServer::run() {
    server->set_read_timeout(kTimeoutSeconds);
    server->set_write_timeout(kTimeoutSeconds);
    server->set_payload_max_length(kMaxRequestBytes);

    // The GUI is served from somewhere else, so every answer needs these.
    server->set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"},
        {"Access-Control-Allow-Headers", "*"},
        {"Access-Control-Max-Age", "86400"},
    });

    // A preflight touches no debugger state, so it never reaches a handler.
    server->Options(".*", [](const httplib::Request&, httplib::Response& outgoing) {
        outgoing.status = 200;
    });

    auto serve = [this](const httplib::Request& incoming, httplib::Response& outgoing) {
        HttpResponse answer = dispatch(toRequest(incoming));
        outgoing.status = answer.statusCode;
        outgoing.reason = answer.statusMessage;
        outgoing.set_content(answer.body, answer.contentType);
    };
    server->Get(".*", serve);
    server->Post(".*", serve);
    server->Put(".*", serve);
    server->Patch(".*", serve);
    server->Delete(".*", serve);

    // "::" with V6ONLY off answers ::1 and 127.0.0.1 alike. An IPv4-only
    // listener leaves nothing on ::1, which is what "localhost" resolves to
    // first, so every client stalls on a dead IPv6 attempt before falling back
    // and pays that on each connection.
    std::cout << "Webside backend server listening on port " << port << std::endl;
    if (!server->listen("::", port))
        std::cerr << "Failed to listen on port " << port << std::endl;
}

void HttpServer::stop() {
    server->stop();
}

// Exact match, else the longest prefix ending at a segment boundary.
const HttpHandler* HttpServer::handlerFor(const HttpRequest& request) const {
    std::string routeKey = getRouteKey(request.method, request.path);

    auto exact = routes.find(routeKey);
    if (exact != routes.end()) return &exact->second;

    const HttpHandler* best = nullptr;
    size_t bestLength = 0;
    for (const auto& [key, handler] : prefixRoutes) {
        if (routeKey.compare(0, key.length(), key) != 0) continue;
        if (routeKey.length() != key.length() && routeKey[key.length()] != '/') continue;
        if (key.length() < bestLength) continue;
        best = &handler;
        bestLength = key.length();
    }
    return best;
}

HttpResponse HttpServer::dispatch(const HttpRequest& request) {
    // Handlers drive the debug session, which serves one request at a time.
    std::lock_guard<std::mutex> serialize(handlerMutex);

    const HttpHandler* handler = handlerFor(request);
    if (!handler) {
        HttpResponse missing;
        missing.statusCode = 404;
        missing.statusMessage = "Not Found";
        missing.body = "{\"error\":\"Route not found\"}";
        return missing;
    }

    try {
        return handlerWrapper ? handlerWrapper(request, *handler) : (*handler)(request);
    } catch (const std::exception& e) {
        HttpResponse failed;
        failed.statusCode = 500;
        failed.statusMessage = "Internal Server Error";
        failed.body = "{\"error\":\"" + std::string(e.what()) + "\"}";
        return failed;
    }
}

std::string HttpServer::getRouteKey(const std::string& method, const std::string& path) const {
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
