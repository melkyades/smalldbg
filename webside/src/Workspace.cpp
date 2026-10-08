#include "Workspace.h"
#include "Json.h"
#include "WebsideSession.h"

#include <cstdio>
#include <fstream>
#include <sstream>

namespace webside {

namespace {

const char* kindNames[] = {"launch", "attach", "trace", "dump"};

std::string nameOf(TargetKind kind) {
    return kindNames[static_cast<int>(kind)];
}

TargetKind kindNamed(const std::string& name) {
    for (int i = 0; i < 4; ++i)
        if (name == kindNames[i]) return static_cast<TargetKind>(i);
    return TargetKind::Launch;
}

std::string hexOf(uint64_t address) {
    char text[32];
    std::snprintf(text, sizeof(text), "0x%llx",
                  static_cast<unsigned long long>(address));
    return text;
}

uint64_t addressOf(const Json& value) {
    if (value.isNumber()) return value.asUInt();
    try {
        return std::stoull(value.asString(), nullptr, 0);
    } catch (...) {
        return 0;
    }
}

Json namedAddresses(const std::map<uint64_t, std::string>& entries) {
    auto array = Json::array();
    for (const auto& [address, name] : entries)
        array.add(Json::object()
            .set("address", hexOf(address))
            .set("name", name));
    return array;
}

void readNamedAddresses(const Json& array,
                        std::map<uint64_t, std::string>& into) {
    if (!array.isArray()) return;
    for (const auto& entry : array.elements()) {
        uint64_t address = addressOf(entry["address"]);
        if (address != 0) into[address] = entry["name"].asString();
    }
}

std::string joined(const std::vector<std::string>& paths) {
    std::string all;
    for (const auto& path : paths) {
        if (path.empty()) continue;
        if (!all.empty()) all += ";";
        all += path;
    }
    return all;
}

std::vector<std::string> split(const std::string& paths) {
    std::vector<std::string> parts;
    std::stringstream stream(paths);
    std::string part;
    while (std::getline(stream, part, ';'))
        if (!part.empty()) parts.push_back(part);
    return parts;
}

} // namespace

Workspace::Workspace(SessionFactory factory)
    : makeSession(std::move(factory)) {}

Workspace::~Workspace() = default;

void Workspace::setLogCallback(
    std::function<void(const std::string&)> callback) {
    logger = std::move(callback);
}

void Workspace::log(const std::string& message) const {
    if (logger) logger(message);
}

void Workspace::setSymbolSearchPath(const std::string& path) {
    symbolDirs = split(path);
    symbolPath = joined(symbolDirs);
    saveIfConfigured();
}

void Workspace::addSymbolSearchPath(const std::string& path) {
    for (const auto& known : symbolDirs)
        if (known == path) return;
    symbolDirs.push_back(path);
    symbolPath = joined(symbolDirs);
    saveIfConfigured();
}

void Workspace::rememberSymbolModule(const std::string& module) {
    if (module.empty()) return;
    for (const auto& known : symModules)
        if (known == module) return;
    symModules.push_back(module);
    saveIfConfigured();
}

bool Workspace::setBreakpoint(uint64_t address, const std::string& name) {
    breaks[address] = name;
    saveIfConfigured();
    return current ? current->setBreakpoint(address, name) : true;
}

bool Workspace::clearBreakpoint(uint64_t address) {
    bool known = breaks.erase(address) != 0;
    saveIfConfigured();
    return current ? current->clearBreakpoint(address) : known;
}

void Workspace::setLabel(uint64_t address, const std::string& name) {
    names[address] = name;
    saveIfConfigured();
}

void Workspace::clearLabel(uint64_t address) {
    names.erase(address);
    saveIfConfigured();
}

std::string Workspace::labelAt(uint64_t address) const {
    auto it = names.find(address);
    return it == names.end() ? std::string{} : it->second;
}

std::string Workspace::toJson() const {
    auto args = Json::array();
    for (const auto& arg : spec.args) args.add(arg);

    auto paths = Json::array();
    for (const auto& path : symbolDirs) paths.add(path);

    auto modules = Json::array();
    for (const auto& module : symModules) modules.add(module);

    return Json::object()
        .set("target", Json::object()
            .set("kind", nameOf(spec.kind))
            .set("path", spec.path)
            .set("args", args)
            .set("pid", static_cast<int64_t>(spec.pid))
            .set("sourcePath", spec.sourcePath))
        .set("symbolPaths", paths)
        .set("symbolModules", modules)
        .set("breakpoints", namedAddresses(breaks))
        .set("labels", namedAddresses(names))
        .dump();
}

bool Workspace::load(const std::string& path) {
    configFile = path;

    std::ifstream file(path);
    if (!file) return false;

    std::stringstream text;
    text << file.rdbuf();
    auto config = Json::parse(text.str());
    if (!config.isObject()) {
        log("workspace " + path + " is not readable as a workspace");
        return false;
    }

    const Json& target = config["target"];
    if (target.isObject()) {
        spec.kind = kindNamed(target["kind"].asString());
        spec.path = target["path"].asString();
        spec.pid = static_cast<int>(target["pid"].asInt());
        spec.sourcePath = target["sourcePath"].asString();
        spec.args.clear();
        for (const auto& arg : target["args"].elements())
            spec.args.push_back(arg.asString());
    }

    symbolDirs.clear();
    for (const auto& entry : config["symbolPaths"].elements())
        symbolDirs.push_back(entry.asString());
    symbolPath = joined(symbolDirs);

    symModules.clear();
    for (const auto& entry : config["symbolModules"].elements())
        symModules.push_back(entry.asString());

    breaks.clear();
    names.clear();
    readNamedAddresses(config["breakpoints"], breaks);
    readNamedAddresses(config["labels"], names);

    log("workspace loaded from " + path);
    return true;
}

bool Workspace::save() const {
    if (configFile.empty()) return false;
    std::ofstream file(configFile);
    if (!file) {
        log("workspace could not be written to " + configFile);
        return false;
    }
    file << toJson() << "\n";
    return true;
}

void Workspace::saveIfConfigured() const {
    if (!configFile.empty()) save();
}

bool Workspace::open(const TargetSpec& target) {
    close();
    spec = target;

    auto session = makeSession(target);
    // A dump or a trace loads its modules while opening, so the search path
    // must be set first.
    session->setOpeningLog(logger);
    session->setSymbolSearchPath(symbolPath);
    session->setVerboseSymbolLogging(verbose);
    session->setStartupPause(startupPause);
    if (!session->open(spec)) return false;

    current = std::move(session);
    loadRememberedSymbols();
    applyBreakpoints();
    saveIfConfigured();
    return true;
}

void Workspace::close() {
    current.reset();
}

void Workspace::loadRememberedSymbols() {
    for (const auto& module : symModules)
        current->loadModuleSymbols(module);
}

void Workspace::applyBreakpoints() {
    for (const auto& [address, name] : breaks)
        current->setBreakpoint(address, name);
}

} // namespace webside
