#include "Setup.h"
#include "Json.h"

#include <fstream>
#include <sstream>

namespace vmdbg {

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
            .set("address", Json::hex(address))
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

std::vector<std::string> stringsIn(const Json& array) {
    std::vector<std::string> strings;
    for (const auto& entry : array.elements())
        strings.push_back(entry.asString());
    return strings;
}

Json arrayOf(const std::vector<std::string>& strings) {
    auto array = Json::array();
    for (const auto& text : strings) array.add(text);
    return array;
}

TargetSpec targetIn(const Json& target) {
    TargetSpec spec;
    spec.kind = kindNamed(target["kind"].asString());
    spec.path = target["path"].asString();
    spec.pid = static_cast<int>(target["pid"].asInt());
    spec.sourcePath = target["sourcePath"].asString();
    spec.workingDir = target["workingDir"].asString();
    spec.args = stringsIn(target["args"]);
    return spec;
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

void Setup::log(const std::string& message) const {
    if (logger) logger(message);
}

void Setup::setSymbolSearchPath(const std::string& path) {
    symbolDirs = split(path);
    symbolPath = joined(symbolDirs);
    saveIfConfigured();
}

void Setup::addSymbolSearchPath(const std::string& path) {
    for (const auto& known : symbolDirs)
        if (known == path) return;
    symbolDirs.push_back(path);
    symbolPath = joined(symbolDirs);
    saveIfConfigured();
}

void Setup::rememberSymbolModule(const std::string& module) {
    if (module.empty()) return;
    for (const auto& known : symModules)
        if (known == module) return;
    symModules.push_back(module);
    saveIfConfigured();
}

bool Setup::setBreakpoint(uint64_t address, const std::string& name) {
    breaks[address] = name;
    saveIfConfigured();
    return true;
}

bool Setup::clearBreakpoint(uint64_t address) {
    bool known = breaks.erase(address) != 0;
    saveIfConfigured();
    return known;
}

void Setup::setLabel(uint64_t address, const std::string& name) {
    names[address] = name;
    saveIfConfigured();
}

void Setup::clearLabel(uint64_t address) {
    names.erase(address);
    saveIfConfigured();
}

std::string Setup::labelAt(uint64_t address) const {
    auto it = names.find(address);
    return it == names.end() ? std::string{} : it->second;
}

std::string Setup::toJson() const {
    return Json::object()
        .set("target", Json::object()
            .set("kind", nameOf(spec.kind))
            .set("path", spec.path)
            .set("args", arrayOf(spec.args))
            .set("pid", static_cast<int64_t>(spec.pid))
            .set("sourcePath", spec.sourcePath)
            .set("workingDir", spec.workingDir))
        .set("symbolPaths", arrayOf(symbolDirs))
        .set("symbolModules", arrayOf(symModules))
        .set("breakpoints", namedAddresses(breaks))
        .set("labels", namedAddresses(names))
        .dump();
}

bool Setup::load(const std::string& path) {
    configFile = path;

    std::ifstream file(path);
    if (!file) return false;
    std::stringstream text;
    text << file.rdbuf();
    auto config = Json::parse(text.str());
    if (!config.isObject()) {
        log("setup " + path + " is not readable as one");
        return false;
    }

    if (config["target"].isObject()) spec = targetIn(config["target"]);
    symbolDirs = stringsIn(config["symbolPaths"]);
    symbolPath = joined(symbolDirs);
    symModules = stringsIn(config["symbolModules"]);
    breaks.clear();
    names.clear();
    readNamedAddresses(config["breakpoints"], breaks);
    readNamedAddresses(config["labels"], names);

    log("setup loaded from " + path);
    return true;
}

bool Setup::save() const {
    if (configFile.empty()) return false;
    std::ofstream file(configFile);
    if (!file) {
        log("setup could not be written to " + configFile);
        return false;
    }
    file << toJson() << "\n";
    return true;
}

void Setup::saveIfConfigured() const {
    if (!configFile.empty()) save();
}

} // namespace vmdbg
