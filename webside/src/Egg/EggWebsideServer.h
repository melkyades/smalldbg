#pragma once

#include "../WebsideServer.h"
#include "../Json.h"
#include "EggDebugSession.h"
#include <memory>
#include <cstdint>

namespace webside {

/// Webside server for the Egg C++ VM — uses the smalldbg API to
/// launch/attach to an egg process, suspend/resume it, walk its native
/// stack, read objects via readMemory, and expose class browsing, frame
/// detail, and search through the standard Webside HTTP routes.
class EggWebsideServer : public WebsideServer {
public:
    explicit EggWebsideServer(int port);

    /// Launch the egg executable, wait for initialization, then suspend.
    bool launch(const std::string& eggPath,
                const std::vector<std::string>& args = {});

protected:
    // ---- WebsideServer overrides ----
    std::string dialect() const override;
    std::string description() const override;

    bool isActive() const override;
    std::string stopReason() const override;
    std::optional<int> pid() const override;

    bool resume() override;
    bool suspend() override;

    std::string listFrames() const override;
    std::string getFrameDetail(int index) const override;
    std::string getFrameBindings(int index) const override;

    void setupRoutes() override;

    // ---- class / search data ----
    std::string classListData(const std::string& root,
                              bool namesOnly) const override;
    std::string classDetailData(const std::string& name) const override;
    std::string searchData(const std::string& text, bool ignoreCase,
                           const std::string& condition,
                           const std::string& type) const override;
    std::string subclassesData(const std::string& name) const override;
    std::string superclassesData(const std::string& name) const override;
    std::string variablesData(const std::string& name) const override;
    std::string instanceVariablesData(const std::string& name) const override;
    std::string classVariablesData(const std::string& name) const override;
    std::string categoriesData(const std::string& name) const override;
    std::string usedCategoriesData(const std::string& name) const override;
    std::string selectorsData(const std::string& name) const override;
    std::string methodsData(const std::string& name) const override;
    std::string methodDetailData(const std::string& className,
                                 const std::string& selector) const override;

    // ---- native symbol data ----
    std::string nativeSymbolsData(const std::string& filter) const override;
    std::string nativeModulesData() const override;
    std::string nativeSymbolDetailData(const std::string& name) const override;
    std::string nativeInspectData(const std::string& expression) const override;

private:
    std::unique_ptr<EggDebugSession> session;

    // ---- Multi-debugger helpers ----
    HttpResponse handleDebuggerRoute(const HttpRequest& req) const;
    HttpResponse handleNativeDebuggerRoute(
        const std::vector<std::string>& segments) const;
    HttpResponse handleSmalltalkDebuggerRoute(
        const std::vector<std::string>& segments, int threadIndex) const;
};

} // namespace webside
