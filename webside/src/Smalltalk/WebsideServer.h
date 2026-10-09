#pragma once

#include "Smalltalk/Inspector.h"
#include "Session.h"
#include "../WebsideServer.h"

namespace smalltalk {

/** A smalltalk::WebsideServer serves a Smalltalk VM. It adds the routes of a
 *  VM with an object memory: where its spaces are, what an address is, and
 *  what an object holds. It answers them from the session's Smalltalk
 *  inspector, so that every dialect gets them. **/
class WebsideServer : public webside::WebsideServer {
public:
    using webside::WebsideServer::WebsideServer;

protected:
    /** Returns the session's Smalltalk inspector, or null when the session's
     *  inspector is not a Smalltalk one. It stays valid while the session is
     *  open. **/
    Inspector* smalltalkInspector() const;

    webside::HttpResponse handleRegions(
        const webside::HttpRequest& req) const override;
    webside::HttpResponse handleClassify(
        const webside::HttpRequest& req) const override;
    webside::HttpResponse handleInspect(
        const webside::HttpRequest& req) const override;

    /** Returns one object as JSON, with what every Smalltalk object has. A
     *  dialect whose objects hold more overrides this. **/
    virtual std::string inspectJson(uint64_t oop, int maxSlots) const;

    void setupRoutes() override;
};

} // namespace smalltalk
