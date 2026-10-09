#pragma once

#include "Smalltalk/Inspector.h"
#include "Session.h"
#include "../WebsideServer.h"

namespace smalltalk {

/** A smalltalk::WebsideServer serves a Smalltalk VM. It adds the routes of a
 *  VM with an object memory: where its spaces are and what an address is. It
 *  answers them from the session's Smalltalk inspector, so that every dialect
 *  gets them. **/
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

    void setupRoutes() override;
};

} // namespace smalltalk
