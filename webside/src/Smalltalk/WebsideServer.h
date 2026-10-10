#pragma once

#include "Smalltalk/Inspector.h"
#include "Session.h"
#include "../WebsideServer.h"

namespace smalltalk {

/** A smalltalk::WebsideServer serves a Smalltalk VM. It adds the routes
 *  about objects every dialect has, such as what keeps an object alive, and
 *  answers them from the session's Smalltalk inspector. **/
class WebsideServer : public webside::WebsideServer {
public:
    using webside::WebsideServer::WebsideServer;

protected:
    /** Returns the session's Smalltalk inspector, or null when the session's
     *  inspector is not a Smalltalk one. It stays valid while the session is
     *  open. **/
    Inspector* smalltalkInspector() const;

    void setupRoutes() override;
};

} // namespace smalltalk
