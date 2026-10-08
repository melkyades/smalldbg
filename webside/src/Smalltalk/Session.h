#pragma once

#include "Smalltalk/Inspector.h"
#include "WebsideSession.h"

#include <memory>
#include <string>

namespace smalltalk {

/** A smalltalk::Session is the Webside session of a Smalltalk VM. It answers
 *  the class-browsing part of the Webside API from the inspector's class
 *  table, the same way for every dialect. A dialect's subclass covers what its
 *  VM does its own way, such as where the heap is and what a frame holds. **/
class Session : public webside::WebsideSession {
public:
    bool isActive() const override;
    std::optional<int> getPid() const override;
    std::string getStopReason() const override;

    // ---- class browsing ----------------------------------------------------
    bool discoverClasses() override;
    std::string listClasses(const std::string& root, bool namesOnly,
                            bool tree, int depth) const override;
    std::string getClass(const std::string& name) const override;
    std::string getSubclasses(const std::string& name) const override;
    std::string getSuperclasses(const std::string& name) const override;
    std::string getVariables(const std::string& name) const override;
    std::string getInstanceVariables(const std::string& name) const override;
    std::string getClassVariables(const std::string& name) const override;
    std::string getCategories(const std::string& name) const override;
    std::string getUsedCategories(const std::string& name) const override;

    // ---- green threads: none unless the dialect has them -------------------
    void refreshGreenThreads() override {}
    int greenThreadCount() const override { return 0; }
    std::string getGreenThreadName(int) const override { return {}; }
    std::string listSmalltalkFrames(int) const override { return "[]"; }
    std::string getSmalltalkFrameDetail(int, int) const override {
        return "{}";
    }
    std::string getSmalltalkFrameBindings(int, int) const override {
        return "[]";
    }
    std::string getSmalltalkStackContents(int, int) const override {
        return "[]";
    }

protected:
    /** Returns the dialect's inspector, which holds the class table. **/
    virtual Inspector& smalltalkInspector() const = 0;

    /** Returns one class in the shape the Webside client expects. **/
    webside::Json classJson(const ClassEntry& entry) const;

    /** Returns the class definition as source, which a browser shows above
     *  the methods. **/
    static std::string classDefinition(const ClassEntry& entry);

    /** Returns true for a metaclass name, such as "Object class". **/
    static bool isMetaclassName(const std::string& name);

private:
    webside::Json classTreeJson(const std::string& name, bool namesOnly,
                                int depth) const;
    std::string rootClassName() const;
};

} // namespace smalltalk
