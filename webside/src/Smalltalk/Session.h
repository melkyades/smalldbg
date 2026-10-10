#pragma once

#include "Smalltalk/Inspector.h"
#include "WebsideSession.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace smalltalk {

/** A smalltalk::Session is the Webside session of a Smalltalk VM. It answers
 *  the class-browsing and search parts of the Webside API from the
 *  inspector's class table and methods, the same way for every dialect. A
 *  dialect's subclass covers what its VM does its own way, such as where the
 *  heap is and what a frame holds. **/
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
    std::string getSelectors(const std::string& name) const override;
    std::string getMethods(const std::string& name) const override;
    std::string getMethod(const std::string& className,
                          const std::string& selector) const override;
    std::string search(const std::string& text, bool ignoreCase,
                       const std::string& condition,
                       const std::string& type) const override;

    std::string describeObject(uint64_t oop, int firstSlot,
                               int maxSlots) const override;

    /** Returns a source that names a word pointing into object memory by
     *  what its object prints as, and anything else by native symbol. **/
    std::unique_ptr<smalldbg::AnnotationSource> annotationSource() const override;

    // ---- green threads: none unless the dialect has them -------------------
    /** Reads the VM's processes again when the target has moved since they
     *  were last read, and otherwise leaves them. **/
    void refreshGreenThreads() final;
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

    /** Adds the class and the method a frame is running, with the method's
     *  source, and what self is. **/
    void addSmalltalkFrameDetail(webside::Json& json,
                                 const smalldbg::StackFrame& frame) const override;

    /** Reads the VM's processes. The session calls this the first time they
     *  are asked for after the target moved. Returns false when they cannot
     *  be read, so that the next request tries again. **/
    virtual bool readGreenThreads() { return true; }

    /** Returns one class in the shape the Webside client expects. A dialect
     *  that knows more about its classes adds it. **/
    virtual webside::Json classJson(const ClassEntry& entry) const;

    /** Returns one method, with its source, in the shape the Webside client
     *  expects. A dialect that knows more about its methods adds it. **/
    virtual webside::Json methodJson(const MethodEntry& method) const;

    /** Adds to `json` what the dialect's header says about the heap object
     *  at `oop`, such as its hash and flags. The base adds nothing. **/
    virtual void describeHeader(webside::Json& /*json*/,
                                uint64_t /*oop*/) const {}

    /** Returns the class definition as source, which a browser shows above
     *  the methods. **/
    static std::string classDefinition(const ClassEntry& entry);

    /** Returns true for a metaclass name, such as "Object class". **/
    static bool isMetaclassName(const std::string& name);

    /** Returns the class table's entry for `name`, or for a metaclass the
     *  table does not hold, one made from its class. Returns nothing when
     *  neither is there. **/
    std::optional<ClassEntry> entryNamed(const std::string& name) const;

private:
    webside::Json classTreeJson(const std::string& name, bool namesOnly,
                                int depth) const;
    std::string rootClassName() const;
    std::vector<std::string> categoriesOf(const std::string& name) const;
    void addClassVariables(webside::Json& array,
                           const std::string& name) const;
    std::string printed(uint64_t oop) const;

    std::optional<uint64_t> greenThreadsVersion;  // stateVersion they are from
};

} // namespace smalltalk
