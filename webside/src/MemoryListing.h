#pragma once

#include "Json.h"
#include "MemoryTypeMap.h"

#include <smalldbg/Disassembler.h>
#include <smalldbg/DisassemblyAnnotator.h>

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace webside {

using vmdbg::Json;

class WebsideSession;

/** A MemoryListing lays a stretch of target memory out as the rows of a
 *  disassembly view: instructions where the memory types say code, and
 *  values, strings and the VM's layouts elsewhere. **/
class MemoryListing {
public:
    /** Makes a listing in which `labels`, the user's names for addresses,
     *  win over any other name. **/
    MemoryListing(const WebsideSession& session,
                  const std::map<uint64_t, std::string>& labels);
    ~MemoryListing();

    /** Returns the rows for `bytes`, read from `address`. **/
    Json rows(uint64_t address, const std::vector<uint8_t>& bytes);

private:
    std::vector<smalldbg::DisasmInsn> decode(const vmdbg::MemTypeRange& run) const;
    size_t addCode(const vmdbg::MemTypeRange& run, size_t next);
    void addInstruction(size_t index);
    void addData(const vmdbg::MemTypeRange& run);
    void addStrings(const vmdbg::MemTypeRange& run);
    void addLayout(const vmdbg::MemTypeRange& run);
    void addLabel(uint64_t at, const std::string& label);
    std::string dataNote(uint64_t at, size_t size, uint64_t value) const;
    uint64_t valueAt(uint64_t at, size_t size) const;
    std::string bytesAt(uint64_t at, size_t size) const;
    Json address(uint64_t at) const;

    const WebsideSession& session;
    const std::map<uint64_t, std::string>& userLabels;
    std::unique_ptr<smalldbg::AnnotationSource> source;

    uint64_t base{0};
    const std::vector<uint8_t>* memory{nullptr};
    std::vector<smalldbg::DisasmInsn> code;
    std::vector<smalldbg::AnnotatedInstruction> annotated;
    Json out;
    std::set<uint64_t> labelled;
};

} // namespace webside
