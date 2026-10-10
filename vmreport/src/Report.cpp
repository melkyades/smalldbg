#include "Report.h"

#include <Setup.h>
#include <Target.h>
#include <smalldbg/Arch.h>
#include <smalldbg/Debugger.h>
#include <smalldbg/Process.h>
#include <smalldbg/StackTrace.h>
#include <smalldbg/Thread.h>
#include <smalldbg/symbols/SymbolLoader.h>
#include <smalldbg/symbols/SymbolProvider.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <sstream>

namespace vmreport {

namespace {

// A target that was debugged before has its setup beside it, which says where
// its symbols were found.
std::string symbolPathsBeside(const std::string& target) {
    vmdbg::Setup setup;
    return setup.load(target + ".workspace.json") ? setup.symbolSearchPath()
                                                  : std::string();
}

} // namespace

bool parseCommandLine(int argc, char* argv[], Options& options) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <dump.dmp | trace.run>"
                     " [-o <report.txt>] [--symbols <dirs>] [--source <dir>]\n";
        return false;
    }
    options.target = argv[1];
    options.output = options.target + ".report.txt";
    for (int i = 2; i + 1 < argc; i++) {
        std::string flag = argv[i];
        if (flag == "-o") options.output = argv[i + 1];
        if (flag == "--symbols") options.symbols = argv[i + 1];
        if (flag == "--source") options.sources = argv[i + 1];
    }
    if (options.symbols.empty())
        options.symbols = symbolPathsBeside(options.target);
    return true;
}

bool openTarget(smalldbg::Debugger& debugger, const Options& options,
                const vmdbg::VMModule& vm) {
    // Before opening: a dump or a trace resolves its modules while opening,
    // and by then the engine has already decided where it looked.
    smalldbg::SymbolLoader symbols(debugger, [](const std::string& message) {
        std::cerr << "  [vm] " << message << std::endl;
    });
    symbols.setSearchPath(options.symbols);

    vmdbg::TargetSpec spec;
    spec.kind = vmdbg::targetKindFor(options.target);
    spec.path = options.target;
    if (vmdbg::openInEngine(debugger, spec) != smalldbg::Status::Ok) {
        std::cerr << "could not open " << options.target << "\n";
        return false;
    }

    // A dump or a trace arrives with every module deferred, and the inspector
    // is built entirely on the VM's own symbols, so they have to be in before
    // anything it reports is true. They usually sit beside the target, which
    // is not a directory the engine would search on its own.
    symbols.useSymbolsBeside(options.target);
    smalldbg::SymbolState state = symbols.load(vm.name);
    if (state == smalldbg::SymbolState::Missing && !vm.needsSymbolFile)
        std::cerr << "  [vm] no symbol file for " << vm.name << ", which is no"
                     " obstacle here: the globals this reads are exported.\n";
    else if (!symbols.report(vm.name, state, vm.note))
        return false;
    symbols.reportModules();
    return true;
}

std::string hex(uint64_t v, int width) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(width) << std::setfill('0') << v;
    return out.str();
}

void heading(std::ostream& out, const std::string& title) {
    out << "\n" << title << "\n" << std::string(title.size(), '=') << "\n\n";
}

namespace {

// The registers come first and the name last, because a reader scanning a
// backtrace goes down the names: a column that begins in a different place on
// every line cannot be scanned at all, and the addresses are what one stops to
// read once a name has been found.
void writeFrame(std::ostream& out, const smalldbg::StackFrame& frame,
                size_t n, int digits) {
    std::ostringstream registers;
    registers << "  " << std::setw(3) << std::setfill(' ') << n << "  "
              << hex(frame.ip(), digits) << "  "
              << hex(frame.fp(), digits) << "  "
              << hex(frame.sp(), digits) << "  ";
    out << registers.str();

    if (!frame.moduleName.empty()) out << frame.moduleName << "!";
    out << (frame.functionName.empty() ? "<unknown>" : frame.functionName);
    if (frame.functionOffset)
        out << "+0x" << std::hex << frame.functionOffset << std::dec;
    if (frame.inlined) out << "  (inlined)";
    out << "\n";

    // Under the name it belongs to rather than at the margin, so it reads as
    // part of the frame and not as another one.
    if (!frame.sourceFile.empty())
        out << std::string(registers.str().size(), ' ')
            << frame.sourceFile << ":" << frame.sourceLine << "\n";
}

// Named columns, because three bare hex numbers in a row are not self
// describing and the alignment is only useful if the reader knows what lines
// up with what.
void writeFrameHeadings(std::ostream& out, int digits) {
    int column = digits + 2;  // the "0x" a hex value is written with
    out << "  " << std::setw(3) << std::setfill(' ') << "#" << "  "
        << std::left << std::setw(column) << "ip" << "  "
        << std::setw(column) << "fp" << "  "
        << std::setw(column) << "sp" << "  " << "frame\n" << std::right;
}

void writeModules(std::ostream& out, smalldbg::Debugger& debugger, int digits) {
    auto modules = debugger.getSymbolProvider()->getModules();
    heading(out, "Modules (" + std::to_string(modules.size()) + ")");
    std::sort(modules.begin(), modules.end(),
              [](const smalldbg::ModuleInfo& a, const smalldbg::ModuleInfo& b) {
                  return a.loadAddress < b.loadAddress;
              });
    for (const auto& module : modules)
        out << "  " << hex(module.loadAddress, digits) << " - "
            << hex(module.endAddress, digits)
            << "  " << module.shortName << "\n";
}

// Three to a row, and the row ends after the last one on it rather than
// before the next: separating afterwards leaves an indent hanging under the
// block with nothing on it, which reads as a register whose name was lost.
void writeNamedValues(std::ostream& out,
                             const std::pair<const char*, uint64_t>* named,
                             size_t count, int digits) {
    const size_t perRow = 3;
    for (size_t i = 0; i < count; i++) {
        out << (i % perRow == 0 ? "    " : "  ")
            << named[i].first << "=" << hex(named[i].second, digits);
        if ((i + 1) % perRow == 0 || i + 1 == count) out << "\n";
    }
}

void writeRegisters(std::ostream& out, const smalldbg::Registers& regs) {
    const int digits = static_cast<int>(regs.pointerSize()) * 2;

    // A 32-bit target keeps its state in the other set, and printing the wrong
    // one gives a column of zeros that reads like a corrupt thread.
    if (regs.pointerSize() == 4) {
        const auto& r = regs.x86;
        const std::pair<const char*, uint64_t> named[] = {
            {"eip", r.eip}, {"esp", r.esp}, {"ebp", r.ebp},
            {"eax", r.eax}, {"ebx", r.ebx}, {"ecx", r.ecx}, {"edx", r.edx},
            {"esi", r.esi}, {"edi", r.edi},
        };
        writeNamedValues(out, named, std::size(named), digits);
        return;
    }

    const auto& r = regs.x64;
    const std::pair<const char*, uint64_t> named[] = {
        {"rip", r.rip}, {"rsp", r.rsp}, {"rbp", r.rbp},
        {"rax", r.rax}, {"rbx", r.rbx}, {"rcx", r.rcx}, {"rdx", r.rdx},
        {"rsi", r.rsi}, {"rdi", r.rdi},
        {"r8 ", r.r8},  {"r9 ", r.r9},  {"r10", r.r10}, {"r11", r.r11},
        {"r12", r.r12}, {"r13", r.r13}, {"r14", r.r14}, {"r15", r.r15},
    };
    writeNamedValues(out, named, std::size(named), digits);
}

// Returns the exception the target stopped on, or the stop reason when it
// stopped on none.
std::string stopText(smalldbg::Debugger& debugger) {
    auto exception = debugger.getStopException();
    if (!exception) return smalldbg::stopReasonName(debugger.getStopReason());

    std::ostringstream text;
    text << "exception 0x" << std::hex << exception->code
         << " at 0x" << exception->address;
    for (size_t i = 0; i < exception->parameters.size(); ++i)
        text << " [" << i << "]=0x" << exception->parameters[i];
    if (!exception->description.empty())
        text << ": " << exception->description;
    return text.str();
}

} // namespace

void writeReport(smalldbg::Debugger& debugger, const std::string& target,
                 const std::function<void(std::ostream&)>& vmSection,
                 std::ostream& out) {
    // A pointer is as wide as the target makes it, not as wide as whatever
    // recorded it. Padding a 32-bit address out to a 64-bit column buries the
    // eight digits that vary under eight that never do, which is most of why
    // a backtrace reads badly.
    const int digits = static_cast<int>(debugger.arch()->pointerSize()) * 2;

    out << "vmreport: " << target << "\n";

    heading(out, "Why it stopped");
    out << "  " << stopText(debugger) << "\n";

    writeModules(out, debugger, digits);

    auto process = debugger.getProcess();
    auto threads = process ? process->threads()
                           : std::vector<std::shared_ptr<smalldbg::Thread>>{};
    vmSection(out);

    heading(out, "Native threads (" + std::to_string(threads.size()) + ")");
    for (size_t i = 0; i < threads.size(); i++) {
        smalldbg::Thread& thread = *threads[i];
        out << "Thread " << (i + 1) << "  id=0x" << std::hex
            << thread.getThreadId() << std::dec << "\n";

        smalldbg::Registers regs;
        if (debugger.getRegisters(&thread, regs) == smalldbg::Status::Ok)
            writeRegisters(out, regs);

        auto* trace = thread.getStackTrace(256);
        if (!trace) {
            out << "  (could not unwind)\n\n";
            continue;
        }
        const auto& frames = trace->getFrames();
        out << "\n  " << frames.size() << " frames\n";
        writeFrameHeadings(out, digits);
        for (size_t f = 0; f < frames.size(); f++)
            writeFrame(out, *frames[f], f + 1, digits);
        out << "\n";
    }
}

std::unique_ptr<smalldbg::Debugger> makeDebugger(const Options& options,
                                                 const smalldbg::Arch* arch) {
    auto debugger = std::make_unique<smalldbg::Debugger>(
        smalldbg::Mode::External, arch,
        vmdbg::debuggeeFor(vmdbg::targetKindFor(options.target)));
    debugger->setLogCallback([](const std::string& message) {
        std::cerr << "  [engine] " << message << std::endl;
    });
    return debugger;
}

int writeReportFile(smalldbg::Debugger& debugger, const Options& options,
                    const std::function<void(std::ostream&)>& vmSection) {
    std::ofstream file(options.output);
    if (!file) {
        std::cerr << "could not write " << options.output << "\n";
        return 1;
    }
    writeReport(debugger, options.target, vmSection, file);
    std::cout << "wrote " << options.output << "\n";
    return 0;
}

} // namespace vmreport
