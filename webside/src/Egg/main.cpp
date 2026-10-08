#include "EggWebsideServer.h"
#include "EggDebugSession.h"
#include "Main.h"

// Egg is an interpreter this launches and then reads: there is no process to
// attach to, and no dump or trace of one to open.
int main(int argc, char** argv) {
    webside::DialectInfo egg;
    egg.name = "egg";
    egg.targetSyntax = "<egg_exe>";
    egg.opensAttach = false;
    egg.opensDump = false;
    egg.opensTrace = false;
    return webside::runWebside<webside::EggWebsideServer>(
        argc, argv,
        [](const vmdbg::TargetSpec&) {
            return std::make_unique<webside::EggDebugSession>();
        }, egg);
}
