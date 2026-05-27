#include "logger.h"
#include <Poco/ConsoleChannel.h>
#include <Poco/FormattingChannel.h>
#include <Poco/PatternFormatter.h>
#include <Poco/AutoPtr.h>

namespace tpmman {
    void InitLogger(const bool debug) {
        const Poco::AutoPtr pCons(new Poco::ConsoleChannel);
        Poco::AutoPtr pPF(new Poco::PatternFormatter);
        pPF->setProperty("pattern", "%Y-%m-%d %H:%M:%S [%p] %s: %t");
        const Poco::AutoPtr pFC(new Poco::FormattingChannel(pPF, pCons));
        Poco::Logger::root().setChannel(pFC);
        Poco::Logger::root().setLevel(debug ? Poco::Message::PRIO_DEBUG : Poco::Message::PRIO_INFORMATION);
    }

    Poco::Logger& GetLogger(const std::string& name) {
        return Poco::Logger::get(name);
    }
}
