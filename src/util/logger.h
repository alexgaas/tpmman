#pragma once

#include <string>
#include <Poco/Logger.h>

namespace tpmman {
    void InitLogger(bool debug);
    Poco::Logger& GetLogger(const std::string& name);
}
