#pragma once

#include <string>
#include <vector>

namespace tpmman {
    struct SavedToken {
        std::string Label;
        std::string UserPin;
    };

    class Config {
    public:
        bool Debug;
        std::string BackendPath;
        std::vector<SavedToken> SavedTokens;

        static Config FromFile(const std::string &filepath);
    };
}
