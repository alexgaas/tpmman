#include "config.h"
#include <yaml-cpp/yaml.h>
#include <Poco/File.h>
#include <Poco/Exception.h>
#include "../util/logger.h"

namespace YAML {
    template<>
    struct convert<tpmman::SavedToken> {
        static bool decode(const Node& node, tpmman::SavedToken& rhs) {
            if (!node.IsMap() || !node["label"] || !node["userpin"]) {
                return false;
            }
            rhs.Label = node["label"].as<std::string>();
            rhs.UserPin = node["userpin"].as<std::string>();
            return true;
        }
    };
}

namespace tpmman {
    namespace {
#ifdef __APPLE__
        // libsofthsm2.dylib
        auto defaultBackendPath = "/opt/homebrew/lib/libtpm2_pkcs11.dylib";
#else
        auto defaultBackendPath = "/usr/lib64/pkcs11/libtpm2_pkcs11.so.0.0.0";
#endif
    }

    Config Config::FromFile(const std::string &filepath) {
        if (const Poco::File file(filepath); !file.exists()) {
            throw Poco::FileNotFoundException(filepath);
        }

        YAML::Node node = YAML::LoadFile(filepath);

        Config cfg;
        cfg.Debug = node["debug"] && node["debug"].as<bool>();
        cfg.BackendPath = defaultBackendPath;
        
        if (node["backend"]) {
            cfg.BackendPath = node["backend"].as<std::string>();
        }

        if (node["saved_tokens"]) {
            cfg.SavedTokens = node["saved_tokens"].as<std::vector<SavedToken>>();
        }

        // We can't use GetLogger here safely if InitLogger hasn't been called, 
        // but Poco::Logger::get will still work (it just might not have the right channel yet).
        Poco::Logger::get("config").debug("Loaded configuration from " + filepath);

        return cfg;
    }
}
