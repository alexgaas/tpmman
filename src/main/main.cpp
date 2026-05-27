#include <iostream>

#include "../config/config.h"
#include "../util/logger.h"

int main() {
    const tpmman::Config config = tpmman::Config::FromFile("configs/config.yml");

    tpmman::InitLogger(config.Debug);
    auto& logger = tpmman::GetLogger("main");

    logger.information("Debug: " + std::string(config.Debug ? "true" : "false"));
    logger.information("BackendPath: " + config.BackendPath);
    logger.information("SavedTokens count: " + std::to_string(config.SavedTokens.size()));
    if (!config.SavedTokens.empty()) {
        logger.information("  First Token Label: " + config.SavedTokens[0].Label);
    }

    return 0;
}
