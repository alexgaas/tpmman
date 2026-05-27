#include "tpm.h"
#include "../util/logger.h"

namespace tpmman {
    namespace {
        std::string Strip(const std::string& s) {
            const auto last = s.find_last_not_of(' ');
            if (last == std::string::npos) return "";
            return s.substr(0, last + 1);
        }
    }

    TPM::TPM(const Config& cfg) : cfg(cfg), lib(cfg.BackendPath) {
        auto& logger = GetLogger("tpm");
        logger.debug("Initializing TPM with backend: " + cfg.BackendPath);

        Initialize = reinterpret_cast<CK_C_Initialize>(lib.getSymbol("C_Initialize"));
        Finalize = reinterpret_cast<CK_C_Finalize>(lib.getSymbol("C_Finalize"));
        GetInfo = reinterpret_cast<CK_C_GetInfo>(lib.getSymbol("C_GetInfo"));
        GetSlotList = reinterpret_cast<CK_C_GetSlotList>(lib.getSymbol("C_GetSlotList"));
        GetSlotInfo = reinterpret_cast<CK_C_GetSlotInfo>(lib.getSymbol("C_GetSlotInfo"));
        GetTokenInfo = reinterpret_cast<CK_C_GetTokenInfo>(lib.getSymbol("C_GetTokenInfo"));
        GetMechanismList = reinterpret_cast<CK_C_GetMechanismList>(lib.getSymbol("C_GetMechanismList"));
        GetMechanismInfo = reinterpret_cast<CK_C_GetMechanismInfo>(lib.getSymbol("C_GetMechanismInfo"));
        OpenSession = reinterpret_cast<CK_C_OpenSession>(lib.getSymbol("C_OpenSession"));
        CloseSession = reinterpret_cast<CK_C_CloseSession>(lib.getSymbol("C_CloseSession"));
        CloseAllSessions = reinterpret_cast<CK_C_CloseAllSessions>(lib.getSymbol("C_CloseAllSessions"));
        GetSessionInfo = reinterpret_cast<CK_C_GetSessionInfo>(lib.getSymbol("C_GetSessionInfo"));
        Login = reinterpret_cast<CK_C_Login>(lib.getSymbol("C_Login"));
        Logout = reinterpret_cast<CK_C_Logout>(lib.getSymbol("C_Logout"));
        GetAttributeValue = reinterpret_cast<CK_C_GetAttributeValue>(lib.getSymbol("C_GetAttributeValue"));
        SetAttributeValue = reinterpret_cast<CK_C_SetAttributeValue>(lib.getSymbol("C_SetAttributeValue"));
        FindObjectsInit = reinterpret_cast<CK_C_FindObjectsInit>(lib.getSymbol("C_FindObjectsInit"));
        FindObjects = reinterpret_cast<CK_C_FindObjects>(lib.getSymbol("C_FindObjects"));
        FindObjectsFinal = reinterpret_cast<CK_C_FindObjectsFinal>(lib.getSymbol("C_FindObjectsFinal"));
        SignInit = reinterpret_cast<CK_C_SignInit>(lib.getSymbol("C_SignInit"));
        Sign = reinterpret_cast<CK_C_Sign>(lib.getSymbol("C_Sign"));
        SignUpdate = reinterpret_cast<CK_C_SignUpdate>(lib.getSymbol("C_SignUpdate"));
        SignFinal = reinterpret_cast<CK_C_SignFinal>(lib.getSymbol("C_SignFinal"));
    }

    bool TPM::MapSavedToken(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
        auto& logger = GetLogger("tpm");
        if (pInfo == nullptr) {
            logger.error("MapSavedToken: pInfo is null");
            return false;
        }

        const auto label = Strip(std::string{reinterpret_cast<char *>(pInfo->label), sizeof(static_cast<CK_TOKEN_INFO *>(nullptr)->label)});
        logger.debug("Mapping token with label: " + label);

        for (size_t i = 0; i < cfg.SavedTokens.size(); ++i) {
            if (label == cfg.SavedTokens[i].Label) {
                logger.information("Found saved token for label: " + label + " at slot: " + std::to_string(slotID));
                slotToSavedTokens[slotID] = i;
                pInfo->flags &= CKF_PROTECTED_AUTHENTICATION_PATH;
                return true;
            }
        }

        logger.warning("No saved token found for label: " + label);
        return false;
    }

    std::string TPM::UserPin(CK_SLOT_ID slotID) {
        if (!slotToSavedTokens.contains(slotID)) {
            return std::string{};
        }

        return cfg.SavedTokens[slotToSavedTokens[slotID]].UserPin;
    }
}