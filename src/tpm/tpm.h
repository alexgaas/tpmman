#pragma once

#include <unordered_map>

#include "../pkcs11/pkcs11.h"
#include "../config/config.h"

#include <Poco/SharedLibrary.h>

namespace tpmman {

    class TPM {
    public:
        CK_C_Initialize Initialize{};
        CK_C_Finalize Finalize{};
        CK_C_GetInfo GetInfo{};
        CK_C_GetSlotList GetSlotList{};
        CK_C_GetSlotInfo GetSlotInfo{};
        CK_C_GetTokenInfo GetTokenInfo{};
        CK_C_GetMechanismList GetMechanismList{};
        CK_C_GetMechanismInfo GetMechanismInfo{};
        CK_C_OpenSession OpenSession{};
        CK_C_CloseSession CloseSession{};
        CK_C_CloseAllSessions CloseAllSessions{};
        CK_C_GetSessionInfo GetSessionInfo{};
        CK_C_Login Login{};
        CK_C_Logout Logout{};
        CK_C_GetAttributeValue GetAttributeValue{};
        CK_C_SetAttributeValue SetAttributeValue{};
        CK_C_FindObjectsInit FindObjectsInit{};
        CK_C_FindObjects FindObjects{};
        CK_C_FindObjectsFinal FindObjectsFinal{};
        CK_C_SignInit SignInit{};
        CK_C_Sign Sign{};
        CK_C_SignUpdate SignUpdate{};
        CK_C_SignFinal SignFinal{};

        explicit TPM(const Config& cfg);

        bool MapSavedToken(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

        std::string UserPin(CK_SLOT_ID slotID);

    protected:
        Config cfg;
        Poco::SharedLibrary lib;
        std::unordered_map<CK_SLOT_ID, size_t> slotToSavedTokens{};
    };
}