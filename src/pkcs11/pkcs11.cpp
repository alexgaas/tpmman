#include "pkcs11.h"
#include "../tpm/tpm.h"
#include "../util/logger.h"
#include <memory>
#include <functional>

namespace {
    auto kConfigPath = "configs/config.yml";

    std::unique_ptr<tpmman::TPM> g_tpm = nullptr;

    CK_RV initialize() {
        if (!g_tpm) {
            auto cfg = tpmman::Config::FromFile(kConfigPath);
            tpmman::InitLogger(cfg.Debug);
            g_tpm = std::make_unique<tpmman::TPM>(cfg);
        }

        return CKR_OK;
    }

    CK_RV wrapCall(const std::string &name, const std::function<CK_RV()> &f) {
        auto& logger = tpmman::GetLogger("pkcs11");
        try {
            logger.debug("tpmman: called " + name + "()");

            return f();
        } catch (const std::exception &e) {
            logger.error("tpmman: " + name + "() fail: " + std::string(e.what()));
        } catch (...) {
            logger.error("tpmman: " + name + "() fail: unknown");
        }
        return CKR_FUNCTION_FAILED;
    }
}

extern "C" {

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    auto& logger = tpmman::GetLogger("pkcs11");
    try {
        CK_RV ret = initialize();
        if (ret != CKR_OK) {
            return ret;
        }
    } catch (const std::exception &e) {
        logger.error("tpmman: initialize fail: " + std::string(e.what()));
        return CKR_FUNCTION_FAILED;
    }

    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->Initialize(pInitArgs);
    });
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->Finalize(pReserved);
    });
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->GetInfo(pInfo);
    });
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pusCount) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->GetSlotList(tokenPresent, pSlotList, pusCount);
    });
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->GetSlotInfo(slotID, pInfo);
    });
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    return wrapCall(__func__, [&]() -> CK_RV {
        CK_RV ret = g_tpm->GetTokenInfo(slotID, pInfo);
        if (ret != CKR_OK) {
            return ret;
        }

        g_tpm->MapSavedToken(slotID, pInfo);
        return CKR_OK;
    });
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pusCount) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->GetMechanismList(slotID, pMechanismList, pusCount);
    });
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->GetMechanismInfo(slotID, type, pInfo);
    });
}

CK_RV C_InitToken(CK_SLOT_ID /*slotID*/, CK_CHAR_PTR /*pPin*/, CK_ULONG /*usPinLen*/, CK_CHAR_PTR /*pLabel*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_InitToken()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE /*hSession*/, CK_CHAR_PTR /*pPin*/, CK_ULONG /*usPinLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_InitPIN()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE /*hSession*/, CK_CHAR_PTR /*pOldPin*/, CK_ULONG /*usOldLen*/, CK_CHAR_PTR /*pNewPin*/,
               CK_ULONG /*usNewLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_SetPIN()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify,
                    CK_SESSION_HANDLE_PTR phSession) {
    return wrapCall(__func__, [&]() -> CK_RV {
        CK_RV ret = g_tpm->OpenSession(slotID, flags, pApplication, notify, phSession);
        if (ret != CKR_OK) {
            return ret;
        }

        const std::string &pin = g_tpm->UserPin(slotID);
        if (pin.empty()) {
            return ret;
        }

        return g_tpm->Login(*phSession, CKU_USER, (CK_UTF8CHAR_PTR) pin.data(), pin.size());
    });
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->CloseSession(hSession);
    });
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->CloseAllSessions(slotID);
    });
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->GetSessionInfo(hSession, pInfo);
    });
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pOperationState*/, CK_ULONG_PTR /*pulOperationStateLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_GetOperationState()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pOperationState*/, CK_ULONG /*ulOperationStateLen*/,
                          CK_OBJECT_HANDLE /*hEncryptionKey*/, CK_OBJECT_HANDLE /*hAuthenticationKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_SetOperationState()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG usPinLen) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->Login(hSession, userType, pPin, usPinLen);
    });
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->Logout(hSession);
    });
}

CK_RV C_CreateObject(CK_SESSION_HANDLE /*hSession*/, CK_ATTRIBUTE_PTR /*pTemplate*/, CK_ULONG /*usCount*/,
                     CK_OBJECT_HANDLE_PTR /*phObject*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_CreateObject()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE /*hSession*/, CK_OBJECT_HANDLE /*hObject*/, CK_ATTRIBUTE_PTR /*pTemplate*/, CK_ULONG /*usCount*/,
                   CK_OBJECT_HANDLE_PTR /*phNewObject*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_CopyObject()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE /*hSession*/, CK_OBJECT_HANDLE /*hObject*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DestroyObject()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE /*hSession*/, CK_OBJECT_HANDLE /*hObject*/, CK_ULONG_PTR /*pusSize*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_GetObjectSize()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG usCount) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->GetAttributeValue(hSession, hObject, pTemplate, usCount);
    });
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE /*hSession*/, CK_OBJECT_HANDLE /*hObject*/, CK_ATTRIBUTE_PTR /*pTemplate*/,
                          CK_ULONG /*usCount*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_SetAttributeValue()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->FindObjectsInit(hSession, pTemplate, usCount);
    });
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG usMaxObjectCount,
                    CK_ULONG_PTR pusObjectCount) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->FindObjects(hSession, phObject, usMaxObjectCount, pusObjectCount);
    });
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->FindObjectsFinal(hSession);
    });
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_EncryptInit()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pData*/, CK_ULONG /*usDataLen*/, CK_BYTE_PTR /*pEncryptedData*/,
                CK_ULONG_PTR /*pusEncryptedDataLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_Encrypt()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pPart*/, CK_ULONG /*usPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/,
                      CK_ULONG_PTR /*pusEncryptedPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_EncryptUpdate()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pLastEncryptedPart*/, CK_ULONG_PTR /*pusLastEncryptedPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_EncryptFinal()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DecryptInit()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pEncryptedData*/, CK_ULONG /*usEncryptedDataLen*/, CK_BYTE_PTR /*pData*/,
                CK_ULONG_PTR /*pusDataLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_Decrypt()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG /*usEncryptedPartLen*/,
                      CK_BYTE_PTR /*pPart*/, CK_ULONG_PTR /*pusPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DecryptUpdate()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pLastPart*/, CK_ULONG_PTR /*pusLastPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DecryptFinal()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DigestInit()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pData*/, CK_ULONG /*usDataLen*/, CK_BYTE_PTR /*pDigest*/,
               CK_ULONG_PTR /*pusDigestLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_Digest()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pPart*/, CK_ULONG /*usPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DigestUpdate()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE /*hSession*/, CK_OBJECT_HANDLE /*hKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DigestKey()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pDigest*/, CK_ULONG_PTR /*pusDigestLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DigestFinal()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->SignInit(hSession, pMechanism, hKey);
    });
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pusSignatureLen) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->Sign(hSession, pData, usDataLen, pSignature, pusSignatureLen);
    });
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG usPartLen) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->SignUpdate(hSession, pPart, usPartLen);
    });
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pusSignatureLen) {
    return wrapCall(__func__, [&]() -> CK_RV {
        return g_tpm->SignFinal(hSession, pSignature, pusSignatureLen);
    });
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_SignRecoverInit()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pData*/, CK_ULONG /*usDataLen*/, CK_BYTE_PTR /*pSignature*/,
                    CK_ULONG_PTR /*pusSignatureLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_SignRecover()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_VerifyInit()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pData*/, CK_ULONG /*usDataLen*/, CK_BYTE_PTR /*pSignature*/,
               CK_ULONG /*usSignatureLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_Verify()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pPart*/, CK_ULONG /*usPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_VerifyUpdate()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pSignature*/, CK_ULONG /*usSignatureLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_VerifyFinal()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_VerifyRecoverInit()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pSignature*/, CK_ULONG /*usSignatureLen*/, CK_BYTE_PTR /*pData*/,
                      CK_ULONG_PTR /*pusDataLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_VerifyRecover()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_DigestEncryptUpdate(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/,
                      CK_ULONG_PTR /*pulEncryptedPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DigestEncryptUpdate()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG /*ulEncryptedPartLen*/,
                            CK_BYTE_PTR /*pPart*/, CK_ULONG_PTR /*pulPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DecryptDigestUpdate()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/,
                          CK_ULONG_PTR /*pulEncryptedPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_SignEncryptUpdate()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG /*ulEncryptedPartLen*/,
                            CK_BYTE_PTR /*pPart*/, CK_ULONG_PTR /*pulPartLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DecryptVerifyUpdate()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_GenerateKey(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_ATTRIBUTE_PTR /*pTemplate*/, CK_ULONG /*usCount*/,
              CK_OBJECT_HANDLE_PTR /*phKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_GenerateKey()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_ATTRIBUTE_PTR /*pPublicKeyTemplate*/,
                        CK_ULONG /*usPublicKeyAttributeCount*/, CK_ATTRIBUTE_PTR /*pPrivateKeyTemplate*/,
                        CK_ULONG /*usPrivateKeyAttributeCount*/, CK_OBJECT_HANDLE_PTR /*phPrivateKey*/,
                        CK_OBJECT_HANDLE_PTR /*phPublicKey*/) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hWrappingKey*/,
                CK_OBJECT_HANDLE /*hKey*/, CK_BYTE_PTR /*pWrappedKey*/, CK_ULONG_PTR /*pusWrappedKeyLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_WrapKey()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hUnwrappingKey*/,
                  CK_BYTE_PTR /*pWrappedKey*/, CK_ULONG /*usWrappedKeyLen*/, CK_ATTRIBUTE_PTR /*pTemplate*/,
                  CK_ULONG /*usAttributeCount*/, CK_OBJECT_HANDLE_PTR /*phKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_UnwrapKey()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE /*hSession*/, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hBaseKey*/,
                  CK_ATTRIBUTE_PTR /*pTemplate*/, CK_ULONG /*usAttributeCount*/, CK_OBJECT_HANDLE_PTR /*phKey*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_DeriveKey()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pSeed*/, CK_ULONG /*usSeedLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_SeedRandom()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE /*hSession*/, CK_BYTE_PTR /*pRandomData*/, CK_ULONG /*usRandomLen*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_GenerateRandom()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE /*hSession*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_GetFunctionStatus()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE /*hSession*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_CancelFunction()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_WaitForSlotEvent(CK_FLAGS /*flags*/, CK_SLOT_ID_PTR /*pSlot*/, CK_VOID_PTR /*pReserved*/) {
    tpmman::GetLogger("pkcs11").warning("tpmman: called not implemented C_WaitForSlotEvent()");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    static CK_FUNCTION_LIST function_list = {
            .version =  {
                    .major =  0,
                    .minor =  0
            },
            .C_Initialize =  C_Initialize,
            .C_Finalize =  C_Finalize,
            .C_GetInfo =  C_GetInfo,
            .C_GetFunctionList =  C_GetFunctionList,
            .C_GetSlotList =  C_GetSlotList,
            .C_GetSlotInfo =  C_GetSlotInfo,
            .C_GetTokenInfo =  C_GetTokenInfo,
            .C_GetMechanismList =  C_GetMechanismList,
            .C_GetMechanismInfo =  C_GetMechanismInfo,
            .C_InitToken = C_InitToken,
            .C_InitPIN = C_InitPIN,
            .C_SetPIN = C_SetPIN,
            .C_OpenSession = C_OpenSession,
            .C_CloseSession = C_CloseSession,
            .C_CloseAllSessions = C_CloseAllSessions,
            .C_GetSessionInfo = C_GetSessionInfo,
            .C_GetOperationState = C_GetOperationState,
            .C_SetOperationState = C_SetOperationState,
            .C_Login = C_Login,
            .C_Logout = C_Logout,
            .C_CreateObject = C_CreateObject,
            .C_CopyObject = C_CopyObject,
            .C_DestroyObject = C_DestroyObject,
            .C_GetObjectSize = C_GetObjectSize,
            .C_GetAttributeValue = C_GetAttributeValue,
            .C_SetAttributeValue = C_SetAttributeValue,
            .C_FindObjectsInit = C_FindObjectsInit,
            .C_FindObjects = C_FindObjects,
            .C_FindObjectsFinal = C_FindObjectsFinal,
            .C_EncryptInit = C_EncryptInit,
            .C_Encrypt = C_Encrypt,
            .C_EncryptUpdate = C_EncryptUpdate,
            .C_EncryptFinal = C_EncryptFinal,
            .C_DecryptInit = C_DecryptInit,
            .C_Decrypt = C_Decrypt,
            .C_DecryptUpdate = C_DecryptUpdate,
            .C_DecryptFinal = C_DecryptFinal,
            .C_DigestInit = C_DigestInit,
            .C_Digest = C_Digest,
            .C_DigestUpdate = C_DigestUpdate,
            .C_DigestKey = C_DigestKey,
            .C_DigestFinal = C_DigestFinal,
            .C_SignInit = C_SignInit,
            .C_Sign = C_Sign,
            .C_SignUpdate = C_SignUpdate,
            .C_SignFinal = C_SignFinal,
            .C_SignRecoverInit = C_SignRecoverInit,
            .C_SignRecover = C_SignRecover,
            .C_VerifyInit = C_VerifyInit,
            .C_Verify = C_Verify,
            .C_VerifyUpdate = C_VerifyUpdate,
            .C_VerifyFinal = C_VerifyFinal,
            .C_VerifyRecoverInit = C_VerifyRecoverInit,
            .C_VerifyRecover = C_VerifyRecover,
            .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
            .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
            .C_SignEncryptUpdate = C_SignEncryptUpdate,
            .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
            .C_GenerateKey = C_GenerateKey,
            .C_GenerateKeyPair = C_GenerateKeyPair,
            .C_WrapKey = C_WrapKey,
            .C_UnwrapKey = C_UnwrapKey,
            .C_DeriveKey = C_DeriveKey,
            .C_SeedRandom = C_SeedRandom,
            .C_GenerateRandom = C_GenerateRandom,
            .C_GetFunctionStatus = C_GetFunctionStatus,
            .C_CancelFunction = C_CancelFunction,
            .C_WaitForSlotEvent = C_WaitForSlotEvent,
    };

    if (ppFunctionList == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &function_list;
    return CKR_OK;
}

}
