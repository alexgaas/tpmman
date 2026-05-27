import ctypes
import os
import platform

# PKCS#11 Types
CK_ULONG = ctypes.c_ulong
CK_RV = CK_ULONG
CK_SLOT_ID = CK_ULONG
CK_SESSION_HANDLE = CK_ULONG
CK_FLAGS = CK_ULONG
CK_BYTE = ctypes.c_ubyte
CK_CHAR = ctypes.c_char
CK_UTF8CHAR = ctypes.c_ubyte
CK_BBOOL = ctypes.c_ubyte
CK_VOID_PTR = ctypes.c_void_p
CK_OBJECT_HANDLE = CK_ULONG
CK_USER_TYPE = CK_ULONG
CK_MECHANISM_TYPE = CK_ULONG
CK_ATTRIBUTE_TYPE = CK_ULONG

# Constants
CKR_OK = 0x00000000
CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002
CKU_SO = 0
CKU_USER = 1

class CK_VERSION(ctypes.Structure):
    _fields_ = [
        ("major", CK_BYTE),
        ("minor", CK_BYTE),
    ]

class CK_INFO(ctypes.Structure):
    _fields_ = [
        ("cryptokiVersion", CK_VERSION),
        ("manufacturerID", CK_CHAR * 32),
        ("flags", CK_FLAGS),
        ("libraryDescription", CK_CHAR * 32),
        ("libraryVersion", CK_VERSION),
    ]

class CK_SLOT_INFO(ctypes.Structure):
    _fields_ = [
        ("slotDescription", CK_CHAR * 64),
        ("manufacturerID", CK_CHAR * 32),
        ("flags", CK_FLAGS),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
    ]

class CK_TOKEN_INFO(ctypes.Structure):
    _fields_ = [
        ("label", CK_CHAR * 32),
        ("manufacturerID", CK_CHAR * 32),
        ("model", CK_CHAR * 16),
        ("serialNumber", CK_CHAR * 16),
        ("flags", CK_FLAGS),
        ("ulMaxSessionCount", CK_ULONG),
        ("ulSessionCount", CK_ULONG),
        ("ulMaxRwSessionCount", CK_ULONG),
        ("ulRwSessionCount", CK_ULONG),
        ("ulMaxPinLen", CK_ULONG),
        ("ulMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG),
        ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG),
        ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
        ("utcTime", CK_CHAR * 16),
    ]

class CK_SESSION_INFO(ctypes.Structure):
    _fields_ = [
        ("slotID", CK_SLOT_ID),
        ("state", CK_ULONG),
        ("flags", CK_FLAGS),
        ("ulDeviceError", CK_ULONG),
    ]

class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("type", CK_ATTRIBUTE_TYPE),
        ("pValue", CK_VOID_PTR),
        ("ulValueLen", CK_ULONG),
    ]

class CK_MECHANISM(ctypes.Structure):
    _fields_ = [
        ("mechanism", CK_MECHANISM_TYPE),
        ("pParameter", CK_VOID_PTR),
        ("ulParameterLen", CK_ULONG),
    ]

class TpmManPKCS11:
    def __init__(self, lib_path=None):
        if lib_path is None:
            if platform.system() == "Darwin":
                lib_path = os.path.join(os.path.dirname(__file__), "../build/libtpmman.dylib")
            else:
                lib_path = os.path.join(os.path.dirname(__file__), "../build/libtpmman.so")
        
        self.lib = ctypes.CDLL(lib_path)
        self._setup_functions()

    def _setup_functions(self):
        self.lib.C_Initialize.argtypes = [CK_VOID_PTR]
        self.lib.C_Initialize.restype = CK_RV

        self.lib.C_Finalize.argtypes = [CK_VOID_PTR]
        self.lib.C_Finalize.restype = CK_RV

        self.lib.C_GetInfo.argtypes = [ctypes.POINTER(CK_INFO)]
        self.lib.C_GetInfo.restype = CK_RV

        self.lib.C_GetSlotList.argtypes = [CK_BBOOL, ctypes.POINTER(CK_SLOT_ID), ctypes.POINTER(CK_ULONG)]
        self.lib.C_GetSlotList.restype = CK_RV

        self.lib.C_GetSlotInfo.argtypes = [CK_SLOT_ID, ctypes.POINTER(CK_SLOT_INFO)]
        self.lib.C_GetSlotInfo.restype = CK_RV

        self.lib.C_GetTokenInfo.argtypes = [CK_SLOT_ID, ctypes.POINTER(CK_TOKEN_INFO)]
        self.lib.C_GetTokenInfo.restype = CK_RV

        self.lib.C_OpenSession.argtypes = [CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, ctypes.POINTER(CK_SESSION_HANDLE)]
        self.lib.C_OpenSession.restype = CK_RV

        self.lib.C_CloseSession.argtypes = [CK_SESSION_HANDLE]
        self.lib.C_CloseSession.restype = CK_RV

        self.lib.C_Login.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, ctypes.POINTER(CK_UTF8CHAR), CK_ULONG]
        self.lib.C_Login.restype = CK_RV

        self.lib.C_Logout.argtypes = [CK_SESSION_HANDLE]
        self.lib.C_Logout.restype = CK_RV

        self.lib.C_FindObjectsInit.argtypes = [CK_SESSION_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG]
        self.lib.C_FindObjectsInit.restype = CK_RV

        self.lib.C_FindObjects.argtypes = [CK_SESSION_HANDLE, ctypes.POINTER(CK_OBJECT_HANDLE), CK_ULONG, ctypes.POINTER(CK_ULONG)]
        self.lib.C_FindObjects.restype = CK_RV

        self.lib.C_GetSessionInfo.argtypes = [CK_SESSION_HANDLE, ctypes.POINTER(CK_SESSION_INFO)]
        self.lib.C_GetSessionInfo.restype = CK_RV

        self.lib.C_GetAttributeValue.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG]
        self.lib.C_GetAttributeValue.restype = CK_RV

        self.lib.C_SignInit.argtypes = [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE]
        self.lib.C_SignInit.restype = CK_RV

        self.lib.C_Sign.argtypes = [CK_SESSION_HANDLE, ctypes.POINTER(CK_BYTE), CK_ULONG, ctypes.POINTER(CK_BYTE), ctypes.POINTER(CK_ULONG)]
        self.lib.C_Sign.restype = CK_RV

    def get_session_info(self, handle):
        info = CK_SESSION_INFO()
        rv = self.lib.C_GetSessionInfo(handle, ctypes.byref(info))
        return rv, info

    def find_objects(self, handle, template):
        attr_array = (CK_ATTRIBUTE * len(template))()
        for i, (attr_type, value) in enumerate(template.items()):
            attr_array[i].type = attr_type
            if isinstance(value, int):
                val_ptr = ctypes.pointer(CK_ULONG(value))
                attr_array[i].pValue = ctypes.cast(val_ptr, CK_VOID_PTR)
                attr_array[i].ulValueLen = ctypes.sizeof(CK_ULONG)
            elif isinstance(value, str):
                val_bytes = value.encode('utf-8')
                val_ptr = (CK_BYTE * len(val_bytes))(*val_bytes)
                attr_array[i].pValue = ctypes.cast(val_ptr, CK_VOID_PTR)
                attr_array[i].ulValueLen = len(val_bytes)
            # Add more types if needed

        rv = self.lib.C_FindObjectsInit(handle, attr_array, len(template))
        if rv != CKR_OK:
            return rv, []

        obj_handles = (CK_OBJECT_HANDLE * 100)()
        count = CK_ULONG(0)
        rv = self.lib.C_FindObjects(handle, obj_handles, 100, ctypes.byref(count))
        self.lib.C_FindObjectsFinal(handle)
        
        return rv, list(obj_handles[:count.value])

    def sign(self, handle, mechanism_type, key_handle, data):
        mech = CK_MECHANISM(mechanism_type, None, 0)
        rv = self.lib.C_SignInit(handle, ctypes.byref(mech), key_handle)
        if rv != CKR_OK:
            return rv, None

        data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        data_ptr = (CK_BYTE * len(data_bytes))(*data_bytes)
        
        sig_len = CK_ULONG(0)
        rv = self.lib.C_Sign(handle, data_ptr, len(data_bytes), None, ctypes.byref(sig_len))
        if rv != CKR_OK:
            return rv, None
        
        sig = (CK_BYTE * sig_len.value)()
        rv = self.lib.C_Sign(handle, data_ptr, len(data_bytes), sig, ctypes.byref(sig_len))
        return rv, bytes(sig[:sig_len.value])

    def initialize(self):
        return self.lib.C_Initialize(None)

    def finalize(self):
        return self.lib.C_Finalize(None)

    def get_info(self):
        info = CK_INFO()
        rv = self.lib.C_GetInfo(ctypes.byref(info))
        return rv, info

    def get_slot_list(self, token_present=True):
        count = CK_ULONG(0)
        rv = self.lib.C_GetSlotList(1 if token_present else 0, None, ctypes.byref(count))
        if rv != CKR_OK:
            return rv, []
        
        slots = (CK_SLOT_ID * count.value)()
        rv = self.lib.C_GetSlotList(1 if token_present else 0, slots, ctypes.byref(count))
        return rv, list(slots)

    def get_slot_info(self, slot_id):
        info = CK_SLOT_INFO()
        rv = self.lib.C_GetSlotInfo(slot_id, ctypes.byref(info))
        return rv, info

    def get_token_info(self, slot_id):
        info = CK_TOKEN_INFO()
        rv = self.lib.C_GetTokenInfo(slot_id, ctypes.byref(info))
        return rv, info

    def open_session(self, slot_id, flags=CKF_SERIAL_SESSION | CKF_RW_SESSION):
        handle = CK_SESSION_HANDLE(0)
        rv = self.lib.C_OpenSession(slot_id, flags, None, None, ctypes.byref(handle))
        return rv, handle.value

    def close_session(self, handle):
        return self.lib.C_CloseSession(handle)

    def login(self, handle, user_type, pin):
        pin_bytes = pin.encode('utf-8')
        pin_ptr = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
        return self.lib.C_Login(handle, user_type, pin_ptr, len(pin_bytes))

    def logout(self, handle):
        return self.lib.C_Logout(handle)

if __name__ == "__main__":
    # Example usage
    wrapper = TpmManPKCS11()
    print("Initializing...")
    rv = wrapper.initialize()
    if rv == CKR_OK:
        print("Initialized successfully.")
        
        rv, info = wrapper.get_info()
        if rv == CKR_OK:
            print(f"Manufacturer: {info.manufacturerID.decode('utf-8').strip()}")
            print(f"Library Description: {info.libraryDescription.decode('utf-8').strip()}")
        
        rv, slots = wrapper.get_slot_list()
        print(f"Slots: {slots}")
        
        for slot in slots:
            rv, tinfo = wrapper.get_token_info(slot)
            if rv == CKR_OK:
                print(f"Token Label: {tinfo.label.decode('utf-8').strip()}")
        
        wrapper.finalize()
    else:
        print(f"Failed to initialize: {rv}")
