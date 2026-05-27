#!/usr/bin/env python3

from tpmman_pkcs11 import TpmManPKCS11, CKR_OK, CKU_USER

def test_tpmman():
    wrapper = TpmManPKCS11()
    
    print("--- PKCS#11 Test ---")
    
    # Initialize
    rv = wrapper.initialize()
    if rv != CKR_OK:
        print(f"Failed to initialize: {rv}")
        return
    print("Initialized.")

    try:
        # Get Info
        rv, info = wrapper.get_info()
        if rv == CKR_OK:
            print(f"Manufacturer: {info.manufacturerID.decode('utf-8').strip()}")
        
        # Get Slots
        rv, slots = wrapper.get_slot_list()
        print(f"Available slots: {slots}")
        
        for slot_id in slots:
            rv, tinfo = wrapper.get_token_info(slot_id)
            if rv == CKR_OK:
                label = tinfo.label.decode('utf-8').strip()
                print(f"Slot {slot_id}: Token Label = '{label}'")
                
                # Open Session
                rv, session = wrapper.open_session(slot_id)
                if rv == CKR_OK:
                    print(f"  Session {session} opened.")
                    
                    # Session Info
                    rv, sinfo = wrapper.get_session_info(session)
                    if rv == CKR_OK:
                        print(f"  Session State: {sinfo.state}")
                    
                    wrapper.close_session(session)
                    print(f"  Session {session} closed.")
                else:
                    print(f"  Failed to open session: {rv}")

    finally:
        wrapper.finalize()
        print("Finalized.")

if __name__ == "__main__":
    test_tpmman()
