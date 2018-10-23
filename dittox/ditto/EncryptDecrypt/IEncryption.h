// IEncryption.h: interface for the IEncryption class.
//
//////////////////////////////////////////////////////////////////////

#define AFX_IENCRYPTION_H__7741547B_BA15_4851_A41B_2B4EC1DC12D5__INCLUDED_

#define DLL_DECLSPEC

#define IENCRYPTION_VERSION 0x0000

class IEncryption;

typedef IEncryption* (*PFNCREATE)(); // function prototype
extern "C" DLL_DECLSPEC IEncryption* CreateEncryptionInterface();

typedef int (*PFNGETVERSION)(); // function prototype
extern "C" DLL_DECLSPEC int GetInterfaceVersion();

#if 0
// helper method
static IEncryption* CreateEncryptionInterface(const TCHAR* szDllPath)
{
    IEncryption* pInterface = NULL;
    HMODULE hDll = LoadLibrary(szDllPath);
	
    if (hDll)
    {
        PFNCREATE pCreate = (PFNCREATE)GetProcAddress(hDll, "CreateEncryptionInterface");
		
        if (pCreate)
		{
			// check version
			PFNGETVERSION pVersion = (PFNGETVERSION)GetProcAddress(hDll, "GetInterfaceVersion");

			if (!IENCRYPTION_VERSION || (pVersion && pVersion() >= IENCRYPTION_VERSION))
				pInterface = pCreate();
		}
    }
	
    return pInterface;
}

static BOOL IsEncryptionDll(const TCHAR* szDllPath)
{
    HMODULE hDll = LoadLibrary(szDllPath);
	
    if (hDll)
    {
        PFNCREATE pCreate = (PFNCREATE)GetProcAddress(hDll, "CreateEncryptionInterface");
		FreeLibrary(hDll);

		return (NULL != pCreate);
	}

	return FALSE;
}
#endif

class IEncryption
{
public:
    virtual void Release() = 0; // releases the interface
	
    // returns a dynamically allocated buffer to the encrypted text
    // caller responsible for calling FreeBuffer on the returned buffer
    virtual bool Encrypt(const unsigned char* pInput, int nLenInput, const char* szPassword, 
						 unsigned char*& pOutput, int& nLenOutput) = 0;
	
    // returns a dynamically allocated buffer to the decrypted text
    // caller responsible for calling FreeBuffer on the returned buffer
    virtual bool Decrypt(const unsigned char* pInput, int nLenInput, const char* szPassword,
						 unsigned char*& pOutput, int& nLenOutput) = 0;
	
    // frees a previously returned buffer and sets the ptr to NULL
    // eg for buffer allocated with 'new' use 'delete []'
    // eg for buffer allocated with 'strdup' use 'free'
    virtual void FreeBuffer(unsigned char*& pBuffer) = 0;
	
};

static void ReleaseEncryptionInterface(IEncryption*& pInterface)
{
    if (pInterface)
    {
        pInterface->Release();
        pInterface = NULL;
    }
}
