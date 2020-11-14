#include <iostream>
#include <cstring>
#include <vector>

#include <openssl/md5.h>
#include <zlib.h>
#include <windows.h>

typedef struct
{
    char Code[300];
    char Email[300];
    char Name[300];
    char MachineID[300];
    uint32_t RunCount;
    time_t LastUpdated;
    time_t LastShown;
    bool Validated;
} SupportInfo;

std::string StringifyMd5(unsigned char* md5)
{
    std::string ret;
    char buf[MD5_DIGEST_LENGTH];
    int index = 0;
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        sprintf(buf, "%02x", md5[i]);
        ret.append(buf);
    }

    for (int i = 0; i < ret.length(); i++)
    {
        ret[i] = toupper(ret[i]);
    }

    return ret;
}

// largely taken from ./Source/Project64/UserInterface/ProjectSupport.cpp
// Updated to support mingw
std::string GenerateMachineID(void)
{
    DWORD Dump;

    char ComputerName[256];
    DWORD Length = sizeof(ComputerName) / sizeof(ComputerName[0]);
    GetComputerName(ComputerName, &Length);

    char SysPath[MAX_PATH], VolumePath[MAX_PATH];
    GetSystemDirectory(SysPath, sizeof(SysPath) / sizeof(SysPath[0]));

    GetVolumePathName(SysPath, VolumePath, sizeof(VolumePath) / sizeof(VolumePath[0]));

    DWORD SerialNumber;
    GetVolumeInformation(VolumePath, NULL, Dump, &SerialNumber, NULL, NULL, NULL, Dump);

    char MachineGuid[200];
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        DWORD Type, dwDataSize = sizeof(MachineGuid);
        RegQueryValueEx(hKey, "MachineGuid", nullptr, &Type, (LPBYTE)MachineGuid, &dwDataSize);
        RegCloseKey(hKey);
    }

    char buf[300];
    int sz;
    sz = sprintf(buf, "%s.%ud.%s", ComputerName, SerialNumber, MachineGuid);

    return StringifyMd5(MD5((const unsigned char *)buf, sz, NULL));
}

// largely taken from ./Source/Project64/UserInterface/ProjectSupport.cpp
// see CProjectSupport::LoadSupportInfo
bool ValidateSupportInfo(void)
{
    SupportInfo m_SupportInfo = { 0 };
    std::string MachineID = GenerateMachineID();
    std::vector<uint8_t> InData;

    HKEY hKeyResults = 0;
    long lResult = RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Project64", 0, KEY_READ, &hKeyResults);
    if (lResult == ERROR_SUCCESS)
    {
        DWORD DataSize = 0;
        if (RegQueryValueEx(hKeyResults, "user", NULL, NULL, NULL, &DataSize) == ERROR_SUCCESS)
        {
            InData.resize(DataSize);
            if (RegQueryValueEx(hKeyResults, "user", NULL, NULL, InData.data(), &DataSize) != ERROR_SUCCESS)
            {
                InData.clear();
            }
        }
    }

    if (hKeyResults != NULL)
    {
        RegCloseKey(hKeyResults);
        NULL;
    }

    std::vector<uint8_t> OutData;
    if (InData.size() > 0)
    {
        for (size_t i = 0, n = InData.size(); i < n; i++)
        {
            InData[i] ^= 0xAA;
        }
        OutData.resize(sizeof(SupportInfo) + 100);
        uLongf DestLen = OutData.size();
        if (uncompress(OutData.data(), &DestLen, InData.data(), InData.size()) >= 0)
        {
            OutData.resize(DestLen);
        }
        else
        {
            OutData.clear();
        }
    }

    if (OutData.size() == sizeof(SupportInfo) + 32)
    {
        SupportInfo * Info = (SupportInfo *)OutData.data();
        const char * CurrentHash = (const char *)(OutData.data() + sizeof(SupportInfo));
        std::string hash = StringifyMd5(MD5((const unsigned char *)Info, sizeof(SupportInfo), NULL));
        if (strcmp(hash.c_str(), CurrentHash) == 0 && strcmp(Info->MachineID, MachineID.c_str()) == 0)
        {
            memcpy(&m_SupportInfo, Info, sizeof(SupportInfo));
        }
    }
    strcpy(m_SupportInfo.MachineID, MachineID.c_str());
	
    return m_SupportInfo.Validated;
}

void CreateSupportInfoKey(void)
{
	SupportInfo info;
    std::string hash;

    // init info
    memset(&info, 0, sizeof(info));
    strcpy(info.MachineID, GenerateMachineID().c_str());
    info.Validated = true;
    long unsigned int size = (long unsigned int)sizeof(info.Name);
    GetUserNameA(info.Name, &size);

    // generate md5 hash
    hash = StringifyMd5(MD5((const unsigned char *)&info, sizeof(info), NULL));

    std::vector<uint8_t> in_data(sizeof(SupportInfo) + hash.length());
    std::vector<uint8_t> out_data(in_data.size());

    // copy data in buffer
    memcpy(in_data.data(), (const unsigned char *)&info, sizeof(info));
    memcpy(in_data.data() + sizeof(info), hash.data(), hash.length());

    // create zlib stream
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = (uInt)in_data.size();
    stream.next_in = (Bytef *)in_data.data();
    stream.avail_out = (uInt)out_data.size();
    stream.next_out = (Bytef *)out_data.data();

    // compress data
    deflateInit(&stream, Z_BEST_COMPRESSION);
    deflate(&stream, Z_FINISH);
    deflateEnd(&stream);

    // reset buffer size
    out_data.resize(stream.total_out);

    // ???
    for (size_t i = 0, n = out_data.size(); i < n; i++)
        out_data[i] ^= 0xAA;

    // store data in registry
    HKEY hKeyResults = 0;
    DWORD Disposition = 0;
    long ret = RegCreateKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Project64", 0, (char*)"", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKeyResults, &Disposition);
    if (ret == ERROR_SUCCESS)
    {
        RegSetValueEx(hKeyResults, "user", 0, REG_BINARY, (BYTE *)out_data.data(), out_data.size());
        RegCloseKey(hKeyResults);
    }
}

int main(void)
{
	if (ValidateSupportInfo())
	{
		std::cout << "Validated existing key" << std::endl;
	}
	else
	{
		CreateSupportInfoKey();
		std::cout << "Generated new key" << std::endl;
	}
    
	return 0;
}