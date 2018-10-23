#pragma once


#define CHUNK_WRITE_SIZE 65536

class MyEnums
{
public:
	enum eSendType{
		START, 		// 0
		DATA, 		// 1
		DATA_START, 	// 2
		DATA_END, 	// 3
		END, 		// 4
		EXIT, 		// 5
		REQUEST_FILES};	// 6
};

class CSendInfo
{
public:
	CSendInfo()
	{
		memset(this, 0, sizeof(*this));
		m_nSize = sizeof(CSendInfo);
		m_nVersion = 1;
		m_lParameter1 = -1;
		m_lParameter2 = -1;
	}
	int32_t			m_nSize;
	MyEnums::eSendType	m_Type;
	int32_t			m_nVersion;
	CHAR			m_cIP[20];
	CHAR			m_cComputerName[MAX_COMPUTERNAME_LENGTH + 1];
	CHAR			m_cDesc[250];
	int32_t			m_lParameter1;
	int32_t			m_lParameter2;
	char			m_cExtra[50];
};

class CDittoCF_HDROP
{
public:
	CDittoCF_HDROP()
	{
		memset(m_cIP, 0, sizeof(m_cIP));
		memset(m_cComputerName, 0, sizeof(m_cComputerName));
	}
	char m_cIP[25];
	char m_cComputerName[MAX_COMPUTERNAME_LENGTH + 1];
};
