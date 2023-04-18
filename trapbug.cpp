// trapbug.cpp : ���� DLL �ĳ�ʼ�����̡�
//

#include "stdafx.h"
#include "trapbug.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//
//TODO: ����� DLL ����� MFC DLL �Ƕ�̬���ӵģ�
//		��Ӵ� DLL �������κε���
//		MFC �ĺ������뽫 AFX_MANAGE_STATE ����ӵ�
//		�ú�������ǰ�档
//
//		����:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// �˴�Ϊ��ͨ������
//		}
//
//		�˺������κ� MFC ����
//		������ÿ��������ʮ����Ҫ������ζ��
//		��������Ϊ�����еĵ�һ�����
//		���֣������������ж������������
//		������Ϊ���ǵĹ��캯���������� MFC
//		DLL ���á�
//
//		�й�������ϸ��Ϣ��
//		����� MFC ����˵�� 33 �� 58��
//

// CtrapbugApp

BEGIN_MESSAGE_MAP(CtrapbugApp, CWinApp)
END_MESSAGE_MAP()


// CtrapbugApp ����

CtrapbugApp::CtrapbugApp()
{
	// TODO: �ڴ˴���ӹ�����룬
	// ��������Ҫ�ĳ�ʼ�������� InitInstance ��
}


// Ψһ��һ�� CtrapbugApp ����

CtrapbugApp theApp;


#include <windows.h>
#include <Dbghelp.h>

using namespace std;
#pragma auto_inline (off)
#pragma comment( lib, "DbgHelp")

BOOL m_bX86 = TRUE;
CString GetStringExceptionCode(DWORD dwCode)
{
	CString strInfo = _T("δ�����쳣");

	switch (dwCode)
	{   
		//  ���ڴ��йص��쳣��    
	case EXCEPTION_ACCESS_VIOLATION:   
		strInfo = _T("�߳���ͼ����δ�����Ƿ��ڴ���쳣");   
		break;   
	case EXCEPTION_DATATYPE_MISALIGNMENT:   
		strInfo = _T("�߳���ͼ����д��֧�ֶ����Ӳ���ϵ�δ���������" );   
		break;   
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:   
		strInfo = _T("�߳���ͼ��ȡһ��Խ�������Ԫ��" );   
		break;   
	case EXCEPTION_IN_PAGE_ERROR:   
		strInfo = _T("�����ļ�ϵͳ��һ���豸�������򷵻�һ����������ɲ�������Ҫ���ҳ����" );   
		break;   
	case EXCEPTION_GUARD_PAGE:   
		strInfo = _T("�߳���ͼ��ȡһ������PAGE_GUARD�������Ե��ڴ�ҳ" );   
		break;   
	case EXCEPTION_ILLEGAL_INSTRUCTION:   
		strInfo = _T("�߳�ִ����һ����Ч��ָ��" );   
		break;   
	case EXCEPTION_PRIV_INSTRUCTION:   
		strInfo = _T("�߳�ִ����һ����ǰ����ģʽ�������ָ��" );   
		break;   

		//  ��ṹ���쳣��ص��쳣��    
	case EXCEPTION_INVALID_DISPOSITION:   
		strInfo = _T( "�쳣�����������˴����ֵ" );   
		break;   
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:   
		strInfo = _T( "�쳣��������һ�����ܼ������쳣���ص�EXCEPTION_CONTINUE_EXCEPTION" );   
		break;   

		//  �������йص��쳣��    
	case EXCEPTION_INT_DIVIDE_BY_ZERO:   
		strInfo = _T( "�����������쳣" );   
		break;   
	case EXCEPTION_INT_OVERFLOW:   
		strInfo = _T( "һ�����������Ľ������������ֵ�涨�ķ�Χ" );   
		break;   

		//  �븡�����йص��쳣��    
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:   
		strInfo = _T ("�����������쳣" );   
		break;   
	case EXCEPTION_FLT_DENORMAL_OPERAND:   
		strInfo = _T( "��������е�һ��������������" );   
		break;   
	case EXCEPTION_FLT_INEXACT_RESULT:   
		strInfo = _T( "��������Ľṹ���ܾ�ȷ��ʾ��ʮ����С��" );   
		break;   
	case EXCEPTION_FLT_INVALID_OPERATION:   
		strInfo = _T( "��ʾ�κ�û���ڴ��г��������������쳣" );   
		break;   
	case EXCEPTION_FLT_OVERFLOW:   
		strInfo = _T( "��������Ľṹ�����������ֵ" );   
		break;   
	case EXCEPTION_FLT_STACK_CHECK:   
		strInfo = _T( "���ڸ���������ջ���" );   
		break;   
	case EXCEPTION_FLT_UNDERFLOW:   
		strInfo = _T( "��������Ľ��С�������ֵ" );   
		break;   

		//  ���ָܻ��Ľṹ���쳣��ջ���    
	case EXCEPTION_STACK_OVERFLOW:   
		strInfo = _T( "ջ����쳣" );   
		break;   
	}   

	return strInfo;
}

LONG WINAPI NewUnhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	CTime t = CTime::GetCurrentTime();
	CString strFile;
	strFile.Format(_T("DumpFile[%04d-%02d-%02d %02d-%02d-%02d].dmp"), t.GetYear(), t.GetMonth(), t.GetDay(), t.GetHour(), t.GetMinute(), t.GetSecond());

    HANDLE lhDumpFile = CreateFile(strFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL ,NULL);
	if (lhDumpFile == NULL)
	{
		AfxMessageBox(_T("�����쳣,����dmp�ļ�ʧ��!"));
		return EXCEPTION_CONTINUE_SEARCH;
	}

    MINIDUMP_EXCEPTION_INFORMATION loExceptionInfo;
    loExceptionInfo.ExceptionPointers = ExceptionInfo;
    loExceptionInfo.ThreadId = GetCurrentThreadId();
    loExceptionInfo.ClientPointers = TRUE;
    BOOL b = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),lhDumpFile, MiniDumpNormal, &loExceptionInfo, NULL, NULL);
    CloseHandle(lhDumpFile);

	if (b == TRUE)
	{
		CString str;
		if (ExceptionInfo->ExceptionRecord->ExceptionFlags == 0)
			str = _T("����᳢�Լ�������");
		else
			str = _T("�����쳣����windowϵͳ����,���������˳�");

		CString strInfo;
		strInfo.Format(_T("��������쳣,��ϸ��Ϣ����%s��.\r\n\r\n�쳣˵��:	%s\r\n�쳣����:	%x\r\n�����ַ:	%x\r\n��һ���쳣��ַ:	%x\r\n���[ȷ��]��:	%s"),
						strFile,
						GetStringExceptionCode(ExceptionInfo->ExceptionRecord->ExceptionCode),
						ExceptionInfo->ExceptionRecord->ExceptionCode,
						ExceptionInfo->ExceptionRecord->ExceptionAddress,
						ExceptionInfo->ExceptionRecord->ExceptionRecord,
						str);
		MessageBox(NULL, strInfo, _T("�쳣"), MB_ICONEXCLAMATION);

		return EXCEPTION_CONTINUE_SEARCH;

		if (ExceptionInfo->ExceptionRecord->ExceptionFlags == 0)
			return EXCEPTION_EXECUTE_HANDLER;
		else
			return EXCEPTION_CONTINUE_SEARCH;
	}
	else
	{
		::DeleteFile(strFile);
		AfxMessageBox(_T("�����쳣,dump����ʧ��!"));
	}

    return EXCEPTION_CONTINUE_SEARCH;
}

void new_invalid_parameter_handler(const wchar_t * expression,
								   const wchar_t * function,
								   const wchar_t * file,
								   unsigned int line,
								   uintptr_t pReserved)
{
	CString strInfo;
	strInfo.Format(_T("Invalid parameter detected in function [%s].\r\nFile: [%s]\r\n Line: [%d]\r\nExpression: %s\r\n��ȷ����������г���"), function, file, line, expression);
//	MessageBox(NULL, strInfo, _T("�쳣-������Ч��������"), MB_ICONEXCLAMATION);
    return ;
}

void newpurecall_handler()
{
//	MessageBox(NULL, _T("�麯������ʧ��"), _T("�쳣"), MB_ICONEXCLAMATION);
	exit(0);
}

BOOL DisableSetUnhandledExceptionFilterEx()
{
	HMODULE hKernel32 = LoadLibrary(_T("kernel32.dll"));
	if (hKernel32 == NULL) return FALSE;
	void *pOrgEntry = GetProcAddress(hKernel32, 
		"SetUnhandledExceptionFilter");
	if(pOrgEntry == NULL) return FALSE;

	DWORD dwOldProtect = 0;
	SIZE_T jmpSize = 5;
	if(!m_bX86)
	{
		jmpSize = 13;
	}
	BOOL bProt = VirtualProtect(pOrgEntry, jmpSize, 
		PAGE_EXECUTE_READWRITE, &dwOldProtect);
	BYTE newJump[20];
	void *pNewFunc = &NewUnhandledExceptionFilter;
	if(m_bX86)
	{
		DWORD dwOrgEntryAddr = (DWORD) pOrgEntry;
		dwOrgEntryAddr += jmpSize; // add 5 for 5 op-codes for jmp rel32
		DWORD dwNewEntryAddr = (DWORD) pNewFunc;
		DWORD dwRelativeAddr = dwNewEntryAddr - dwOrgEntryAddr;
		// JMP rel32: Jump near, relative, displacement relative to next instruction.
		newJump[0] = 0xE9;  // JMP rel32
		memcpy(&newJump[1], &dwRelativeAddr, sizeof(pNewFunc));
	}
	else
	{
		// We must use R10 or R11, because these are "scratch" registers 
		// which need not to be preserved accross function calls
		// For more info see: Register Usage for x64 64-Bit
		// http://msdn.microsoft.com/en-us/library/ms794547.aspx
		// Thanks to Matthew Smith!!!
		newJump[0] = 0x49;  // MOV R11, ...
		newJump[1] = 0xBB;  // ...
		memcpy(&newJump[2], &pNewFunc, sizeof (pNewFunc));
		//pCur += sizeof (ULONG_PTR);
		newJump[10] = 0x41;  // JMP R11, ...
		newJump[11] = 0xFF;  // ...
		newJump[12] = 0xE3;  // ...
	}
	SIZE_T bytesWritten;
	BOOL bRet = WriteProcessMemory(GetCurrentProcess(),
		pOrgEntry, newJump, jmpSize, &bytesWritten);

	if (bProt != FALSE)
	{
		DWORD dwBuf;
		VirtualProtect(pOrgEntry, jmpSize, dwOldProtect, &dwBuf);
	}
	return bRet;
}

BOOL DisableSetUnhandledExceptionFilter()
{
	void *addr = (void*)GetProcAddress(LoadLibrary(_T("kernel32.dll")), "SetUnhandledExceptionFilter");
	if (addr) 
	{
		unsigned char code[16];
		int size = 0;
		//xor eax,eax;
		code[size++] = 0x33;
		code[size++] = 0xC0;
		//ret 4
		code[size++] = 0xC2;
		code[size++] = 0x04;
		code[size++] = 0x00;

		DWORD dwOldFlag, dwTempFlag;
		VirtualProtect(addr, size, PAGE_READWRITE, &dwOldFlag);
		WriteProcessMemory(GetCurrentProcess(), addr, code, size, NULL);
		VirtualProtect(addr, size, dwOldFlag, &dwTempFlag);
	}

	return TRUE;
}

CString GetOSVersion()  
{  
	CString strVersion = _T("");  
	OSVERSIONINFO osvi;                 //����OSVERSIONINFO���ݽṹ����  
	memset(&osvi, 0, sizeof(OSVERSIONINFO));        //���ռ�   
	osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);  //�����С   
	GetVersionEx (&osvi);                   //��ð汾��Ϣ  

	DWORD dwMajorVersion = osvi.dwMajorVersion;         //���汾��  
	DWORD dwMinorVersion = osvi.dwMinorVersion;         //���汾  
	char swVersion[10]={0};      
	sprintf(swVersion,"%d.%d",dwMajorVersion,dwMinorVersion);   

	if (!strcmp(swVersion,"5.0"))  
	{  
		strVersion =  _T("Windows 2000");       
	}      
	else if (!strcmp(swVersion,"5.1"))  
	{  
		strVersion = _T("Windows XP");      
	}     
	else if (!strcmp(swVersion,"5.2"))  
	{  
		strVersion = _T("Windows XP Professional x64");      
	}     
	else if (!strcmp(swVersion,"6.0"))  
	{  
		strVersion = _T("Windows Vista");      
	}     
	else if (!strcmp(swVersion,"6.1"))  
	{  
		strVersion = _T("Windows 7");      
	}     
	else if (!strcmp(swVersion,"6.2"))  
	{  
		strVersion = _T("Windows 8");        
	}  
	else if (!strcmp(swVersion,"6.3"))  
	{  
		strVersion = _T("Windows 8.1");       
	}  
	else if (!strcmp(swVersion,"10.0"))  
	{  
		strVersion = _T("Windows 10");        
	}  
	else  
	{  
		strVersion = _T("");  
	}  
	return strVersion;  
}  

// CtrapbugApp ��ʼ��

BOOL CtrapbugApp::InitInstance()
{
	CWinApp::InitInstance();

	CString strFile = _T("");
	strFile.Format(_T("%s\\PlayoutConfig.ini"), GetAppFolder());
	m_bX86 = ::GetPrivateProfileInt(_T("TRAPBUG"), _T("X86"), 1, strFile);

	SetUnhandledExceptionFilter(NewUnhandledExceptionFilter);

	TCHAR exeFullName[MAX_PATH] = {0};
	::GetModuleFileName(NULL, exeFullName, MAX_PATH);
	CString strPath = exeFullName;
	strPath.MakeLower();
	if((strPath.Find(_T("datapipeserver.exe")) >= 0 || strPath.Find(_T("deleteserver.exe")) >= 0) && (GetOSVersion().Find(_T("Windows 10")) >= 0
		|| GetOSVersion().Find(_T("Windows 8")) >= 0 || GetOSVersion().Find(_T("Windows 8.1")) >= 0))
	{
		DisableSetUnhandledExceptionFilterEx();
	}
	else
	{
		DisableSetUnhandledExceptionFilter();
	}

	_invalid_parameter_handler old = _set_invalid_parameter_handler(new_invalid_parameter_handler);
	_CrtSetReportMode(_CRT_ASSERT, 0);
	_set_purecall_handler(newpurecall_handler);

	return TRUE;
}

int CtrapbugApp::ExitInstance()
{
	// TODO: �ڴ����ר�ô����/����û���
	return CWinApp::ExitInstance();
}
