// trapbug.cpp : 定义 DLL 的初始化例程。
//

#include "stdafx.h"
#include "trapbug.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//
//TODO: 如果此 DLL 相对于 MFC DLL 是动态链接的，
//		则从此 DLL 导出的任何调入
//		MFC 的函数必须将 AFX_MANAGE_STATE 宏添加到
//		该函数的最前面。
//
//		例如:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// 此处为普通函数体
//		}
//
//		此宏先于任何 MFC 调用
//		出现在每个函数中十分重要。这意味着
//		它必须作为函数中的第一个语句
//		出现，甚至先于所有对象变量声明，
//		这是因为它们的构造函数可能生成 MFC
//		DLL 调用。
//
//		有关其他详细信息，
//		请参阅 MFC 技术说明 33 和 58。
//

// CtrapbugApp

BEGIN_MESSAGE_MAP(CtrapbugApp, CWinApp)
END_MESSAGE_MAP()


// CtrapbugApp 构造

CtrapbugApp::CtrapbugApp()
{
	// TODO: 在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}


// 唯一的一个 CtrapbugApp 对象

CtrapbugApp theApp;


#include <windows.h>
#include <Dbghelp.h>

using namespace std;
#pragma auto_inline (off)
#pragma comment( lib, "DbgHelp")

BOOL m_bX86 = TRUE;
CString GetStringExceptionCode(DWORD dwCode)
{
	CString strInfo = _T("未定义异常");

	switch (dwCode)
	{   
		//  与内存有关的异常。    
	case EXCEPTION_ACCESS_VIOLATION:   
		strInfo = _T("线程试图访问未分配或非法内存的异常");   
		break;   
	case EXCEPTION_DATATYPE_MISALIGNMENT:   
		strInfo = _T("线程试图读或写不支持对齐的硬件上的未对齐的数据" );   
		break;   
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:   
		strInfo = _T("线程试图存取一个越界的数组元素" );   
		break;   
	case EXCEPTION_IN_PAGE_ERROR:   
		strInfo = _T("由于文件系统或一个设备启动程序返回一个读错误，造成不能满足要求的页故障" );   
		break;   
	case EXCEPTION_GUARD_PAGE:   
		strInfo = _T("线程试图读取一个带有PAGE_GUARD保护属性的内存页" );   
		break;   
	case EXCEPTION_ILLEGAL_INSTRUCTION:   
		strInfo = _T("线程执行了一个无效的指令" );   
		break;   
	case EXCEPTION_PRIV_INSTRUCTION:   
		strInfo = _T("线程执行了一个当前机器模式不允许的指令" );   
		break;   

		//  与结构化异常相关的异常。    
	case EXCEPTION_INVALID_DISPOSITION:   
		strInfo = _T( "异常过滤器返回了错误的值" );   
		break;   
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:   
		strInfo = _T( "异常过滤器对一个不能继续的异常返回的EXCEPTION_CONTINUE_EXCEPTION" );   
		break;   

		//  与整数有关的异常。    
	case EXCEPTION_INT_DIVIDE_BY_ZERO:   
		strInfo = _T( "整型数除零异常" );   
		break;   
	case EXCEPTION_INT_OVERFLOW:   
		strInfo = _T( "一个整数操作的结果超过了整数值规定的范围" );   
		break;   

		//  与浮点数有关的异常。    
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:   
		strInfo = _T ("浮点数除零异常" );   
		break;   
	case EXCEPTION_FLT_DENORMAL_OPERAND:   
		strInfo = _T( "浮点操作中的一个操作数不正常" );   
		break;   
	case EXCEPTION_FLT_INEXACT_RESULT:   
		strInfo = _T( "浮点操作的结构不能精确表示成十进制小数" );   
		break;   
	case EXCEPTION_FLT_INVALID_OPERATION:   
		strInfo = _T( "表示任何没有在此列出的其它浮点数异常" );   
		break;   
	case EXCEPTION_FLT_OVERFLOW:   
		strInfo = _T( "浮点操作的结构超过了允许的值" );   
		break;   
	case EXCEPTION_FLT_STACK_CHECK:   
		strInfo = _T( "由于浮点操作造成栈溢出" );   
		break;   
	case EXCEPTION_FLT_UNDERFLOW:   
		strInfo = _T( "浮点操作的结果小于允许的值" );   
		break;   

		//  不能恢复的结构化异常。栈溢出    
	case EXCEPTION_STACK_OVERFLOW:   
		strInfo = _T( "栈溢出异常" );   
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
		AfxMessageBox(_T("出现异常,创建dmp文件失败!"));
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
			str = _T("程序会尝试继续运行");
		else
			str = _T("程序将异常交给window系统处理,尝试立即退出");

		CString strInfo;
		strInfo.Format(_T("程序出现异常,详细信息存入%s中.\r\n\r\n异常说明:	%s\r\n异常类型:	%x\r\n出错地址:	%x\r\n下一个异常地址:	%x\r\n点击[确定]后:	%s"),
						strFile,
						GetStringExceptionCode(ExceptionInfo->ExceptionRecord->ExceptionCode),
						ExceptionInfo->ExceptionRecord->ExceptionCode,
						ExceptionInfo->ExceptionRecord->ExceptionAddress,
						ExceptionInfo->ExceptionRecord->ExceptionRecord,
						str);
		MessageBox(NULL, strInfo, _T("异常"), MB_ICONEXCLAMATION);

		return EXCEPTION_CONTINUE_SEARCH;

		if (ExceptionInfo->ExceptionRecord->ExceptionFlags == 0)
			return EXCEPTION_EXECUTE_HANDLER;
		else
			return EXCEPTION_CONTINUE_SEARCH;
	}
	else
	{
		::DeleteFile(strFile);
		AfxMessageBox(_T("出现异常,dump数据失败!"));
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
	strInfo.Format(_T("Invalid parameter detected in function [%s].\r\nFile: [%s]\r\n Line: [%d]\r\nExpression: %s\r\n点确定后继续运行程序"), function, file, line, expression);
//	MessageBox(NULL, strInfo, _T("异常-出现无效参数调用"), MB_ICONEXCLAMATION);
    return ;
}

void newpurecall_handler()
{
//	MessageBox(NULL, _T("虚函数调用失败"), _T("异常"), MB_ICONEXCLAMATION);
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
	OSVERSIONINFO osvi;                 //定义OSVERSIONINFO数据结构对象  
	memset(&osvi, 0, sizeof(OSVERSIONINFO));        //开空间   
	osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);  //定义大小   
	GetVersionEx (&osvi);                   //获得版本信息  

	DWORD dwMajorVersion = osvi.dwMajorVersion;         //主版本号  
	DWORD dwMinorVersion = osvi.dwMinorVersion;         //副版本  
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

// CtrapbugApp 初始化

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
	// TODO: 在此添加专用代码和/或调用基类
	return CWinApp::ExitInstance();
}
