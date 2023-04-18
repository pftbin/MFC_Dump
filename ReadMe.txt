//h头文件
HINSTANCE			m_hDebug;

//InitInstance调用【CWinApp::InitInstance()之后】
m_hDebug = LoadLibrary(_T("trapbug.dll"));

//ExitInstance调用
if ( NULL != m_hDebug ) 
{
	FreeLibrary( m_hDebug );
}