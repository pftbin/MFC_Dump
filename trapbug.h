// trapbug.h : trapbug DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CtrapbugApp
// �йش���ʵ�ֵ���Ϣ������� trapbug.cpp
//

class CtrapbugApp : public CWinApp
{
public:
	CtrapbugApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
	virtual int ExitInstance();
};
