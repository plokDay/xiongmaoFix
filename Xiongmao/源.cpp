#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "Md5.h"
#include <string>
#define MAX_PATH 500
using std::string;

//1. 查找并结束病毒进程, 删除文件
//2. 删除指定病毒文件
//3. 更改注册表
//4. 递归遍历删除硬盘中的病毒文件，并修复被感染文件

//提权
bool EnableDebugPrivilege(char * pszPrivilege)
{
	HANDLE hToken = INVALID_HANDLE_VALUE;
	LUID luid;
	TOKEN_PRIVILEGES tp;

	BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if (bRet == FALSE)
	{
		return bRet;
	}
	bRet = LookupPrivilegeValue(NULL, pszPrivilege, &luid);
	if (bRet == FALSE)
	{
		return bRet;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

	return bRet;
}

//设置颜色
void setColor(int fcolor, int bcolor = 0)
{
	HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hOutput, fcolor + bcolor * 0x10);
}
//特征码检测
int SigDet(const char* szPath,const char* sig)
{

	//1. 将文件读入内存
	HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA ERROR\n");
		return false;
	}
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (dwSize == 0xFFFFFFFF)
	{
		printf("GetFileSize ERROR\n");
		return false;
	}
	const char *pFile = new char[dwSize]();

	if (pFile == NULL)
	{
		printf("malloc ERROR\n");
		return false;
	}
	DWORD dwNum = 0;
	ReadFile(hFile, (LPVOID)pFile, dwSize, &dwNum, NULL);
	CloseHandle(hFile);
	//2. 查找特征码
	string pebuff;
	for (int i = 0; i < dwSize; ++i)
	{
		pebuff += pFile[i];
	}
	int n = pebuff.find(sig);
	if (n == -1)
	{
		return false;
	}
	return n;
}
//校验
bool Detect(const char* szPath)
{
	const char* MD5Vir = "16BB583E913DD1B4643212F1B8E3ACD2";//已脱壳
	const char* MD5Vir1 = "512301C535C88255C9A252FDF70B7A03";//未脱壳
	//MD5
	char* fileMd5 = md5FileValue(szPath);
	if (!_stricmp(fileMd5, MD5Vir1))
	{
		return true;
	}
	if (!_stricmp(fileMd5, MD5Vir))
	{
		return true;
	}
	//特征码
	if (SigDet(szPath, "WhBoy"))
	{
		return true;
	}
	else
	{
		return false;
	}
}
//删除文件
void DeleteVirFile(const char* szPath)
{
	setColor(12);
	printf(szPath);
	setColor(10);
	SetFileAttributesA(szPath, FILE_ATTRIBUTE_NORMAL);
	// 删除Desktop_.ini
	BOOL bRet = DeleteFileA(szPath);
	if (bRet)
	{
		printf("删除成功\n");
	}
	else
	{
		printf("删除失败\n");
	}
}
//修复被感染的exe等文件
void FixFile(const char *szPath, char* FileName)
{
	char cSig[100] ;
	lstrcpy(cSig, "WhBoy");
	lstrcat(cSig, FileName);
	//1. 判断有没有被感染
	//将exe读入内存
	//从最末尾-0x20的地方开始读
	// 将文件读入内存
	HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA ERROR\n");
		return;
	}
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (dwSize == 0xFFFFFFFF)
	{
		printf("GetFileSize ERROR\n");
	}
	const char *pFile = new char[dwSize]();
	if (pFile == NULL)
	{
		printf("malloc ERROR\n");
	}
	DWORD dwNum = 0;
	ReadFile(hFile, (LPVOID)pFile, dwSize, &dwNum, NULL);
	CloseHandle(hFile);
	string strJud;
	for (int i=0;i<0x25;++i)
	{
		strJud += pFile[dwSize - 0x25+i-1];
	}
	int nRes = 0; nRes = strJud.find(cSig);
	//2. 被感染的要修复
	if (nRes !=-1)
	{
		setColor(12);
		printf(szPath);
		printf("被感染了\t");
		setColor(10);
		DWORD dwRSize = 0;
		//从0x7531开始读
		DWORD corHead = 0x7531;
	
		dwRSize = dwSize - corHead;
		char* pebuff = new char[dwRSize]();
		for (int i = corHead,j=0; i < dwSize; ++i, ++j)
		{
			if (i >= dwSize-0x20)
			{
				pebuff[j] = 0;
			}
			else
				pebuff[j] = pFile[i];
		}
		HANDLE hFile1 = CreateFileA(szPath, GENERIC_WRITE, FILE_SHARE_READ,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		WriteFile(hFile1, pebuff, dwRSize, &dwNum, NULL);
		CloseHandle(hFile1);
		printf("修复成功\n");
	}
	else
	{
		printf("没有被感染\n");
	}

}
//修复被感染的脚本文件
void FixScript(const char *szPath)
{
	//1. 读取文件到内存
	HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA ERROR\n");
		return;
	}
	DWORD dwSize = GetFileSize(hFile, NULL);
	//printf("%0X\n", dwSize);
	if (dwSize<0x4c)
	{
		CloseHandle(hFile);
		return;
	}
	if (dwSize == 0xFFFFFFFF)
	{
		printf("GetFileSize ERROR\n");
	}
	const char *pFile = new char[dwSize]();
	if (pFile == NULL)
	{
		printf("malloc ERROR\n");
	}
	DWORD dwNum = 0;
	ReadFile(hFile, (LPVOID)pFile, dwSize, &dwNum, NULL);
	CloseHandle(hFile);
	//printf("成功载入内存\n");
	//2. 检测是否末尾的0x4C个字节是否有恶意代码
	char cSig[0x4C];
	//<iframe src=http://www.ac86.cn/66/index.htm width=\"0\" height=\"0\"></iframe>"
	string strJud;
	for (int i = 0; i < dwSize; ++i)
	{
		strJud+= pFile[i];
	}
	int n = strJud.find("<iframe src=http://www.ac86.cn/66/index.htm");
	if (n!=-1)
	{
		setColor(12);
		printf(szPath);
		printf("被感染了\t");
		setColor(10);
		//3. 有就删除并修复
		char* pebuff = new char[dwSize-0x4C]();
		for (int i = 0, j = 0; i < n; ++i, ++j)
		{
			pebuff[j] = pFile[i];
		}
		HANDLE hFile1 = CreateFileA(szPath, GENERIC_WRITE, FILE_SHARE_READ,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		WriteFile(hFile1, pebuff, dwSize-0x4C, &dwNum, NULL);
		CloseHandle(hFile1);
		printf("修复成功\n"); 
	}

}
//1. 查找并结束病毒进程, 删除文件
void VirProcess()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 proc = { sizeof(PROCESSENTRY32) };
		Process32First(hSnap, &proc);
		do
		{
			if (!_stricmp(proc.szExeFile, "spo0lsv.exe"))
			{
				setColor(12);
				printf("%s\n", proc.szExeFile);
				setColor(10);
				printf("找到可疑进程！正在校验……\n");
				//1. 根据PID得到进程路径
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
					PROCESS_VM_READ, FALSE, proc.th32ProcessID);
				char szPath[MAX_PATH] = { 0 };
				GetModuleFileNameEx(hProcess, 0, szPath, MAX_PATH);
				CloseHandle(hProcess);
				printf("Path:%s\n", szPath);
				//2. 校验
				if (Detect(szPath) == true)
				{
					setColor(12); printf("校验成功，符合病毒特征\n"); setColor(10);

					HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, proc.th32ProcessID);
					if (hProc == 0) {
						printf("打开进程失败\n");
						break;
					}
					else {
						TerminateProcess(hProc, 0);
						CloseHandle(hProc);
						printf("已经结束进程\n");
						DeleteFile(szPath);
						printf("已经删除文件\n");
						break;
					}
				}
				else
					printf("校验成功，不符合病毒特征\n");
			}
			else
				printf("%s\n", proc.szExeFile);
		} while (Process32Next(hSnap, &proc));
	}
	CloseHandle(hSnap);
}
//2. 删除指定病毒文件
//	C:\setup.exe
//	C:\autorun.inf
void DeleteVir()
{
	printf("扫描并删除病毒文件……\n");
	const char* szSetup = "C:\\setup.exe";
	const char* szAuto = "C:\\autorun.inf";
	if (Detect(szSetup) == true)
	{
		DeleteVirFile(szSetup);
	}
	DeleteVirFile(szAuto);
	//删除特殊目录的文件
	const char szNetFile[100] = "C:\\Users\\15pb-win7\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts\\Desktop_.ini";
	DeleteVirFile(szNetFile);
}
//3 递归遍历删除硬盘中的病毒文件，并修复被感染文件
//	Desktop_ini
DWORD CALLBACK DeleteVirProc(LPVOID p)
{
	char szFindFile[MAX_PATH];
	char cPath[MAX_PATH];
	char cPathf[MAX_PATH];
	WIN32_FIND_DATA fData = { 0 };
	const char* szFilter = "/*";
	lstrcpy(cPathf, (char *)p);
	lstrcpy(cPath, (char *)p);
	lstrcat(cPathf, szFilter);
	
	//21个排除的特殊目录
	const char* exceptDir[21] = { ".","..","$Recycle.Bin","WINDOWS","WINNT","system32","Documents and Settings","System Volume Information",
		"Recycled","Windows NT","WindowsUpdate","Windows Media Player","Outlook Express","Internet Explorer","Common Files",
		"ComPlus Applications","Messenger","InstallShield Installation Information","Microsoft Frontpage","Movie Maker","MSN Gamin Zone"};
	bool isExDir = false;
	HANDLE hFind = FindFirstFile(cPathf, &fData);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{//如果是目录，就排除特殊目录
					lstrcpy(szFindFile, cPath);
					lstrcat(szFindFile, "/");
					lstrcat(szFindFile, fData.cFileName);
					isExDir = false;
					for (int i = 0; i < 21; ++i)
					{
						if (_stricmp(fData.cFileName, exceptDir[i]) == 0)
						{
							isExDir = true;
							break;
						}
					}
					if (isExDir)
					{
						continue;
					}
					DeleteVirProc(szFindFile);//递归遍历
				}
				else//如果是文件
				{
					lstrcpy(szFindFile, cPath);
					lstrcat(szFindFile, "/");
					lstrcat(szFindFile, fData.cFileName);
					if (strcmp(fData.cFileName, "setup.exe") == 0 || strcmp(fData.cFileName, "NTDETECT.COM") == 0)
					{
						continue;
					}
					if (_stricmp(fData.cFileName, "Desktop_.ini")==0)
					{
						DeleteVirFile(szFindFile);
					}
					else
					{
						//判断后缀名是不是exe
						char* pExtName = fData.cFileName + strlen(fData.cFileName);
						while (pExtName != fData.cFileName && *pExtName != '.')
							--pExtName;
						if (_stricmp(pExtName,".exe")==0|| strcmp(pExtName, ".scr") == 0
							|| strcmp(pExtName, ".pif") == 0|| strcmp(pExtName, ".com") == 0)
						{
							printf(szFindFile);
							printf("\n");
							FixFile(szFindFile, fData.cFileName);
						}
						else if (_stricmp(pExtName, ".html") == 0 || strcmp(pExtName, ".htm") == 0
							|| strcmp(pExtName, ".asp") == 0 || strcmp(pExtName, ".php") == 0
							|| strcmp(pExtName, ".jsp") == 0 || strcmp(pExtName, ".aspx") == 0)
						{
							FixScript(szFindFile);
						}
					}
			}

		} while (FindNextFile(hFind, &fData));
	}
	
	FindClose(hFind);
	return true;
}
//4. 更改注册表
void FixReg()
{
	//检查注册表  spo0lsv_RASMANCS和spo0lsv_RASAPI32
	char RegSpo0lsv[] = "SOFTWARE\\Microsoft\\Tracing\\spo0lsv_RASMANCS";
	HKEY hKey= NULL;
	DWORD lSize = MAXBYTE;
	char cData[MAXBYTE] = { 0 };
	long lRetSpo = RegOpenKey(HKEY_LOCAL_MACHINE, RegSpo0lsv, &hKey);
	if (lRetSpo==ERROR_SUCCESS)
	{
		setColor(12); printf("注册表中存在spo0lsv_RASMANCS\n"); setColor(10);
		if (RegDeleteKey(hKey, "") == 0)//删除本身
			printf("删除成功\n");
		else printf("删除失败\n");
	}
	else
	{
		printf("注册表中不存在spo0lsv_RASMANCS\n");
	}
	char RegSpo0lsv1[] = "SOFTWARE\\Microsoft\\Tracing\\spo0lsv_RASAPI32";
	
	lRetSpo = RegOpenKey(HKEY_LOCAL_MACHINE, RegSpo0lsv1, &hKey);
	if (lRetSpo == ERROR_SUCCESS)
	{
		setColor(12); printf("注册表中存在spo0lsv_RASAPI32\n"); setColor(10);
		if (RegDeleteKey(hKey, "") == 0)//删除本身
			printf("删除成功\n");
		else printf("删除失败\n");
	}
	else
	{
		printf("注册表中不存在spo0lsv_RASAPI32\n");
	}
	printf("检查注册表启动项……\n");
	char RegRun[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	
	if (RegOpenKey(HKEY_CURRENT_USER, RegRun, &hKey) == ERROR_SUCCESS)
	{
		RegQueryValueEx(hKey, "svcshare", NULL, NULL, (unsigned char *)cData, &lSize);
		if (_stricmp(cData, "C:\\windows\\system32\\drivers\\spo0lsv.exe") == 0)
		{
			setColor(10); printf("开机启动项中存在spo0lsv.exe\n"); setColor(12);
			if (RegDeleteValue(hKey, "svcshare") == ERROR_SUCCESS)
			{
				printf("成功删除\n");
			}
			else
			{
				printf("删除失败\n");
			}
		}
		else
		{
			printf("开机启动项中不存在病毒信息\n");
		}
	}
	else
	{
		printf("打开注册表失败\n");
	}
	//需要将CheckedValue的值设置为1
	printf("检查注册表的文件隐藏选项……\n");
	char RegHide[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL";
	DWORD dwFlag = 1;
	DWORD val = 0;
	long lRetHide = RegOpenKey(HKEY_LOCAL_MACHINE, RegHide, &hKey);
	if (lRetHide == ERROR_SUCCESS)
	{
		//long a=RegQueryValueEx(hKeyHKLM, "CheckedValue", 0, &dwFlag, (LPBYTE)&val, &lsize);
		long lRetSet = RegSetValueEx(hKey, "CheckedValue", 0,REG_DWORD, 
			(CONST BYTE*)&dwFlag, //pointer to value data  
			4);						//length of value data
		if (ERROR_SUCCESS == lRetSet)
		{
			printf("隐藏选项修复成功\n");
		}
		else
		{
			printf("隐藏选项修复失败\n");
		}
	}
	else
	{
		printf("打开注册表失败\n");
	}
	RegCloseKey(hKey);
}
int main()
{
	system("color 0a");
	int bRet = EnableDebugPrivilege((char*)SE_DEBUG_NAME);
	if (bRet == FALSE)
	{
		printf("提升权限失败\n");
	}
	else
	{
		printf("提升权限成功！\n");
	}
	VirProcess();
	DeleteVir();
	FixReg();
	char nDrive[100] = { 0 };
	GetLogicalDriveStrings(100, (LPSTR)nDrive);
	for(int i=0; nDrive[i] != 0;i+=4)
	{
		char dri = nDrive[i];
		if (dri=='A'|| dri == 'B'|| dri == 'D' )
		{
			continue;
		}
		char rdri = dri;//这里需要重新赋值，因为dri不停在变
		char* pdri = &rdri;
		pdri[1] = ':';pdri[2] = '\0';
		printf("%s\n",pdri);
		CreateThread(0, 0, DeleteVirProc, (LPVOID)pdri, 0, 0);
	}
	printf("查杀完毕\n");
	getchar();
	return 0;
}