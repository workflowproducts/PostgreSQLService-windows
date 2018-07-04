#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <signal.h>

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

STARTUPINFOA si;
PROCESS_INFORMATION pi;

int ServiceMain(int argc, char **argv);
void ControlHandler(DWORD request);
int InitService();

char str_log[512] = { 0 };

BOOL AddUserToTokenDacl(HANDLE hToken);

int WriteToLog(char *str) {
	FILE *logfile;
	logfile = fopen(str_log, "a+");
	if (logfile == NULL) {
		return -1;
	}
	fprintf(logfile, "%s\n", str);
	fclose(logfile);
	return 0;
}

int main() {
	if (GetModuleFileNameA(NULL, str_log, 512) == 0) {
		return 1;
	}
	char *ptr_log = strrchr(str_log, '\\');
	if (ptr_log == 0) {
		return 1;
	}
	memcpy(ptr_log - 3, "log", 3);
	memcpy(ptr_log + 1, "PostgreSQLService.log", strlen("PostgreSQLService.log") + 1);

	SERVICE_TABLE_ENTRY ServiceTable[2];
	ServiceTable[0].lpServiceName = L"Production Line PostgreSQL";
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;
	// Start the control dispatcher thread for our service
	StartServiceCtrlDispatcher(ServiceTable);
	return 0;
}

int ServiceMain(int argc, char **argv) {
	int error;

	WriteToLog("ServiceMain");

	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandler(L"Production Line PostgreSQL", (LPHANDLER_FUNCTION)ControlHandler);
	if (hStatus == (SERVICE_STATUS_HANDLE)0) {
		// Registering Control Handler failed
		return 1;
	}
	// Initialize Service 
	error = InitService();
	if (error != 0) {
		// Initialization failed
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ServiceStatus.dwWin32ExitCode = -1;
		SetServiceStatus(hStatus, &ServiceStatus);
		return 1;
	}
	// We report the running status to SCM. 
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &ServiceStatus);

	WriteToLog("Starting the loop.");

	// The worker loop of a service
	while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
		DWORD intExitCode = 0;
		GetExitCodeProcess(pi.hProcess, &intExitCode);
		if (intExitCode != STILL_ACTIVE) {
			char str_intExitCode[25] = { 0 };
			sprintf(str_intExitCode, "%d", intExitCode);

			WriteToLog("PostgreSQL stopped");
			WriteToLog(str_intExitCode);

			error = InitService();
			if (error != 0) {
				// Initialization failed
				ServiceStatus.dwCurrentState = SERVICE_STOPPED;
				ServiceStatus.dwWin32ExitCode = -1;
				SetServiceStatus(hStatus, &ServiceStatus);
				return 1;
			}
		}
		Sleep(1000);
	}

	WriteToLog("Loop is stopped.");

	return 0;
}

// Service initialization
int InitService() {
	WriteToLog("InitService");
	char str_bin[256] = { 0 };
	char str_cmdline[512] = "\"";
	char str_cmdline1[512] = { 0 };
	
	if (GetModuleFileNameA(NULL, str_bin, 255) == 0) {
		return 1;
	}
	char *ptr_bin = strrchr(str_bin, '\\');
	if (ptr_bin == 0) {
		return 1;
	}
	memcpy(ptr_bin + 1, "postgres.exe", strlen("postgres.exe") + 1);
	
	WriteToLog(str_bin);

	memcpy(str_cmdline + 1, str_bin, strlen(str_bin) + 1);
	memcpy(str_cmdline + strlen(str_cmdline), "\" -D \"\\ProgramData", strlen("\" -D \"\\ProgramData") + 1);
	
	if (GetModuleFileNameA(NULL, str_cmdline1, 255) == 0) {
		return 1;
	}
	char *ptr_cmdline = strrchr(str_cmdline1, '\\');
	if (ptr_cmdline == 0) {
		return 1;
	}
	memcpy(ptr_cmdline - 4, "\\data\"", strlen("\\data\"") + 1);
	ptr_cmdline = strstr(str_cmdline1, "Program Files");
	ptr_cmdline = strstr(ptr_cmdline, "\\");
	memcpy(str_cmdline + strlen(str_cmdline), ptr_cmdline, strlen(ptr_cmdline) + 1);
	
	WriteToLog(str_cmdline);

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	//si.hStdError = GetStdHandle(STD_OUTPUT_HANDLE);
	//si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	//si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	ZeroMemory(&pi, sizeof(pi));

	WriteToLog("InitService()");
	WriteToLog(str_cmdline);

	int r;
	BOOL b;
	HANDLE origToken;
	HANDLE restrictedToken;
	SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
	SID_AND_ATTRIBUTES dropSids[2];
	// Open the current token to use as a base for the restricted one */
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &origToken)) {
		WriteToLog("could not open process token\n");
		return 1;
	}

	ZeroMemory(&dropSids, sizeof(dropSids));
	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &dropSids[0].Sid) ||
		!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_POWER_USERS, 0, 0, 0, 0, 0, 0, &dropSids[1].Sid)) {
		WriteToLog("could not allocate SIDs\n");
		return 1;
	}

	b = CreateRestrictedToken(origToken,
		DISABLE_MAX_PRIVILEGE,
		sizeof(dropSids) / sizeof(dropSids[0]),
		dropSids,
		0, NULL,
		0, NULL,
		&restrictedToken);

	FreeSid(dropSids[1].Sid);
	FreeSid(dropSids[0].Sid);
	CloseHandle(origToken);

	if (!b) {
		WriteToLog("could not create restricted token\n");
		return 1;
	}

	AddUserToTokenDacl(restrictedToken);

	SetLastError(0);
	// Start the child process.
	if (!CreateProcessAsUserA(
		restrictedToken,
		str_bin,
		str_cmdline,
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_NEW_CONSOLE | CREATE_NO_WINDOW,
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		) {
		char str_int_last_error[25] = { 0 };
		sprintf(str_int_last_error, "%d", GetLastError());

		WriteToLog("PostgreSQL not started.");
		WriteToLog(str_int_last_error);

		fprintf(stderr, "CreateProcessAsUserA fail\n");

		return 1;
	}
	fprintf(stderr, "CreateProcessAsUserA success\n");


	WriteToLog("PostgreSQL not started.");
	
	CloseHandle(restrictedToken);

	DWORD pid = GetProcessId(pi.hProcess);
	char str_pid[25] = { 0 };
	sprintf(str_pid, "%d", pid);

	WriteToLog("PostgreSQL started");
	WriteToLog(str_pid);
	return 0;
}

// Control handler function
void ControlHandler(DWORD request) {
	switch (request) {
	case SERVICE_CONTROL_STOP: // fall through
	case SERVICE_CONTROL_SHUTDOWN:
		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		ServiceStatus.dwWaitHint = 30000;
		ServiceStatus.dwCheckPoint += 1;

		SetServiceStatus(hStatus, &ServiceStatus);

		// Shutdown PostgreSQL
		FreeConsole();
		if (AttachConsole(pi.dwProcessId)) {
			WriteToLog("test1");

			signal(SIGINT, SIG_IGN);
			GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
			//WaitForSingleObject(pi.hProcess, INFINITE);

			WriteToLog("test2");

			FreeConsole();

			WriteToLog("test3");

			// Close process and thread handles. 
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			WriteToLog("test4");

			WriteToLog("test5");
		}
		WriteToLog("test6");

		ServiceStatus.dwWin32ExitCode = 0;
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ServiceStatus.dwWaitHint = 0;

		break;

	default:
		break;
	}

	// Report current status
	SetServiceStatus(hStatus, &ServiceStatus);

	return;
}

// taken from postgresql 9.6.2
/*
* GetTokenUser(HANDLE hToken, PTOKEN_USER *ppTokenUser)
*
* Get the users token information from a process token.
*
* The caller of this function is responsible for calling LocalFree() on the
* returned TOKEN_USER memory.
*/
static BOOL
GetTokenUser(HANDLE hToken, PTOKEN_USER *ppTokenUser)
{
	DWORD		dwLength;

	*ppTokenUser = NULL;

	if (!GetTokenInformation(hToken,
		TokenUser,
		NULL,
		0,
		&dwLength))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			*ppTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);

			if (*ppTokenUser == NULL)
			{
				WriteToLog("could not allocate memory\n");
				return FALSE;
			}
		} else
		{
			WriteToLog("could not get token information buffer size\n");
			return FALSE;
		}
	}

	if (!GetTokenInformation(hToken,
		TokenUser,
		*ppTokenUser,
		dwLength,
		&dwLength))
	{
		LocalFree(*ppTokenUser);
		*ppTokenUser = NULL;

		WriteToLog("could not get token information\n");
		return FALSE;
	}

	/* Memory in *ppTokenUser is LocalFree():d by the caller */
	return TRUE;
}

/*
* AddUserToTokenDacl(HANDLE hToken)
*
* This function adds the current user account to the restricted
* token used when we create a restricted process.
*
* This is required because of some security changes in Windows
* that appeared in patches to XP/2K3 and in Vista/2008.
*
* On these machines, the Administrator account is not included in
* the default DACL - you just get Administrators + System. For
* regular users you get User + System. Because we strip Administrators
* when we create the restricted token, we are left with only System
* in the DACL which leads to access denied errors for later CreatePipe()
* and CreateProcess() calls when running as Administrator.
*
* This function fixes this problem by modifying the DACL of the
* token the process will use, and explicitly re-adding the current
* user account.  This is still secure because the Administrator account
* inherits its privileges from the Administrators group - it doesn't
* have any of its own.
*/
BOOL
AddUserToTokenDacl(HANDLE hToken)
{
	int			i;
	ACL_SIZE_INFORMATION asi;
	ACCESS_ALLOWED_ACE *pace;
	DWORD		dwNewAclSize;
	DWORD		dwSize = 0;
	DWORD		dwTokenInfoLength = 0;
	PACL		pacl = NULL;
	PTOKEN_USER pTokenUser = NULL;
	TOKEN_DEFAULT_DACL tddNew;
	TOKEN_DEFAULT_DACL *ptdd = NULL;
	TOKEN_INFORMATION_CLASS tic = TokenDefaultDacl;
	BOOL		ret = FALSE;

	/* Figure out the buffer size for the DACL info */
	if (!GetTokenInformation(hToken, tic, (LPVOID)NULL, dwTokenInfoLength, &dwSize))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			ptdd = (TOKEN_DEFAULT_DACL *)LocalAlloc(LPTR, dwSize);
			if (ptdd == NULL)
			{
				WriteToLog("could not allocate memory\n");
				goto cleanup;
			}

			if (!GetTokenInformation(hToken, tic, (LPVOID)ptdd, dwSize, &dwSize))
			{
				WriteToLog("could not get token information\n");
				goto cleanup;
			}
		} else
		{
			WriteToLog("could not get token information buffer size\n");
			goto cleanup;
		}
	}

	/* Get the ACL info */
	if (!GetAclInformation(ptdd->DefaultDacl, (LPVOID)&asi,
		(DWORD) sizeof(ACL_SIZE_INFORMATION),
		AclSizeInformation))
	{
		WriteToLog("could not get ACL information\n");
		goto cleanup;
	}

	/* Get the current user SID */
	if (!GetTokenUser(hToken, &pTokenUser))
		goto cleanup;			/* callee printed a message */

								/* Figure out the size of the new ACL */
	dwNewAclSize = asi.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) +
		GetLengthSid(pTokenUser->User.Sid) - sizeof(DWORD);

	/* Allocate the ACL buffer & initialize it */
	pacl = (PACL)LocalAlloc(LPTR, dwNewAclSize);
	if (pacl == NULL)
	{
		WriteToLog("could not allocate %lu bytes of memory\n", dwNewAclSize);
		goto cleanup;
	}

	if (!InitializeAcl(pacl, dwNewAclSize, ACL_REVISION))
	{
		WriteToLog("could not initialize ACL\n");
		goto cleanup;
	}

	/* Loop through the existing ACEs, and build the new ACL */
	for (i = 0; i < (int)asi.AceCount; i++)
	{
		if (!GetAce(ptdd->DefaultDacl, i, (LPVOID *)&pace))
		{
			WriteToLog("could not get ACE\n");
			goto cleanup;
		}

		if (!AddAce(pacl, ACL_REVISION, MAXDWORD, pace, ((PACE_HEADER)pace)->AceSize))
		{
			WriteToLog("could not add ACE\n");
			goto cleanup;
		}
	}

	/* Add the new ACE for the current user */
	if (!AddAccessAllowedAceEx(pacl, ACL_REVISION, OBJECT_INHERIT_ACE, GENERIC_ALL, pTokenUser->User.Sid))
	{
		WriteToLog("could not add access allowed ACE\n");
		goto cleanup;
	}

	/* Set the new DACL in the token */
	tddNew.DefaultDacl = pacl;

	if (!SetTokenInformation(hToken, tic, (LPVOID)&tddNew, dwNewAclSize))
	{
		WriteToLog("could not set token information\n");
		goto cleanup;
	}

	ret = TRUE;

cleanup:
	if (pTokenUser)
		LocalFree((HLOCAL)pTokenUser);

	if (pacl)
		LocalFree((HLOCAL)pacl);

	if (ptdd)
		LocalFree((HLOCAL)ptdd);

	return ret;
}
