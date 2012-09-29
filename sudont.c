/**
 * super user don't - execute a command without admin privileges
 * Copyright (c) 2012 Bob Carroll
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <tchar.h>
#include <windows.h>

DWORD GetFileMandatoryLabel(wchar_t *file)
{
	HANDLE hheap;
	SECURITY_DESCRIPTOR *sd;
	DWORD szreq;
	BOOL present;
	PACL sacl;
	BOOL defaulted;
	ACL_SIZE_INFORMATION asi;
	void *mlace;
	SID *mlsid;
	DWORD mlrid = -1;

	GetFileSecurity(file, LABEL_SECURITY_INFORMATION, NULL, 0, &szreq);
	if (szreq == 0)
		return mlrid;

	hheap = GetProcessHeap();
	sd = (SECURITY_DESCRIPTOR *)HeapAlloc(hheap, HEAP_ZERO_MEMORY, szreq);

	if (!GetFileSecurity(file, LABEL_SECURITY_INFORMATION, sd, szreq, &szreq)) {
		HeapFree(hheap, 0, sd);
		CloseHandle(hheap);
		return mlrid;
	}

	if (!GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted)) {
		HeapFree(hheap, 0, sd);
		CloseHandle(hheap);
		return mlrid;
	}

	if (present) {
		if (!GetAclInformation(sacl, (void *)&asi, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
			HeapFree(hheap, 0, sd);
			CloseHandle(hheap);
			return mlrid;
		}

		if (asi.AceCount == 1) {
			if (!GetAce(sacl, 0, &mlace)) {
				HeapFree(hheap, 0, sd);
				CloseHandle(hheap);
				return mlrid;
			}

			mlsid = (SID *)&((SYSTEM_MANDATORY_LABEL_ACE *)mlace)->SidStart;

			if (IsValidSid(mlsid))
				mlrid = mlsid->SubAuthority[0];
		}
	}

	HeapFree(hheap, 0, sd);
	CloseHandle(hheap);

	return mlrid;
}

BOOL SetTokenMandatoryLabel(HANDLE token, DWORD mlrid)
{
	PSID integsid;
	SID_IDENTIFIER_AUTHORITY mandlblauth = SECURITY_MANDATORY_LABEL_AUTHORITY;
	TOKEN_MANDATORY_LABEL tml;
	BOOL result;

	if (!AllocateAndInitializeSid(&mandlblauth, 1, mlrid, 0, 0, 0, 0, 0, 0, 0, &integsid))
		return FALSE;

	tml.Label.Sid = integsid;
	tml.Label.Attributes = SE_GROUP_INTEGRITY;

	result = SetTokenInformation(token, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL));
	FreeSid(integsid);

	return result;
}

int wmain(int argc, wchar_t* argv[])
{
	wchar_t cmdline[MAX_PATH];
	HANDLE hcurtok;
	HANDLE hnewtok;
	LUID incrquotaluid;
	TOKEN_PRIVILEGES newtp;
	TOKEN_PRIVILEGES oldtp;
	DWORD dwoldtpsz;
	PSID adminsid;
	SID_IDENTIFIER_AUTHORITY ntauth = SECURITY_NT_AUTHORITY;
	SID_AND_ATTRIBUTES saa;
	DWORD mlrid;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	int i, pos = 0, len = 0;

	if (argc < 2) {
		wprintf(L"USAGE: sudont <command> [ ... ]\n");
		return 0;
	}

	ZeroMemory(&incrquotaluid, sizeof(LUID));
	LookupPrivilegeValue(NULL, SE_INCREASE_QUOTA_NAME, &incrquotaluid);

	ZeroMemory(&newtp, sizeof(TOKEN_PRIVILEGES));
	newtp.PrivilegeCount = 1;
	newtp.Privileges[0].Luid = incrquotaluid;
	newtp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!OpenProcessToken(
			GetCurrentProcess(), 
			TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, 
			&hcurtok)) {
		wprintf(L"sudont: failed to open process token (%d)\n", GetLastError());
		return 0;
	}

	if (!AdjustTokenPrivileges(hcurtok, FALSE, &newtp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwoldtpsz)) {
		wprintf(L"sudont: failed to enable impersonation privilege (%d)\n", GetLastError());
		CloseHandle(hcurtok);
		return 0;
	}

	if (!AllocateAndInitializeSid(
			&ntauth, 
			2, 
			SECURITY_BUILTIN_DOMAIN_RID, 
			DOMAIN_ALIAS_RID_ADMINS, 
			0, 
			0, 
			0, 
			0, 
			0, 
			0, 
			&adminsid)) {
		wprintf(L"sudont: failed to allocate admin SID (%d)\n", GetLastError());
		CloseHandle(hcurtok);
		return 0;
	}

	saa.Sid = adminsid;
	saa.Attributes = SE_GROUP_USE_FOR_DENY_ONLY;
	
	if (!CreateRestrictedToken(hcurtok, DISABLE_MAX_PRIVILEGE, 1, &saa, 0, 0, 0, 0, &hnewtok)) {
		wprintf(L"sudont: failed to create restricted token (%d)\n", GetLastError());
		CloseHandle(hcurtok);
		FreeSid(adminsid);
		return 0;
	}

	CloseHandle(hcurtok);
	FreeSid(adminsid);

	mlrid = GetFileMandatoryLabel(argv[1]);

	if (mlrid == -1 || mlrid > SECURITY_MANDATORY_MEDIUM_RID)
		mlrid = SECURITY_MANDATORY_MEDIUM_RID;

	if (!SetTokenMandatoryLabel(hnewtok, mlrid)) {
		wprintf(L"sudont: failed to set token mandatory label (%d)\n", GetLastError());
		CloseHandle(hnewtok);
		return 0;
	}

	for (i = 1; i < argc; i++) {
		if (pos > 0)
			cmdline[pos++] = ' ';

		len = wcslen(argv[i]);
		if (pos + len + 2 >= MAX_PATH)
			break;

		cmdline[pos++] = '\"';
		CopyMemory(cmdline + pos, argv[i], len * sizeof(wchar_t));
		pos += len;
		cmdline[pos++] = '\"';
	}
	cmdline[pos] = '\0';

	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = L"winsta0\\default";

	if (!CreateProcessAsUser(
			hnewtok, 
			argv[1], 
			cmdline, 
			NULL, 
			NULL, 
			FALSE, 
			CREATE_NEW_CONSOLE, 
			NULL, 
			NULL, 
			&si, 
			&pi)) {
		wprintf(L"sudont: failed to create new process (%d)\n", GetLastError());
		CloseHandle(hnewtok);
		return 0;
	}
	
	CloseHandle(hnewtok);
	return pi.dwProcessId;
}
