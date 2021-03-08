#include <stdio.h>
#include <Windows.h>

int main(){
	const char* forged_api = "CreateThread";

	/*
	DWORD target_api_addr = 0x77864060; //(DWORD)GetProcAddress(k32lib, "CreateProcessA");
	
	HANDLE img_base = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)img_base;
	PIMAGE_NT_HEADERS nt_hdr =  (PIMAGE_NT_HEADERS)(((INT64)img_base + dos_hdr->e_lfanew));
	PIMAGE_FILE_HEADER file_hdr = (PIMAGE_FILE_HEADER)(BYTE*)(&nt_hdr->FileHeader);
	PIMAGE_OPTIONAL_HEADER opt_hdr = (PIMAGE_OPTIONAL_HEADER)((BYTE*)&nt_hdr->OptionalHeader);

	WORD numberOfSection = file_hdr->NumberOfSections;

	PIMAGE_SECTION_HEADER sec_hdr = NULL;
	for(WORD i = 0; numberOfSection > i; i++){
		sec_hdr = (PIMAGE_SECTION_HEADER)((BYTE*)&nt_hdr->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER) + sizeof(IMAGE_SECTION_HEADER)*(i));
		if(strcmp((const char*)sec_hdr->Name, ".rsrc") == 0){
			break;
		}
	}
	DWORD idd_va =  nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if(idd_va){
		LPVOID idd_rva = (LPVOID)((DWORD)img_base + idd_va);
		PIMAGE_IMPORT_DESCRIPTOR IID = (PIMAGE_IMPORT_DESCRIPTOR)idd_rva;
		int idx = 0;
		do{
			PIMAGE_THUNK_DATA origin_thunk = (PIMAGE_THUNK_DATA)((UINT64)(img_base)+IID->OriginalFirstThunk);
			PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((UINT64)(img_base)+IID->FirstThunk);
			do{
				UINT64 iin_rva = origin_thunk->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME iin = (PIMAGE_IMPORT_BY_NAME)((UINT64)(img_base)+iin_rva);

				if(strcmp(forged_api, iin->Name) == 0){
					memcpy((PVOID)&thunk->u1.AddressOfData, &target_api_addr, sizeof(PVOID));
					memcpy((PVOID)&thunk->u1.ForwarderString, &target_api_addr, sizeof(PVOID));
					memcpy((PVOID)&thunk->u1.Function, &target_api_addr, sizeof(PVOID));
					memcpy((PVOID)&thunk->u1.Ordinal, &target_api_addr, sizeof(PVOID));
				}
				printf("%s\n", iin->Name);

				origin_thunk = (PIMAGE_THUNK_DATA)((UINT64)origin_thunk + sizeof(IMAGE_THUNK_DATA));
				thunk = (PIMAGE_THUNK_DATA)((UINT64)thunk + sizeof(IMAGE_THUNK_DATA));
			}while (origin_thunk->u1.AddressOfData != 0);
			idx+=1;
			IID = (PIMAGE_IMPORT_DESCRIPTOR)((UINT64)idd_rva + idx*sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}while(IID->Characteristics != NULL);
	}
	*/
	STARTUPINFOA si = {0, };
	PROCESS_INFORMATION pi = {0,};
	char cmd[] = "notepad.exe";
	CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}