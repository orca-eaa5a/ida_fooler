#include <Windows.h>

void __stdcall ____memcpy(void* dst, void* src, int n){
	BYTE* d = (BYTE*)dst;
	BYTE* s = (BYTE*)src;
	while(n--){
		*d++ = *s++;
	}
}

int __stdcall ___strcmp(void* dst, void* src){
	BYTE* d = (BYTE*)dst;
	BYTE* s = (BYTE*)src;
	int flag = 0;
    while (*d != NULL && *s != NULL){
		if (*s++ != *d++) break;
    }
    return (*(--s) - *(--d));
}

void __stdcall _recov_call_addr(int va, int origin_call){
	int addr = origin_call;
	void* _va = (void*)va;
	____memcpy(_va, &addr, sizeof(UINT));
}

void* get_k32(void* base_name){
	UINT k32[3] = {0x6b65726e, 0x656c3332, 0x2e646c6c};
	UINT t = 0;
	int i = 0;
	int cnt = 0;
	int ok = 3;
	wchar_t* c = (wchar_t*)base_name;
	while (true)
	{
		while(true){
			t = t << 8;
			WORD a = (WORD)*c;

			if (a <= 'Z' && a >= 'A'){
				a+=0x20;
			}
			t += a;
			cnt += 1;
			c+=1;
			if(cnt == 4 || a == 0x20){
				break;
			}
		}
		if(k32[i] == t){
			i += 1;
			cnt = 0;
			t = 0;
			if (i == ok){
				break;
			}
		}
		else{
			return NULL;
		}
	}

	return base_name;

}

void Recov_Original_API(PVOID pMem, DWORD* pRealAPI){
	char* api_name = (char*)pMem;
	char* c = (char*)pMem;
	int len = 0;
	void* k32;
	void* cur_lnk;
	void* start_lnk;
	PVOID pStr = NULL;
	__asm{
		mov eax, fs:[0x18];
		mov eax, [eax+0x30];
		mov eax, [eax+0xC];
		lea ebx, [eax+0xC];
		mov start_lnk, ebx;
L1:
		mov edx, [ebx];
		mov cur_lnk, edx;
		mov ecx, [edx+0x18];
		mov k32, ecx;
		mov edx, [edx+0x30];
		mov esi, edx;

		push esi;
		call get_k32;
		test eax, eax;
		jz L2;
		jmp L3;
L2:
		mov ebx, [cur_lnk];
		cmp start_lnk, ebx;
		jne L1;
L3:
		mov eax, k32;
	}
	
	DWORD oldProtect;
	PVOID pOldProtect = &oldProtect;
	PVOID pVirtualAlloc = (PVOID)((DWORD)k32 + 0x15ed0);
	PVOID pGetModulehandle = (PVOID)((DWORD)k32 + 0x19000);
	PVOID pVirtualProtect = (PVOID)((DWORD)k32 + 0x17D10);
	PVOID img_base = NULL;

	__asm{
		push 0;
		call pGetModulehandle;
		mov img_base, eax;
	}
	
	PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)img_base;
	PIMAGE_NT_HEADERS nt_hdr =  (PIMAGE_NT_HEADERS)(((INT64)img_base + dos_hdr->e_lfanew));
	PIMAGE_OPTIONAL_HEADER opt_hdr = (PIMAGE_OPTIONAL_HEADER)((BYTE*)&nt_hdr->OptionalHeader);
	while(true){
		DWORD real_api = (DWORD)((DWORD)k32 + (DWORD)*pRealAPI);
		api_name = c;
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

					if(___strcmp(api_name, iin->Name) == 0){
						__asm{
							push pOldProtect;
							push PAGE_READWRITE;
							push 0x1000;
							push thunk;
							call pVirtualProtect;
						}
						____memcpy((PVOID)&thunk->u1.AddressOfData, &real_api, sizeof(PVOID));
						____memcpy((PVOID)&thunk->u1.ForwarderString, &real_api, sizeof(PVOID));
						____memcpy((PVOID)&thunk->u1.Function, &real_api, sizeof(PVOID));
						____memcpy((PVOID)&thunk->u1.Ordinal, &real_api, sizeof(PVOID));
					}

					origin_thunk = (PIMAGE_THUNK_DATA)((UINT64)origin_thunk + sizeof(IMAGE_THUNK_DATA));
					thunk = (PIMAGE_THUNK_DATA)((UINT64)thunk + sizeof(IMAGE_THUNK_DATA));
				}while (origin_thunk->u1.AddressOfData != 0);
				idx+=1;
				IID = (PIMAGE_IMPORT_DESCRIPTOR)((UINT64)idd_rva + idx*sizeof(IMAGE_IMPORT_DESCRIPTOR));
			}while(IID->Characteristics != NULL);
		}
		while(*c != NULL){
			*c++;
		}
		if(*(c+1) != NULL){
			*c++;
			pRealAPI = (DWORD*)((DWORD)pRealAPI + sizeof(DWORD));
		}
		else{
			break;
		}
	}


	PVOID entry = (PVOID)((DWORD)img_base + opt_hdr->AddressOfEntryPoint);
	__asm{
		push pOldProtect;
		push PAGE_EXECUTE_READWRITE;
		push 0x1000;
		push entry;
		call pVirtualProtect;
	}

}

int main(){
	__asm{
		push 0x12345678; // <-- api_name
		push 0xFFAAFFAA;
		call Recov_Original_API;
	}

	_recov_call_addr(0x01880188, 0x01880188);
	__asm{
		mov eax, 0xEAA5A;
		push eax;
		ret
	}
	
}