#include <stdio.h>
#include <Windows.h>
#include <Dbghelp.h>

#define LOGSIZE 1337


typedef enum {
	APPEND,
	REMOVE
} LoggerMode;

typedef enum { 
	false, 
	true 
} bool;

struct Log
{
	size_t size;
	void * addr;
	bool is_used;
};

struct Log LogArray[LOGSIZE];
char * hooked_dll = "ucrtbased.dll";


int InstallHook(LPCSTR module, LPCSTR function, void* hook, void** original)
{
	HMODULE process = GetModuleHandle(NULL);

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)process;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(((BYTE*)dos_header) + dos_header->e_lfanew);
	IMAGE_OPTIONAL_HEADER optionalHeader = nt_headers->OptionalHeader;
	IMAGE_DATA_DIRECTORY * dataDirectory = optionalHeader.DataDirectory;
	IMAGE_IMPORT_DESCRIPTOR  * iid = (IMAGE_IMPORT_DESCRIPTOR*)(((BYTE*)dos_header) + dataDirectory[1].VirtualAddress);

	size_t dir_size = ((size_t)(((BYTE*)dos_header) + dataDirectory[1].Size) / sizeof(IMAGE_IMPORT_DESCRIPTOR));
	size_t iter = 0;

	/* Loop through imported DLLs */
	while (iter < dir_size && iid->Characteristics)
	{
		const char* lib_name = ((char*)process) + iid->Name;
		if (stricmp(lib_name, module) == 0)
		{
			IMAGE_THUNK_DATA * itd_name = ((IMAGE_THUNK_DATA*)(((char*)process) + iid->OriginalFirstThunk));
			IMAGE_THUNK_DATA * itd_addr = ((IMAGE_THUNK_DATA*)(((char*)process) + iid->FirstThunk));

			/* Loop through functions in DLL */
			while (itd_name->u1.AddressOfData)
			{
				char * funcName = ((IMAGE_IMPORT_BY_NAME*)(((char*)process) + itd_name->u1.AddressOfData))->Name;
				if (strcmp(funcName, function) == 0)
				{
					/* Save address of original function from DLL */
					*original = (void*)itd_addr->u1.Function;
					/* Remove read-only protection from memory area */
					MEMORY_BASIC_INFORMATION mbi;
					VirtualQuery(itd_addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
					VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);

					/* Replace function */
					*((void**)itd_addr) = hook;

					/* Enable read-only permissions */
					VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect);

				}
				++itd_name;
				++itd_addr;
			}
			return 1;
		}
		++iid;
		++iter;
	}

	return 0;
}

void* (*RealMalloc) (size_t);
void* (*RealCalloc) (size_t, size_t);
void* (*RealRealloc) (void *, size_t);
void(*RealFree) (void *);

int MallocDebug_logger(LoggerMode mode, size_t size, void* addr)
{
	/* Append mode */
	if (addr && mode == APPEND)
	{
		if (size == 0)
			return 1;
		for (size_t i = 0; i < LOGSIZE; ++i)
		{
			if (LogArray[i].is_used == false)
			{
				LogArray[i].addr = addr;
				LogArray[i].size = size;
				LogArray[i].is_used = true;
				return 1;
			}
		}
		//printf("Alloc of mem at addr: %p\n", addr);

	}
	/* Remove mode */
	else if (addr && mode == REMOVE)
	{
		for (size_t i = 0; i < LOGSIZE; ++i)
		{
			if (LogArray[i].is_used == true && LogArray[i].addr == addr)
			{
				LogArray[i].is_used = false;
				//printf("Free of mem at addr: %p\n", addr);
				return 1;
			}
		}

	}
	return 0;
}

void* MallocDebug_malloc(size_t size)
{
	void * addr = RealMalloc(size);
	MallocDebug_logger(APPEND, size, addr);
	//printf("Hooked malloc; addr: %p, size: %d\n", addr, size);
	return addr;
}

void* MallocDebug_calloc(size_t num, size_t size)
{
	void * addr = RealCalloc(num, size);
	MallocDebug_logger(APPEND, size*num, addr);
	//printf("Hooked calloc; addr: %p, size: %d\n", addr, size);
	return addr;
}

void* MallocDebug_realloc(void * addr, size_t size)
{

	if (!MallocDebug_logger(REMOVE, 0, addr))
		puts("Realloc: freeing already freed memory block.");
	addr = RealRealloc(addr, size);
	MallocDebug_logger(APPEND, size, addr);
	//printf("Hooked realloc; addr: %p, size: %d\n", addr, size);

	return addr;
}


void MallocDebug_free(void * addr)
{
	//printf("Hooked free; addr: %p\n", addr);
	if (!MallocDebug_logger(REMOVE, 0, addr))
		puts("Free: Freeing already freed memory block.");
	RealFree(addr);
}

/* Pointers to hooked functions when unhooking */
void* (*HookedMalloc) (size_t) = MallocDebug_malloc;
void* (*HookedCalloc) (size_t, size_t) = MallocDebug_calloc;
void* (*HookedRealloc) (void *, size_t) = MallocDebug_realloc;
void(*HookedFree) (void *) = MallocDebug_free;


void MallocDebug_Init(void)
{
	/* Dummy functions to have functions listed in IAT */
	malloc(0);
	free(NULL);
	realloc(NULL, 0);
	calloc(0, 0);
	/* Initialize LogArray */
	for (size_t i = 0; i < LOGSIZE; i++)
	{
		LogArray[i].is_used = false;
	}
	/* Hook functions with our ones */
	InstallHook(hooked_dll, "malloc", (void*)MallocDebug_malloc, (void**)(&RealMalloc));
	InstallHook(hooked_dll, "free", (void*)MallocDebug_free, (void**)(&RealFree));
	InstallHook(hooked_dll, "calloc", (void*)MallocDebug_calloc, (void**)(&RealCalloc));
	InstallHook(hooked_dll, "realloc", (void*)MallocDebug_realloc, (void**)(&RealRealloc));
}


void MallocDebug_Done(void)
{
	/* Unhook functions back to original ones */
	InstallHook(hooked_dll, "malloc", (void*)(*RealMalloc), (void**)&HookedMalloc);
	InstallHook(hooked_dll, "free", (void*)(*RealFree), (void**)(&HookedFree));
	InstallHook(hooked_dll, "calloc", (void*)(*RealCalloc), (void**)&HookedCalloc);
	InstallHook(hooked_dll, "realloc", (void*)(*RealRealloc), (void**)&HookedRealloc);


	/* Check if there are any initialized memory blocks left */
	printf("======= REPORT =======\n");
	for (size_t i = 0; i < LOGSIZE; i++)
	{
		if (LogArray[i].is_used == true)
		{
			printf("Memory at addr: %p not freed up, size: %u\n", LogArray[i].addr, LogArray[i].size);
		}
	}
}


int main()
{
	char *str;

	MallocDebug_Init();

	/* Run some tests */
	str = (char *)malloc(15);
	void * str2 = malloc(50);
	/* Double free */
	free(str2);
	//free(str2);
	void * str3 = malloc(30);
	str3 = realloc(str3, 5);
	void * str4 = malloc(30);
	str4 = realloc(str4, 0);
	free(str);

	MallocDebug_Done();
	free(str3);

	return 0;
}