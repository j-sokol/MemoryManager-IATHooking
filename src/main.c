#include <stdio.h>
#include <Windows.h>
#include <Dbghelp.h>

#define LOGSIZE 1337

struct Log
{
	size_t size;
	void * addr;
	char is_used;
};

struct Log LogArray[LOGSIZE];
char * hooked_dll = "ucrtbased.dll";

int ModifyImportTable(IMAGE_IMPORT_DESCRIPTOR* iid, void* target,void* replacement)
{
	IMAGE_THUNK_DATA* itd = (IMAGE_THUNK_DATA*)(((char*)GetModuleHandle(NULL)) + iid->FirstThunk);
	while (itd->u1.Function)
	{
		if (((void*)itd->u1.Function) == target)
		{
			/* Remove read-only protection from memory area */
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(itd, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);

			/* Replace function in IAT */
			*((void**)itd) = replacement;

			/* Enable read-only permissions */
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect);

			return 1;
		}

		++itd;
	}
	return 0;
}


int InstallHook(LPCSTR module, LPCSTR function, void* hook, void** original)
{
	HMODULE process = GetModuleHandle(NULL);

	/* Save address of original function from DLL */
	*original = (void*)GetProcAddress(GetModuleHandleA(module), function);
	
	ULONG entrySize;
	IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToData(process, 1, IMAGE_DIRECTORY_ENTRY_IMPORT, &entrySize);

	/* Loop through imported DLLs */
	while (iid->Name)
	{
		const char* name = ((char*)process) + iid->Name;
		if (stricmp(name, module) == 0)
			return ModifyImportTable(iid, *original, hook);
		++iid;
	}

	return 0;
}

int InstallUnhook(LPCSTR module, LPCSTR function, void* hook, void** original)
{
	HMODULE process = GetModuleHandle(NULL);
	ULONG entrySize;
	IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToData(process, 1, IMAGE_DIRECTORY_ENTRY_IMPORT, &entrySize);

	/* Loop through imported DLLs */
	while (iid->Name)
	{
		const char* name = ((char*)process) + iid->Name;
		if (stricmp(name, module) == 0)
			return ModifyImportTable(iid, *original, hook);
		iid += 1;
	}
	return 0;
}

int (__stdcall *RealMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
void* (*RealMalloc) (size_t);
void* (*RealCalloc) (size_t, size_t);
void* ( *RealRealloc) (void *, size_t);
void ( *RealFree) (void *);

int MallocDebug_logger(char mode, size_t size, void* addr)
{
	if (addr && mode == 'a')
	{
		if (size == 0)
			return 1;
		for (size_t i = 0; i < LOGSIZE; ++i)
		{
			if (LogArray[i].is_used == 'n')
			{
				LogArray[i].addr = addr;
				LogArray[i].size = size;
				LogArray[i].is_used = 'y';
				return 1;
			}
		}
		printf("Alloc of mem at addr: %p\n", addr);

	}
	else if (addr && mode == 'r')
	{
		for (size_t i = 0; i < LOGSIZE; ++i)
		{
			if (LogArray[i].is_used == 'y' && LogArray[i].addr == addr)
			{
				LogArray[i].is_used = 'n';
				printf("Free of mem at addr: %p\n", addr);
				return 1;
			}
		}

	}
	return 0;
}

void* MallocDebug_malloc(size_t size)
{
	void * addr = RealMalloc(size);
	MallocDebug_logger('a', size, addr);
	printf("Hooked malloc; addr: %p, size: %d\n", addr, size);
	return addr;
}

void* MallocDebug_calloc(size_t num, size_t size)
{
	void * addr = RealCalloc(num, size);
	MallocDebug_logger('a', size*num, addr);
	printf("Hooked calloc; addr: %p, size: %d\n", addr, size);
	return addr;
}

void* MallocDebug_realloc(void * addr, size_t size)
{

	MallocDebug_logger('r', 0, addr);
	addr = RealRealloc(addr, size);
	MallocDebug_logger('a', size, addr);
	printf("Hooked realloc; addr: %p, size: %d\n", addr, size);

	return addr;
}


void MallocDebug_free(void * addr)
{
	printf("Hooked free; addr: %p\n", addr);
	if (MallocDebug_logger('r', 0, addr))
		RealFree(addr);
}

/* Pointers to hooked functions when unhooking */
void* (*HookedMalloc) (size_t) = MallocDebug_malloc;
void* (*HookedCalloc) (size_t, size_t) = MallocDebug_calloc;
void* (*HookedRealloc) (void *, size_t) = MallocDebug_realloc;
void  (*HookedFree) (void *) = MallocDebug_free;


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
		LogArray[i].is_used = 'n';
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
	InstallUnhook(hooked_dll, "malloc", (void*)(*RealMalloc), (void**)&HookedMalloc);
	InstallUnhook(hooked_dll, "free", (void*)(*RealFree), (void**)(&HookedFree));
	InstallUnhook(hooked_dll, "calloc", (void*)(*RealCalloc), (void**)&HookedCalloc);
	InstallUnhook(hooked_dll, "realloc", (void*)(*RealRealloc), (void**)&HookedRealloc);

	/* Check if there are any initialized memory blocks left */
	printf("======= REPORT =======\n");
	for (size_t i = 0; i < LOGSIZE; i++)
	{
		if (LogArray[i].is_used == 'y')
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
	free(str2);
	void * str3 = realloc(malloc(30), 5);
	void * str4 = realloc(malloc(30), 0);
	free(str);

	MallocDebug_Done();
	free(str3);

	return 0;
}