#include <windows.h>
#include <stdio.h>


#define warn(msg, ...) printf("[!] - " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] - " msg "\n", ##__VA_ARGS__)
#define done(msg, ...) printf("[+] - " msg "\n", ##__VA_ARGS__)


/* ------------- Define original load library function ------------- */
typedef int (*LoadLibPtr)(LPCSTR);
LoadLibPtr originalLoadLibrary = (LoadLibPtr)NULL; // &LoadLibraryA;

int __stdcall HookedLoadLibraryA(LPCSTR lpLibFileName) {
    const char* filename = strrchr(lpLibFileName, '\\');
    if (strcmp(filename, "\\main.dll") == 0) {
        printf("EVIL DLL DETECTED!!!\n");
        return 1;
    }

    printf("It's ok\n");
    originalLoadLibrary(lpLibFileName);
    return 0;
}



int main() {
    uintptr_t oldLoadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");

    uintptr_t baseAddressKernel32 = (uintptr_t)GetModuleHandle("kernel32");

    // Creating the chain to retrieve the EAT from the base address
    // dos header -> nt headers -> optionnal headers -> data directories -> directory entry export
    PIMAGE_DOS_HEADER                dosHeaders = (PIMAGE_DOS_HEADER)baseAddressKernel32;
    PIMAGE_NT_HEADERS64               ntHeaders = (PIMAGE_NT_HEADERS64)(baseAddressKernel32 + dosHeaders->e_lfanew);
    IMAGE_DATA_DIRECTORY    exportDataDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    uintptr_t               exportDirectoryAddr = baseAddressKernel32 + exportDataDirectory.VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY     exportDirectory = (PIMAGE_EXPORT_DIRECTORY)exportDirectoryAddr;

    info("Base address     @ 0x%llx", baseAddressKernel32);
    info("Export directory @ 0x%llx", exportDirectory);

    // ------------- RETRIEVING LOADLIBRARYA OFFSET ------------- //

    DWORD* exportNameTable    = (DWORD*)(baseAddressKernel32 + exportDirectory->AddressOfNames);
    DWORD* exportAddressTable = (DWORD*)(baseAddressKernel32 + exportDirectory->AddressOfFunctions);
    WORD*  exportOrdinalTable = (WORD*)(baseAddressKernel32 + exportDirectory->AddressOfNameOrdinals);

    info("[ Export name table    @ 0x%llx ]", exportNameTable);
    info("[ Export address table @ 0x%llx ]", exportAddressTable);
    info("[ Export ordinal table @ 0x%llx ]", exportOrdinalTable); 

    char*     currName = NULL;
    WORD      currOrd  = 0;
    uintptr_t currAddr = 0;

    for (int i = 0; i < exportDirectory->NumberOfNames; i++) {
        currName = (char*)(baseAddressKernel32 + exportNameTable[i]);
        currOrd  = exportOrdinalTable[i];
        currAddr = (uintptr_t)(baseAddressKernel32 + exportAddressTable[currOrd]);

        if (strncmp(currName, "LoadLibraryA", 12) == 0) {
            done("export %d/%d: %s @ 0x%llx (offset: %x)", i, exportDirectory->NumberOfNames-1, currName, currAddr, exportAddressTable[currOrd]);
            break;
        }
    }



    LPVOID ptrToExportAddress = (LPVOID)&exportAddressTable[currOrd];
    LoadLibPtr originalLoadLibrary = (LoadLibPtr)(baseAddressKernel32 + exportAddressTable[currOrd]);  // TODO: maybe replace this

    // ------------- ALLOCATING SPACE FOR OUR JUMP ------------- //

    DWORD moduleSize = ntHeaders->OptionalHeader.SizeOfImage;
    size_t allocSize = 0x100;
    LPVOID jumpAddress = NULL;
    LPVOID targetAddress = (LPVOID)(baseAddressKernel32 + moduleSize);

    while (jumpAddress == NULL) {
        info("\tTrying to allocate memory @ 0x%llx...", targetAddress);
        jumpAddress = VirtualAlloc(targetAddress, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        targetAddress += allocSize;
    } 

    done("Allocated memory @ 0x%llx", jumpAddress);

    DWORD offsetJmp = (DWORD)(jumpAddress - baseAddressKernel32);
    if (offsetJmp > (DWORD)0xffffff) {
        warn("Offset too big, can't hook it. (%llx)", offsetJmp);
        return EXIT_FAILURE;        
    }

    done("Offset is %llx and is in range of the EAT", offsetJmp);

    /* ------------- WRITING JMP TO OUR SPACE ------------- */

    uintptr_t hookAddress = (uintptr_t)&HookedLoadLibraryA;

    BYTE jumpPayload[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
    memcpy(&jumpPayload[2], &hookAddress, sizeof(hookAddress));

    info("Writing our jump payload...");

    // Writing our jump payload to the jump address
    DWORD dwOldProtect = 0;
    VirtualProtect(jumpAddress, sizeof(jumpPayload), PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(jumpAddress, jumpPayload, sizeof(jumpPayload));
    VirtualProtect(jumpAddress, sizeof(jumpPayload), dwOldProtect, &dwOldProtect);

    done("Wrote [JMP %llx] @ %llx", originalLoadLibrary, jumpAddress);
    info("Writing offset to the EAT (@ 0x%llx)", ptrToExportAddress);

    // Writing the offset to the jump address to the export table at LoadLIbraryA
    VirtualProtect(ptrToExportAddress, sizeof(offsetJmp), PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(ptrToExportAddress, &offsetJmp, sizeof(offsetJmp));
    VirtualProtect(ptrToExportAddress, sizeof(offsetJmp), dwOldProtect, &dwOldProtect);

    done("Success.");

    printf("\n\n");
    printf("LoadLibraryA before hooking: 0x%llx\n", originalLoadLibrary);
    printf("LoadLibraryA after  hooking: 0x%llx\n", GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA"));

    return EXIT_SUCCESS;
}

