@ECHO OFF

ECHO     + Checking shellcode for NULL bytes:
ECHO       + w32-msgbox-shellcode.bin
CALL BETA3.cmd h --nullfree w32-msgbox-shellcode.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED
ECHO       + w32-msgbox-shellcode-esp.bin
CALL BETA3.cmd h --nullfree w32-msgbox-shellcode-esp.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED
ECHO       + w32-msgbox-shellcode-eaf.bin
CALL BETA3.cmd h --nullfree w32-msgbox-shellcode-eaf.bin > nul
IF ERRORLEVEL 1 GOTO :FAILED

ECHO     + Running shellcode:
ECHO       + w32-msgbox-shellcode.bin
w32-testival.exe [$]=ascii:w32-msgbox-shellcode.bin eip=$ --EH --mem:address=28080000 2>&1 | CALL match_output.cmd "^Second chance debugger breakpoint exception at 0x2808[0-9A-F]{4}\.[\r\n]*$" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED
:: ECHO       + w32-msgbox-shellcode-esp.bin
:: w32-testival.exe [$+800]=ascii:w32-msgbox-shellcode-esp.bin eip=$+800 esp=$+7FF --EH --mem:address=28080000 | CALL match_output.cmd "^Second chance debugger breakpoint exception at 0x2808[0-9A-F]{4}\.[\r\n]*$" --verbose >nul
:: IF ERRORLEVEL 1 GOTO :FAILED
ECHO       + w32-msgbox-shellcode-eaf.bin (delayed by 2 seconds)
w32-testival.exe [$]=ascii:w32-msgbox-shellcode-eaf.bin eip=$ --EH --mem:address=28080000 2>&1 --delay=2000 | CALL match_output.cmd "^Second chance debugger breakpoint exception at 0x2808[0-9A-F]{4}\.[\r\n]*$" --verbose >nul
IF ERRORLEVEL 1 GOTO :FAILED

EXIT /B 0

:FAILED
  ECHO     * Test failed!
  EXIT /B %ERRORLEVEL%