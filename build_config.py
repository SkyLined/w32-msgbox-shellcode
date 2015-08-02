build_config = {
  "version": "0.1",
  "projects": {
    "w32-msgbox-shellcode-hash-list.asm": {                               # List of hashes
      "files": {
        "w32-msgbox-shellcode-hash-list.asm": {
          "sources": ["w32-msgbox-shellcode-hash-list.txt"],
          "build commands": [
              ["hash\\hash.cmd",
                "--input=w32-msgbox-shellcode-hash-list.txt",
                "--output=w32-msgbox-shellcode-hash-list.asm"],
          ],
        },
      },
    },
    "w32-msgbox-shellcode.bin": {
      "architecture": "x86",
      "dependencies": ["w32-msgbox-shellcode-hash-list.asm"],
      "files": {
        "w32-msgbox-shellcode.bin": {
          "sources":  ["w32-msgbox-shellcode.asm"],
          "includes": ["w32-msgbox-shellcode-hash-list.asm"],
        },
      },
    },
    "w32-msgbox-shellcode-esp.bin": {
      "architecture": "x86",
      "dependencies": ["w32-msgbox-shellcode-hash-list.asm"],
      "files": {
        "w32-msgbox-shellcode-esp.bin": {
          "sources":  ["w32-msgbox-shellcode.asm"],
          "includes": ["w32-msgbox-shellcode-hash-list.asm"],
          "defines":  {"STACK_ALIGN": "TRUE"},
        },
      },
    },
    "w32-msgbox-shellcode-eaf.bin": {
      "architecture": "x86",
      "dependencies": ["w32-msgbox-shellcode-hash-list.asm"],
      "files": {
        "w32-msgbox-shellcode-eaf.bin": {
          "sources":  ["w32-msgbox-shellcode.asm"],
          "includes": ["w32-msgbox-shellcode-hash-list.asm"],
          "defines":  {"DEFEAT_EAF": "TRUE"},
        },
      },
    },
  },
  "test commands": ["test-w32-msgbox-shellcode.cmd"],
}
