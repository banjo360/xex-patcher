# xexpatcher

Can insert custom code, patch bytes and patch function calls, inside the XBLA version of Banjo-Kazooie.

Example of a file the software accepts (minus the comments):

```
inject:main.rdata         // inject const data
expand:main.bss           // add zero init data
call:820c27dc:hack_update // replace instruction at address 0x820c27dc to a call to function "hack_update"
jump:820c27dc:hack_update // replace instruction to a jump to function "hack_update"
patch:82132404:613d0020   // replace instruction by raw assembly (here "ori r29, r9, 0x20")
nop:824c2ff0              // replace instruction with "ori r0, r0, 0", i.e. NOOP
addr:8201372c:hack_loop   // places the address of a symbol "hack_loop" at address 0x8201372c
```

Read the code for more information and documentation.