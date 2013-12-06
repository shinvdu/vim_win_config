Microsoft (R) COFF/PE Dumper Version 10.00.30319.01
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file sum.exe

File Type: EXECUTABLE IMAGE

  00401000: 55                 push        ebp
  00401001: 89 E5              mov         ebp,esp
  00401003: 83 EC 18           sub         esp,18h
  00401006: C7 45 FC 00 00 00  mov         dword ptr [ebp-4],0
            00
  0040100D: 83 C4 F4           add         esp,0FFFFFFF4h
  00401010: 8D 45 FC           lea         eax,[ebp-4]
  00401013: 50                 push        eax
  00401014: FF 35 38 60 40 00  push        dword ptr ds:[00406038h]
  0040101A: 8D 45 F8           lea         eax,[ebp-8]
  0040101D: 50                 push        eax
  0040101E: 68 04 60 40 00     push        406004h
  00401023: 68 00 60 40 00     push        406000h
  00401028: E8 6B 41 00 00     call        00405198
  0040102D: C9                 leave
  0040102E: C3                 ret
  0040102F: 90                 nop
  00401030: 55                 push        ebp
  00401031: 89 E5              mov         ebp,esp
  00401033: 83 EC 08           sub         esp,8
  00401036: 8B 15 3C 60 40 00  mov         edx,dword ptr ds:[0040603Ch]
  0040103C: 85 D2              test        edx,edx
  0040103E: 74 7B              je          004010BB
  00401040: A1 74 81 40 00     mov         eax,dword ptr ds:[00408174h]
  00401045: 89 10              mov         dword ptr [eax],edx
  00401047: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  0040104C: 85 C0              test        eax,eax
  0040104E: 74 1E              je          0040106E
  00401050: 83 C4 F8           add         esp,0FFFFFFF8h
  00401053: FF 35 3C 60 40 00  push        dword ptr ds:[0040603Ch]
  00401059: 83 C4 F4           add         esp,0FFFFFFF4h
  0040105C: 50                 push        eax
  0040105D: E8 26 41 00 00     call        00405188
  00401062: 83 C4 10           add         esp,10h
  00401065: 50                 push        eax
  00401066: E8 25 41 00 00     call        00405190
  0040106B: 83 C4 10           add         esp,10h
  0040106E: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00401073: 83 C0 20           add         eax,20h
  00401076: 74 1E              je          00401096
  00401078: 83 C4 F8           add         esp,0FFFFFFF8h
  0040107B: FF 35 3C 60 40 00  push        dword ptr ds:[0040603Ch]
  00401081: 83 C4 F4           add         esp,0FFFFFFF4h
  00401084: 50                 push        eax
  00401085: E8 FE 40 00 00     call        00405188
  0040108A: 83 C4 10           add         esp,10h
  0040108D: 50                 push        eax
  0040108E: E8 FD 40 00 00     call        00405190
  00401093: 83 C4 10           add         esp,10h
  00401096: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  0040109B: 83 C0 40           add         eax,40h
  0040109E: 74 1B              je          004010BB
  004010A0: 83 C4 F8           add         esp,0FFFFFFF8h
  004010A3: FF 35 3C 60 40 00  push        dword ptr ds:[0040603Ch]
  004010A9: 83 C4 F4           add         esp,0FFFFFFF4h
  004010AC: 50                 push        eax
  004010AD: E8 D6 40 00 00     call        00405188
  004010B2: 83 C4 10           add         esp,10h
  004010B5: 50                 push        eax
  004010B6: E8 D5 40 00 00     call        00405190
  004010BB: C9                 leave
  004010BC: C3                 ret
  004010BD: 8D 76 00           lea         esi,[esi]
  004010C0: 55                 push        ebp
  004010C1: 89 E5              mov         ebp,esp
  004010C3: 83 EC 10           sub         esp,10h
  004010C6: 56                 push        esi
  004010C7: 53                 push        ebx
  004010C8: 8B 45 08           mov         eax,dword ptr [ebp+8]
  004010CB: 31 DB              xor         ebx,ebx
  004010CD: 31 F6              xor         esi,esi
  004010CF: 8B 00              mov         eax,dword ptr [eax]
  004010D1: 8B 00              mov         eax,dword ptr [eax]
  004010D3: 3D 91 00 00 C0     cmp         eax,0C0000091h
  004010D8: 77 16              ja          004010F0
  004010DA: 3D 8D 00 00 C0     cmp         eax,0C000008Dh
  004010DF: 73 4F              jae         00401130
  004010E1: 3D 05 00 00 C0     cmp         eax,0C0000005h
  004010E6: 74 18              je          00401100
  004010E8: E9 87 00 00 00     jmp         00401174
  004010ED: 8D 76 00           lea         esi,[esi]
  004010F0: 3D 93 00 00 C0     cmp         eax,0C0000093h
  004010F5: 74 39              je          00401130
  004010F7: 3D 94 00 00 C0     cmp         eax,0C0000094h
  004010FC: 74 37              je          00401135
  004010FE: EB 74              jmp         00401174
  00401100: 83 C4 F8           add         esp,0FFFFFFF8h
  00401103: 6A 00              push        0
  00401105: 6A 0B              push        0Bh
  00401107: E8 74 40 00 00     call        00405180
  0040110C: 83 C4 10           add         esp,10h
  0040110F: 83 F8 01           cmp         eax,1
  00401112: 75 10              jne         00401124
  00401114: 83 C4 F8           add         esp,0FFFFFFF8h
  00401117: 6A 01              push        1
  00401119: 6A 0B              push        0Bh
  0040111B: E8 60 40 00 00     call        00405180
  00401120: EB 4D              jmp         0040116F
  00401122: 89 F6              mov         esi,esi
  00401124: 85 C0              test        eax,eax
  00401126: 74 4C              je          00401174
  00401128: 83 C4 F4           add         esp,0FFFFFFF4h
  0040112B: 6A 0B              push        0Bh
  0040112D: EB 3E              jmp         0040116D
  0040112F: 90                 nop
  00401130: BE 01 00 00 00     mov         esi,1
  00401135: 83 C4 F8           add         esp,0FFFFFFF8h
  00401138: 6A 00              push        0
  0040113A: 6A 08              push        8
  0040113C: E8 3F 40 00 00     call        00405180
  00401141: 83 C4 10           add         esp,10h
  00401144: 83 F8 01           cmp         eax,1
  00401147: 75 1B              jne         00401164
  00401149: 83 C4 F8           add         esp,0FFFFFFF8h
  0040114C: 6A 01              push        1
  0040114E: 6A 08              push        8
  00401150: E8 2B 40 00 00     call        00405180
  00401155: 83 C4 10           add         esp,10h
  00401158: 85 F6              test        esi,esi
  0040115A: 74 13              je          0040116F
  0040115C: E8 17 40 00 00     call        00405178
  00401161: EB 0C              jmp         0040116F
  00401163: 90                 nop
  00401164: 85 C0              test        eax,eax
  00401166: 74 0C              je          00401174
  00401168: 83 C4 F4           add         esp,0FFFFFFF4h
  0040116B: 6A 08              push        8
  0040116D: FF D0              call        eax
  0040116F: BB FF FF FF FF     mov         ebx,0FFFFFFFFh
  00401174: 89 D8              mov         eax,ebx
  00401176: 8D 65 E8           lea         esp,[ebp-18h]
  00401179: 5B                 pop         ebx
  0040117A: 5E                 pop         esi
  0040117B: C9                 leave
  0040117C: C2 04 00           ret         4
  0040117F: 90                 nop
  00401180: 55                 push        ebp
  00401181: 89 E5              mov         ebp,esp
  00401183: 83 EC 14           sub         esp,14h
  00401186: 53                 push        ebx
  00401187: 83 C4 F4           add         esp,0FFFFFFF4h
  0040118A: 68 C0 10 40 00     push        4010C0h
  0040118F: E8 14 41 00 00     call        004052A8
  00401194: 83 C4 FC           add         esp,0FFFFFFFCh
  00401197: E8 DC 3F 00 00     call        00405178
  0040119C: E8 5F FE FF FF     call        00401000
  004011A1: E8 8A FE FF FF     call        00401030
  004011A6: 83 C4 FC           add         esp,0FFFFFFFCh
  004011A9: E8 C2 3F 00 00     call        00405170
  004011AE: FF 30              push        dword ptr [eax]
  004011B0: FF 35 04 60 40 00  push        dword ptr ds:[00406004h]
  004011B6: FF 35 00 60 40 00  push        dword ptr ds:[00406000h]
  004011BC: E8 03 08 00 00     call        004019C4
  004011C1: 89 C3              mov         ebx,eax
  004011C3: 83 C4 20           add         esp,20h
  004011C6: E8 9D 3F 00 00     call        00405168
  004011CB: 83 C4 F4           add         esp,0FFFFFFF4h
  004011CE: 53                 push        ebx
  004011CF: E8 DC 40 00 00     call        004052B0
  004011D4: 55                 push        ebp
  004011D5: 89 E5              mov         ebp,esp
  004011D7: 83 EC 08           sub         esp,8
  004011DA: 83 C4 F4           add         esp,0FFFFFFF4h
  004011DD: 6A 01              push        1
  004011DF: A1 60 81 40 00     mov         eax,dword ptr ds:[00408160h]
  004011E4: FF D0              call        eax
  004011E6: E8 95 FF FF FF     call        00401180
  004011EB: 31 C0              xor         eax,eax
  004011ED: C9                 leave
  004011EE: C3                 ret
  004011EF: 90                 nop
  004011F0: 55                 push        ebp
  004011F1: 89 E5              mov         ebp,esp
  004011F3: 83 EC 08           sub         esp,8
  004011F6: 83 C4 F4           add         esp,0FFFFFFF4h
  004011F9: 6A 02              push        2
  004011FB: A1 60 81 40 00     mov         eax,dword ptr ds:[00408160h]
  00401200: FF D0              call        eax
  00401202: E8 79 FF FF FF     call        00401180
  00401207: C9                 leave
  00401208: C3                 ret
  00401209: 8D 76 00           lea         esi,[esi]
  0040120C: 59                 pop         ecx
  0040120D: 12 40 00           adc         al,byte ptr [eax]
  00401210: 00 00              add         byte ptr [eax],al
  00401212: 00 00              add         byte ptr [eax],al
  00401214: 00 00              add         byte ptr [eax],al
  00401216: 00 00              add         byte ptr [eax],al
  00401218: 73 00              jae         0040121A
  0040121A: 00 00              add         byte ptr [eax],al
  0040121C: 54                 push        esp
  0040121D: 12 40 00           adc         al,byte ptr [eax]
  00401220: 00 00              add         byte ptr [eax],al
  00401222: 00 00              add         byte ptr [eax],al
  00401224: 00 00              add         byte ptr [eax],al
  00401226: 00 00              add         byte ptr [eax],al
  00401228: 7E FF              jle         00401229
  0040122A: FF
  0040122B: FF 4C 12 40        dec         dword ptr [edx+edx+40h]
  0040122F: 00 00              add         byte ptr [eax],al
  00401231: 00 00              add         byte ptr [eax],al
  00401233: 00 00              add         byte ptr [eax],al
  00401235: 00 00              add         byte ptr [eax],al
  00401237: 00 7D FF           add         byte ptr [ebp-1],bh
  0040123A: FF
  0040123B: FF 00              inc         dword ptr [eax]
  0040123D: 00 00              add         byte ptr [eax],al
  0040123F: 00 00              add         byte ptr [eax],al
  00401241: 00 00              add         byte ptr [eax],al
  00401243: 00 00              add         byte ptr [eax],al
  00401245: 00 00              add         byte ptr [eax],al
  00401247: 00 00              add         byte ptr [eax],al
  00401249: 00 00              add         byte ptr [eax],al
  0040124B: 00 76 65           add         byte ptr [esi+65h],dh
  0040124E: 72 73              jb          004012C3
  00401250: 69 6F 6E 00 68 65  imul        ebp,dword ptr [edi+6Eh],6C656800h
            6C
  00401257: 70 00              jo          00401259
  00401259: 73 79              jae         004012D4
  0040125B: 73 76              jae         004012D3
  0040125D: 00 8D B4 26 00 00  add         byte ptr [ebp+000026B4h],cl
  00401263: 00 00              add         byte ptr [eax],al
  00401265: 8D BC 27 00 00 00  lea         edi,[edi+00000000h]
            00
  0040126C: 54                 push        esp
  0040126D: 72 79              jb          004012E8
  0040126F: 20 60 25           and         byte ptr [eax+25h],ah
  00401272: 73 20              jae         00401294
  00401274: 2D 2D 68 65 6C     sub         eax,6C65682Dh
  00401279: 70 27              jo          004012A2
  0040127B: 20 66 6F           and         byte ptr [esi+6Fh],ah
  0040127E: 72 20              jb          004012A0
  00401280: 6D                 ins         dword ptr es:[edi],dx
  00401281: 6F                 outs        dx,dword ptr [esi]
  00401282: 72 65              jb          004012E9
  00401284: 20 69 6E           and         byte ptr [ecx+6Eh],ch
  00401287: 66 6F              outs        dx,word ptr [esi]
  00401289: 72 6D              jb          004012F8
  0040128B: 61                 popad
  0040128C: 74 69              je          004012F7
  0040128E: 6F                 outs        dx,dword ptr [esi]
  0040128F: 6E                 outs        dx,byte ptr [esi]
  00401290: 2E 0A 00           or          al,byte ptr cs:[eax]
  00401293: 90                 nop
  00401294: 90                 nop
  00401295: 90                 nop
  00401296: 90                 nop
  00401297: 90                 nop
  00401298: 90                 nop
  00401299: 90                 nop
  0040129A: 90                 nop
  0040129B: 90                 nop
  0040129C: 90                 nop
  0040129D: 90                 nop
  0040129E: 90                 nop
  0040129F: 90                 nop
  004012A0: 90                 nop
  004012A1: 90                 nop
  004012A2: 90                 nop
  004012A3: 90                 nop
  004012A4: 90                 nop
  004012A5: 90                 nop
  004012A6: 90                 nop
  004012A7: 90                 nop
  004012A8: 90                 nop
  004012A9: 90                 nop
  004012AA: 90                 nop
  004012AB: 90                 nop
  004012AC: 55                 push        ebp
  004012AD: 73 61              jae         00401310
  004012AF: 67 65 3A 20        cmp         ah,byte ptr gs:[bx+si]
  004012B3: 25 73 20 5B 4F     and         eax,4F5B2073h
  004012B8: 50                 push        eax
  004012B9: 54                 push        esp
  004012BA: 49                 dec         ecx
  004012BB: 4F                 dec         edi
  004012BC: 4E                 dec         esi
  004012BD: 5D                 pop         ebp
  004012BE: 2E
  004012BF: 2E
  004012C0: 2E 20 5B 46        and         byte ptr cs:[ebx+46h],bl
  004012C4: 49                 dec         ecx
  004012C5: 4C                 dec         esp
  004012C6: 45                 inc         ebp
  004012C7: 5D                 pop         ebp
  004012C8: 2E
  004012C9: 2E
  004012CA: 2E 0A 00           or          al,byte ptr cs:[eax]
  004012CD: 90                 nop
  004012CE: 90                 nop
  004012CF: 90                 nop
  004012D0: 90                 nop
  004012D1: 90                 nop
  004012D2: 90                 nop
  004012D3: 90                 nop
  004012D4: 90                 nop
  004012D5: 90                 nop
  004012D6: 90                 nop
  004012D7: 90                 nop
  004012D8: 90                 nop
  004012D9: 90                 nop
  004012DA: 90                 nop
  004012DB: 90                 nop
  004012DC: 90                 nop
  004012DD: 90                 nop
  004012DE: 90                 nop
  004012DF: 90                 nop
  004012E0: 90                 nop
  004012E1: 90                 nop
  004012E2: 90                 nop
  004012E3: 90                 nop
  004012E4: 90                 nop
  004012E5: 90                 nop
  004012E6: 90                 nop
  004012E7: 90                 nop
  004012E8: 90                 nop
  004012E9: 90                 nop
  004012EA: 90                 nop
  004012EB: 90                 nop
  004012EC: 50                 push        eax
  004012ED: 72 69              jb          00401358
  004012EF: 6E                 outs        dx,byte ptr [esi]
  004012F0: 74 20              je          00401312
  004012F2: 63 68 65           arpl        word ptr [eax+65h],bp
  004012F5: 63 6B 73           arpl        word ptr [ebx+73h],bp
  004012F8: 75 6D              jne         00401367
  004012FA: 20 61 6E           and         byte ptr [ecx+6Eh],ah
  004012FD: 64 20 62 6C        and         byte ptr fs:[edx+6Ch],ah
  00401301: 6F                 outs        dx,dword ptr [esi]
  00401302: 63 6B 20           arpl        word ptr [ebx+20h],bp
  00401305: 63 6F 75           arpl        word ptr [edi+75h],bp
  00401308: 6E                 outs        dx,byte ptr [esi]
  00401309: 74 73              je          0040137E
  0040130B: 20 66 6F           and         byte ptr [esi+6Fh],ah
  0040130E: 72 20              jb          00401330
  00401310: 65 61              popad
  00401312: 63 68 20           arpl        word ptr [eax+20h],bp
  00401315: 46                 inc         esi
  00401316: 49                 dec         ecx
  00401317: 4C                 dec         esp
  00401318: 45                 inc         ebp
  00401319: 2E 0A 0A           or          cl,byte ptr cs:[edx]
  0040131C: 20 20              and         byte ptr [eax],ah
  0040131E: 2D 72 20 20 20     sub         eax,20202072h
  00401323: 20 20              and         byte ptr [eax],ah
  00401325: 20 20              and         byte ptr [eax],ah
  00401327: 20 20              and         byte ptr [eax],ah
  00401329: 20 20              and         byte ptr [eax],ah
  0040132B: 20 20              and         byte ptr [eax],ah
  0040132D: 20 64 65 66        and         byte ptr [ebp+66h],ah
  00401331: 65 61              popad
  00401333: 74 20              je          00401355
  00401335: 2D 73 2C 20 75     sub         eax,75202C73h
  0040133A: 73 65              jae         004013A1
  0040133C: 20 42 53           and         byte ptr [edx+53h],al
  0040133F: 44                 inc         esp
  00401340: 20 73 75           and         byte ptr [ebx+75h],dh
  00401343: 6D                 ins         dword ptr es:[edi],dx
  00401344: 20 61 6C           and         byte ptr [ecx+6Ch],ah
  00401347: 67 6F              outs        dx,dword ptr [si]
  00401349: 72 69              jb          004013B4
  0040134B: 74 68              je          004013B5
  0040134D: 6D                 ins         dword ptr es:[edi],dx
  0040134E: 2C 20              sub         al,20h
  00401350: 75 73              jne         004013C5
  00401352: 65 20 31           and         byte ptr gs:[ecx],dh
  00401355: 4B                 dec         ebx
  00401356: 20 62 6C           and         byte ptr [edx+6Ch],ah
  00401359: 6F                 outs        dx,dword ptr [esi]
  0040135A: 63 6B 73           arpl        word ptr [ebx+73h],bp
  0040135D: 0A 20              or          ah,byte ptr [eax]
  0040135F: 20 2D 73 2C 20 2D  and         byte ptr ds:[2D202C73h],ch
  00401365: 2D 73 79 73 76     sub         eax,76737973h
  0040136A: 20 20              and         byte ptr [eax],ah
  0040136C: 20 20              and         byte ptr [eax],ah
  0040136E: 20 20              and         byte ptr [eax],ah
  00401370: 75 73              jne         004013E5
  00401372: 65 20 53 79        and         byte ptr gs:[ebx+79h],dl
  00401376: 73 74              jae         004013EC
  00401378: 65 6D              ins         dword ptr es:[edi],dx
  0040137A: 20 56 20           and         byte ptr [esi+20h],dl
  0040137D: 73 75              jae         004013F4
  0040137F: 6D                 ins         dword ptr es:[edi],dx
  00401380: 20 61 6C           and         byte ptr [ecx+6Ch],ah
  00401383: 67 6F              outs        dx,dword ptr [si]
  00401385: 72 69              jb          004013F0
  00401387: 74 68              je          004013F1
  00401389: 6D                 ins         dword ptr es:[edi],dx
  0040138A: 2C 20              sub         al,20h
  0040138C: 75 73              jne         00401401
  0040138E: 65 20 35 31 32 20  and         byte ptr gs:[62203231h],dh
            62
  00401395: 79 74              jns         0040140B
  00401397: 65 73 20           jae         004013BA
  0040139A: 62 6C 6F 63        bound       ebp,qword ptr [edi+ebp*2+63h]
  0040139E: 6B 73 0A 00        imul        esi,dword ptr [ebx+0Ah],0
  004013A2: 8D 76 00           lea         esi,[esi]
  004013A5: 8D BC 27 00 00 00  lea         edi,[edi+00000000h]
            00
  004013AC: 20 20              and         byte ptr [eax],ah
  004013AE: 20 20              and         byte ptr [eax],ah
  004013B0: 20 20              and         byte ptr [eax],ah
  004013B2: 2D 2D 68 65 6C     sub         eax,6C65682Dh
  004013B7: 70 20              jo          004013D9
  004013B9: 20 20              and         byte ptr [eax],ah
  004013BB: 20 20              and         byte ptr [eax],ah
  004013BD: 64 69 73 70 6C 61  imul        esi,dword ptr fs:[ebx+70h],2079616Ch
            79 20
  004013C5: 74 68              je          0040142F
  004013C7: 69 73 20 68 65 6C  imul        esi,dword ptr [ebx+20h],706C6568h
            70
  004013CE: 20 61 6E           and         byte ptr [ecx+6Eh],ah
  004013D1: 64 20 65 78        and         byte ptr fs:[ebp+78h],ah
  004013D5: 69 74 0A 00 90 90  imul        esi,dword ptr [edx+ecx],90909090h
            90 90
  004013DD: 90                 nop
  004013DE: 90                 nop
  004013DF: 90                 nop
  004013E0: 90                 nop
  004013E1: 90                 nop
  004013E2: 90                 nop
  004013E3: 90                 nop
  004013E4: 90                 nop
  004013E5: 90                 nop
  004013E6: 90                 nop
  004013E7: 90                 nop
  004013E8: 90                 nop
  004013E9: 90                 nop
  004013EA: 90                 nop
  004013EB: 90                 nop
  004013EC: 20 20              and         byte ptr [eax],ah
  004013EE: 20 20              and         byte ptr [eax],ah
  004013F0: 20 20              and         byte ptr [eax],ah
  004013F2: 2D 2D 76 65 72     sub         eax,7265762Dh
  004013F7: 73 69              jae         00401462
  004013F9: 6F                 outs        dx,dword ptr [esi]
  004013FA: 6E                 outs        dx,byte ptr [esi]
  004013FB: 20 20              and         byte ptr [eax],ah
  004013FD: 6F                 outs        dx,dword ptr [esi]
  004013FE: 75 74              jne         00401474
  00401400: 70 75              jo          00401477
  00401402: 74 20              je          00401424
  00401404: 76 65              jbe         0040146B
  00401406: 72 73              jb          0040147B
  00401408: 69 6F 6E 20 69 6E  imul        ebp,dword ptr [edi+6Eh],666E6920h
            66
  0040140F: 6F                 outs        dx,dword ptr [esi]
  00401410: 72 6D              jb          0040147F
  00401412: 61                 popad
  00401413: 74 69              je          0040147E
  00401415: 6F                 outs        dx,dword ptr [esi]
  00401416: 6E                 outs        dx,byte ptr [esi]
  00401417: 20 61 6E           and         byte ptr [ecx+6Eh],ah
  0040141A: 64 20 65 78        and         byte ptr fs:[ebp+78h],ah
  0040141E: 69 74 0A 00 8D 76  imul        esi,dword ptr [edx+ecx],8D00768Dh
            00 8D
  00401426: BC 27 00 00 00     mov         esp,27h
  0040142B: 00 0A              add         byte ptr [edx],cl
  0040142D: 57                 push        edi
  0040142E: 69 74 68 20 6E 6F  imul        esi,dword ptr [eax+ebp*2+20h],46206F6Eh
            20 46
  00401436: 49                 dec         ecx
  00401437: 4C                 dec         esp
  00401438: 45                 inc         ebp
  00401439: 2C 20              sub         al,20h
  0040143B: 6F                 outs        dx,dword ptr [esi]
  0040143C: 72 20              jb          0040145E
  0040143E: 77 68              ja          004014A8
  00401440: 65 6E              outs        dx,byte ptr gs:[esi]
  00401442: 20 46 49           and         byte ptr [esi+49h],al
  00401445: 4C                 dec         esp
  00401446: 45                 inc         ebp
  00401447: 20 69 73           and         byte ptr [ecx+73h],ch
  0040144A: 20 2D 2C 20 72 65  and         byte ptr ds:[6572202Ch],ch
  00401450: 61                 popad
  00401451: 64 20 73 74        and         byte ptr fs:[ebx+74h],dh
  00401455: 61                 popad
  00401456: 6E                 outs        dx,byte ptr [esi]
  00401457: 64 61              popad
  00401459: 72 64              jb          004014BF
  0040145B: 20 69 6E           and         byte ptr [ecx+6Eh],ch
  0040145E: 70 75              jo          004014D5
  00401460: 74 2E              je          00401490
  00401462: 0A 00              or          al,byte ptr [eax]
  00401464: 62 75 67           bound       esi,qword ptr [ebp+67h]
  00401467: 2D 74 65 78 74     sub         eax,74786574h
  0040146C: 75 74              jne         004014E2
  0040146E: 69 6C 73 40 67 6E  imul        ebp,dword ptr [ebx+esi*2+40h],2E756E67h
            75 2E
  00401476: 6F                 outs        dx,dword ptr [esi]
  00401477: 72 67              jb          004014E0
  00401479: 00 0A              add         byte ptr [edx],cl
  0040147B: 52                 push        edx
  0040147C: 65 70 6F           jo          004014EE
  0040147F: 72 74              jb          004014F5
  00401481: 20 62 75           and         byte ptr [edx+75h],ah
  00401484: 67 73 20           jae         004014A7
  00401487: 74 6F              je          004014F8
  00401489: 20 3C 25 73 3E 2E  and         byte ptr ds:[0A2E3E73h],bh
            0A
  00401490: 00 8D 76 00 55 89  add         byte ptr [ebp+89550076h],cl
  00401496: E5 83              in          eax,83h
  00401498: EC                 in          al,dx
  00401499: 14 53              adc         al,53h
  0040149B: 8B 5D 08           mov         ebx,dword ptr [ebp+8]
  0040149E: 85 DB              test        ebx,ebx
  004014A0: 74 26              je          004014C8
  004014A2: 83 C4 FC           add         esp,0FFFFFFFCh
  004014A5: FF 35 C0 71 40 00  push        dword ptr ds:[004071C0h]
  004014AB: 68 6C 12 40 00     push        40126Ch
  004014B0: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004014B5: 83 C0 40           add         eax,40h
  004014B8: 50                 push        eax
  004014B9: E8 3A 3D 00 00     call        004051F8
  004014BE: 83 C4 10           add         esp,10h
  004014C1: E9 88 00 00 00     jmp         0040154E
  004014C6: 89 F6              mov         esi,esi
  004014C8: 83 C4 F8           add         esp,0FFFFFFF8h
  004014CB: FF 35 C0 71 40 00  push        dword ptr ds:[004071C0h]
  004014D1: 68 AC 12 40 00     push        4012ACh
  004014D6: E8 15 3D 00 00     call        004051F0
  004014DB: 83 C4 F8           add         esp,0FFFFFFF8h
  004014DE: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004014E3: 83 C0 20           add         eax,20h
  004014E6: 50                 push        eax
  004014E7: 68 EC 12 40 00     push        4012ECh
  004014EC: E8 F7 3C 00 00     call        004051E8
  004014F1: 83 C4 20           add         esp,20h
  004014F4: 83 C4 F8           add         esp,0FFFFFFF8h
  004014F7: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004014FC: 83 C0 20           add         eax,20h
  004014FF: 50                 push        eax
  00401500: 68 AC 13 40 00     push        4013ACh
  00401505: E8 DE 3C 00 00     call        004051E8
  0040150A: 83 C4 F8           add         esp,0FFFFFFF8h
  0040150D: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00401512: 83 C0 20           add         eax,20h
  00401515: 50                 push        eax
  00401516: 68 EC 13 40 00     push        4013ECh
  0040151B: E8 C8 3C 00 00     call        004051E8
  00401520: 83 C4 20           add         esp,20h
  00401523: 83 C4 F8           add         esp,0FFFFFFF8h
  00401526: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  0040152B: 83 C0 20           add         eax,20h
  0040152E: 50                 push        eax
  0040152F: 68 2C 14 40 00     push        40142Ch
  00401534: E8 AF 3C 00 00     call        004051E8
  00401539: 83 C4 F8           add         esp,0FFFFFFF8h
  0040153C: 68 64 14 40 00     push        401464h
  00401541: 68 7A 14 40 00     push        40147Ah
  00401546: E8 A5 3C 00 00     call        004051F0
  0040154B: 83 C4 20           add         esp,20h
  0040154E: 83 C4 F4           add         esp,0FFFFFFF4h
  00401551: 31 C0              xor         eax,eax
  00401553: 85 DB              test        ebx,ebx
  00401555: 74 05              je          0040155C
  00401557: B8 FF FF FF FF     mov         eax,0FFFFFFFFh
  0040155C: 50                 push        eax
  0040155D: E8 7E 3C 00 00     call        004051E0
  00401562: 2D 00 72 62 00     sub         eax,627200h
  00401567: 25 73 00 25 30     and         eax,30250073h
  0040156C: 35 64 20 25 35     xor         eax,35252064h
  00401571: 73 00              jae         00401573
  00401573: 20 25 73 00 90 55  and         byte ptr ds:[55900073h],ah
  00401579: 89 E5              mov         ebp,esp
  0040157B: 83 EC 5C           sub         esp,5Ch
  0040157E: 57                 push        edi
  0040157F: 56                 push        esi
  00401580: 53                 push        ebx
  00401581: C7 45 CC 00 00 00  mov         dword ptr [ebp-34h],0
            00
  00401588: C7 45 C0 00 00 00  mov         dword ptr [ebp-40h],0
            00
  0040158F: C7 45 C4 00 00 00  mov         dword ptr [ebp-3Ch],0
            00
  00401596: BA 62 15 40 00     mov         edx,401562h
  0040159B: 8B 75 08           mov         esi,dword ptr [ebp+8]
  0040159E: 89 D7              mov         edi,edx
  004015A0: B9 02 00 00 00     mov         ecx,2
  004015A5: FC                 cld
  004015A6: 31 C0              xor         eax,eax
  004015A8: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  004015AA: 74 04              je          004015B0
  004015AC: 19 C0              sbb         eax,eax
  004015AE: 0C 01              or          al,1
  004015B0: 89 D7              mov         edi,edx
  004015B2: 85 C0              test        eax,eax
  004015B4: 74 26              je          004015DC
  004015B6: 83 C4 F8           add         esp,0FFFFFFF8h
  004015B9: 68 64 15 40 00     push        401564h
  004015BE: 8B 45 08           mov         eax,dword ptr [ebp+8]
  004015C1: 50                 push        eax
  004015C2: E8 11 3C 00 00     call        004051D8
  004015C7: 89 C3              mov         ebx,eax
  004015C9: 83 C4 10           add         esp,10h
  004015CC: 85 DB              test        ebx,ebx
  004015CE: 75 1C              jne         004015EC
  004015D0: 8B 55 08           mov         edx,dword ptr [ebp+8]
  004015D3: 52                 push        edx
  004015D4: E9 F5 00 00 00     jmp         004016CE
  004015D9: 8D 76 00           lea         esi,[esi]
  004015DC: 8B 1D 7C 81 40 00  mov         ebx,dword ptr ds:[0040817Ch]
  004015E2: C7 05 00 70 40 00  mov         dword ptr ds:[00407000h],1
            01 00 00 00
  004015EC: 83 C4 F4           add         esp,0FFFFFFF4h
  004015EF: 83 C4 F4           add         esp,0FFFFFFF4h
  004015F2: 53                 push        ebx
  004015F3: E8 90 3B 00 00     call        00405188
  004015F8: 50                 push        eax
  004015F9: E8 06 3B 00 00     call        00405104
  004015FE: 83 C4 20           add         esp,20h
  00401601: 85 C0              test        eax,eax
  00401603: 75 42              jne         00401647
  00401605: 83 C4 F8           add         esp,0FFFFFFF8h
  00401608: 68 00 80 00 00     push        8000h
  0040160D: 83 C4 F4           add         esp,0FFFFFFF4h
  00401610: 53                 push        ebx
  00401611: E8 72 3B 00 00     call        00405188
  00401616: 83 C4 10           add         esp,10h
  00401619: 50                 push        eax
  0040161A: E8 71 3B 00 00     call        00405190
  0040161F: 83 C4 10           add         esp,10h
  00401622: EB 23              jmp         00401647
  00401624: 83 45 C0 01        add         dword ptr [ebp-40h],1
  00401628: 83 55 C4 00        adc         dword ptr [ebp-3Ch],0
  0040162C: 8B 55 CC           mov         edx,dword ptr [ebp-34h]
  0040162F: D1 FA              sar         edx,1
  00401631: 8B 45 CC           mov         eax,dword ptr [ebp-34h]
  00401634: 83 E0 01           and         eax,1
  00401637: C1 E0 0F           shl         eax,0Fh
  0040163A: 01 C2              add         edx,eax
  0040163C: 8B 45 BC           mov         eax,dword ptr [ebp-44h]
  0040163F: 01 C2              add         edx,eax
  00401641: 0F B7 D2           movzx       edx,dx
  00401644: 89 55 CC           mov         dword ptr [ebp-34h],edx
  00401647: 83 C4 F4           add         esp,0FFFFFFF4h
  0040164A: 53                 push        ebx
  0040164B: E8 78 3B 00 00     call        004051C8
  00401650: 89 45 BC           mov         dword ptr [ebp-44h],eax
  00401653: 83 C4 10           add         esp,10h
  00401656: 83 F8 FF           cmp         eax,0FFFFFFFFh
  00401659: 75 C9              jne         00401624
  0040165B: 83 C4 F4           add         esp,0FFFFFFF4h
  0040165E: 53                 push        ebx
  0040165F: E8 5C 3B 00 00     call        004051C0
  00401664: 83 C4 10           add         esp,10h
  00401667: 85 C0              test        eax,eax
  00401669: 74 3D              je          004016A8
  0040166B: 8B 55 08           mov         edx,dword ptr [ebp+8]
  0040166E: 52                 push        edx
  0040166F: 68 67 15 40 00     push        401567h
  00401674: E8 57 3B 00 00     call        004051D0
  00401679: FF 30              push        dword ptr [eax]
  0040167B: 6A 00              push        0
  0040167D: E8 66 1F 00 00     call        004035E8
  00401682: 8B 75 08           mov         esi,dword ptr [ebp+8]
  00401685: B9 02 00 00 00     mov         ecx,2
  0040168A: FC                 cld
  0040168B: 31 C0              xor         eax,eax
  0040168D: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  0040168F: 74 04              je          00401695
  00401691: 19 C0              sbb         eax,eax
  00401693: 0C 01              or          al,1
  00401695: 83 C4 10           add         esp,10h
  00401698: 85 C0              test        eax,eax
  0040169A: 74 45              je          004016E1
  0040169C: 83 C4 F4           add         esp,0FFFFFFF4h
  0040169F: 53                 push        ebx
  004016A0: E8 13 3B 00 00     call        004051B8
  004016A5: EB 3A              jmp         004016E1
  004016A7: 90                 nop
  004016A8: 8B 75 08           mov         esi,dword ptr [ebp+8]
  004016AB: B9 02 00 00 00     mov         ecx,2
  004016B0: FC                 cld
  004016B1: A8 00              test        al,0
  004016B3: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  004016B5: 74 31              je          004016E8
  004016B7: 83 C4 F4           add         esp,0FFFFFFF4h
  004016BA: 53                 push        ebx
  004016BB: E8 F8 3A 00 00     call        004051B8
  004016C0: 89 C3              mov         ebx,eax
  004016C2: 83 C4 10           add         esp,10h
  004016C5: 83 FB FF           cmp         ebx,0FFFFFFFFh
  004016C8: 75 1E              jne         004016E8
  004016CA: 8B 45 08           mov         eax,dword ptr [ebp+8]
  004016CD: 50                 push        eax
  004016CE: 68 67 15 40 00     push        401567h
  004016D3: E8 F8 3A 00 00     call        004051D0
  004016D8: FF 30              push        dword ptr [eax]
  004016DA: 6A 00              push        0
  004016DC: E8 07 1F 00 00     call        004035E8
  004016E1: B8 FF FF FF FF     mov         eax,0FFFFFFFFh
  004016E6: EB 58              jmp         00401740
  004016E8: 83 C4 FC           add         esp,0FFFFFFFCh
  004016EB: 83 C4 F8           add         esp,0FFFFFFF8h
  004016EE: 6A 01              push        1
  004016F0: 68 00 04 00 00     push        400h
  004016F5: 6A 01              push        1
  004016F7: 8D 45 D0           lea         eax,[ebp-30h]
  004016FA: 50                 push        eax
  004016FB: 8B 45 C0           mov         eax,dword ptr [ebp-40h]
  004016FE: 8B 55 C4           mov         edx,dword ptr [ebp-3Ch]
  00401701: 52                 push        edx
  00401702: 50                 push        eax
  00401703: E8 A4 16 00 00     call        00402DAC
  00401708: 50                 push        eax
  00401709: 8B 55 CC           mov         edx,dword ptr [ebp-34h]
  0040170C: 52                 push        edx
  0040170D: 68 6A 15 40 00     push        40156Ah
  00401712: E8 D9 3A 00 00     call        004051F0
  00401717: 83 C4 30           add         esp,30h
  0040171A: 83 7D 0C 01        cmp         dword ptr [ebp+0Ch],1
  0040171E: 7E 14              jle         00401734
  00401720: 83 C4 F8           add         esp,0FFFFFFF8h
  00401723: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00401726: 50                 push        eax
  00401727: 68 73 15 40 00     push        401573h
  0040172C: E8 BF 3A 00 00     call        004051F0
  00401731: 83 C4 10           add         esp,10h
  00401734: 83 C4 F4           add         esp,0FFFFFFF4h
  00401737: 6A 0A              push        0Ah
  00401739: E8 72 3A 00 00     call        004051B0
  0040173E: 31 C0              xor         eax,eax
  00401740: 8D 65 98           lea         esp,[ebp-68h]
  00401743: 5B                 pop         ebx
  00401744: 5E                 pop         esi
  00401745: 5F                 pop         edi
  00401746: C9                 leave
  00401747: C3                 ret
  00401748: 25 64 20 25 73     and         eax,73252064h
  0040174D: 00 89 F6 55 89 E5  add         byte ptr [ecx+E58955F6h],cl
  00401753: B8 5C 20 00 00     mov         eax,205Ch
  00401758: E8 A7 33 00 00     call        00404B04
  0040175D: 57                 push        edi
  0040175E: 56                 push        esi
  0040175F: 53                 push        ebx
  00401760: C7 85 C0 DF FF FF  mov         dword ptr [ebp+FFFFDFC0h],0
            00 00 00 00
  0040176A: C7 85 C4 DF FF FF  mov         dword ptr [ebp+FFFFDFC4h],0
            00 00 00 00
  00401774: C7 85 BC DF FF FF  mov         dword ptr [ebp+FFFFDFBCh],0
            00 00 00 00
  0040177E: BA 62 15 40 00     mov         edx,401562h
  00401783: 8B 75 08           mov         esi,dword ptr [ebp+8]
  00401786: 89 D7              mov         edi,edx
  00401788: B9 02 00 00 00     mov         ecx,2
  0040178D: FC                 cld
  0040178E: 31 C0              xor         eax,eax
  00401790: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  00401792: 74 04              je          00401798
  00401794: 19 C0              sbb         eax,eax
  00401796: 0C 01              or          al,1
  00401798: 89 D7              mov         edi,edx
  0040179A: 85 C0              test        eax,eax
  0040179C: 74 2A              je          004017C8
  0040179E: 83 C4 F8           add         esp,0FFFFFFF8h
  004017A1: 68 00 80 00 00     push        8000h
  004017A6: 8B 45 08           mov         eax,dword ptr [ebp+8]
  004017A9: 50                 push        eax
  004017AA: E8 4D 39 00 00     call        004050FC
  004017AF: 89 85 CC DF FF FF  mov         dword ptr [ebp+FFFFDFCCh],eax
  004017B5: 83 C4 10           add         esp,10h
  004017B8: 83 F8 FF           cmp         eax,0FFFFFFFFh
  004017BB: 75 1F              jne         004017DC
  004017BD: 8B 55 08           mov         edx,dword ptr [ebp+8]
  004017C0: 52                 push        edx
  004017C1: E9 02 01 00 00     jmp         004018C8
  004017C6: 89 F6              mov         esi,esi
  004017C8: C7 85 CC DF FF FF  mov         dword ptr [ebp+FFFFDFCCh],0
            00 00 00 00
  004017D2: C7 05 00 70 40 00  mov         dword ptr ds:[00407000h],1
            01 00 00 00
  004017DC: 83 C4 F4           add         esp,0FFFFFFF4h
  004017DF: 8B 85 CC DF FF FF  mov         eax,dword ptr [ebp+FFFFDFCCh]
  004017E5: 50                 push        eax
  004017E6: E8 19 39 00 00     call        00405104
  004017EB: 83 C4 10           add         esp,10h
  004017EE: 85 C0              test        eax,eax
  004017F0: 75 1A              jne         0040180C
  004017F2: 83 C4 F8           add         esp,0FFFFFFF8h
  004017F5: 68 00 80 00 00     push        8000h
  004017FA: 8B 95 CC DF FF FF  mov         edx,dword ptr [ebp+FFFFDFCCh]
  00401800: 52                 push        edx
  00401801: E8 8A 39 00 00     call        00405190
  00401806: 83 C4 10           add         esp,10h
  00401809: 8D 76 00           lea         esi,[esi]
  0040180C: 8D B5 00 E0 FF FF  lea         esi,[ebp+FFFFE000h]
  00401812: EB 26              jmp         0040183A
  00401814: 31 D2              xor         edx,edx
  00401816: 39 CA              cmp         edx,ecx
  00401818: 7D 11              jge         0040182B
  0040181A: 89 F3              mov         ebx,esi
  0040181C: 0F B6 04 1A        movzx       eax,byte ptr [edx+ebx]
  00401820: 01 85 BC DF FF FF  add         dword ptr [ebp+FFFFDFBCh],eax
  00401826: 42                 inc         edx
  00401827: 39 CA              cmp         edx,ecx
  00401829: 7C F1              jl          0040181C
  0040182B: 89 C8              mov         eax,ecx
  0040182D: 99                 cdq
  0040182E: 01 85 C0 DF FF FF  add         dword ptr [ebp+FFFFDFC0h],eax
  00401834: 11 95 C4 DF FF FF  adc         dword ptr [ebp+FFFFDFC4h],edx
  0040183A: 83 C4 FC           add         esp,0FFFFFFFCh
  0040183D: 68 00 20 00 00     push        2000h
  00401842: 56                 push        esi
  00401843: 8B 85 CC DF FF FF  mov         eax,dword ptr [ebp+FFFFDFCCh]
  00401849: 50                 push        eax
  0040184A: E8 81 13 00 00     call        00402BD0
  0040184F: 89 C1              mov         ecx,eax
  00401851: 83 C4 10           add         esp,10h
  00401854: 85 C9              test        ecx,ecx
  00401856: 7F BC              jg          00401814
  00401858: 7D 42              jge         0040189C
  0040185A: 8B 55 08           mov         edx,dword ptr [ebp+8]
  0040185D: 52                 push        edx
  0040185E: 68 67 15 40 00     push        401567h
  00401863: E8 68 39 00 00     call        004051D0
  00401868: FF 30              push        dword ptr [eax]
  0040186A: 6A 00              push        0
  0040186C: E8 77 1D 00 00     call        004035E8
  00401871: 8B 75 08           mov         esi,dword ptr [ebp+8]
  00401874: B9 02 00 00 00     mov         ecx,2
  00401879: FC                 cld
  0040187A: 31 C0              xor         eax,eax
  0040187C: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  0040187E: 74 04              je          00401884
  00401880: 19 C0              sbb         eax,eax
  00401882: 0C 01              or          al,1
  00401884: 83 C4 10           add         esp,10h
  00401887: 85 C0              test        eax,eax
  00401889: 74 50              je          004018DB
  0040188B: 83 C4 F4           add         esp,0FFFFFFF4h
  0040188E: 8B 85 CC DF FF FF  mov         eax,dword ptr [ebp+FFFFDFCCh]
  00401894: 50                 push        eax
  00401895: E8 5A 38 00 00     call        004050F4
  0040189A: EB 3F              jmp         004018DB
  0040189C: 8B 75 08           mov         esi,dword ptr [ebp+8]
  0040189F: B9 02 00 00 00     mov         ecx,2
  004018A4: FC                 cld
  004018A5: A8 00              test        al,0
  004018A7: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  004018A9: 74 3D              je          004018E8
  004018AB: 83 C4 F4           add         esp,0FFFFFFF4h
  004018AE: 8B 95 CC DF FF FF  mov         edx,dword ptr [ebp+FFFFDFCCh]
  004018B4: 52                 push        edx
  004018B5: E8 3A 38 00 00     call        004050F4
  004018BA: 89 C3              mov         ebx,eax
  004018BC: 83 C4 10           add         esp,10h
  004018BF: 83 FB FF           cmp         ebx,0FFFFFFFFh
  004018C2: 75 24              jne         004018E8
  004018C4: 8B 45 08           mov         eax,dword ptr [ebp+8]
  004018C7: 50                 push        eax
  004018C8: 68 67 15 40 00     push        401567h
  004018CD: E8 FE 38 00 00     call        004051D0
  004018D2: FF 30              push        dword ptr [eax]
  004018D4: 6A 00              push        0
  004018D6: E8 0D 1D 00 00     call        004035E8
  004018DB: B8 FF FF FF FF     mov         eax,0FFFFFFFFh
  004018E0: E9 83 00 00 00     jmp         00401968
  004018E5: 8D 76 00           lea         esi,[esi]
  004018E8: 8B 9D BC DF FF FF  mov         ebx,dword ptr [ebp+FFFFDFBCh]
  004018EE: C1 EB 10           shr         ebx,10h
  004018F1: 66 C7 85 BE DF FF  mov         word ptr [ebp+FFFFDFBEh],0
            FF 00 00
  004018FA: 03 9D BC DF FF FF  add         ebx,dword ptr [ebp+FFFFDFBCh]
  00401900: 89 D8              mov         eax,ebx
  00401902: C1 F8 10           sar         eax,10h
  00401905: 0F B7 DB           movzx       ebx,bx
  00401908: 01 C3              add         ebx,eax
  0040190A: 83 C4 FC           add         esp,0FFFFFFFCh
  0040190D: 83 C4 F8           add         esp,0FFFFFFF8h
  00401910: 6A 01              push        1
  00401912: 68 00 02 00 00     push        200h
  00401917: 6A 01              push        1
  00401919: 8D 85 D0 DF FF FF  lea         eax,[ebp+FFFFDFD0h]
  0040191F: 50                 push        eax
  00401920: 8B 85 C0 DF FF FF  mov         eax,dword ptr [ebp+FFFFDFC0h]
  00401926: 8B 95 C4 DF FF FF  mov         edx,dword ptr [ebp+FFFFDFC4h]
  0040192C: 52                 push        edx
  0040192D: 50                 push        eax
  0040192E: E8 79 14 00 00     call        00402DAC
  00401933: 50                 push        eax
  00401934: 53                 push        ebx
  00401935: 68 48 17 40 00     push        401748h
  0040193A: E8 B1 38 00 00     call        004051F0
  0040193F: 83 C4 30           add         esp,30h
  00401942: 83 7D 0C 00        cmp         dword ptr [ebp+0Ch],0
  00401946: 74 14              je          0040195C
  00401948: 83 C4 F8           add         esp,0FFFFFFF8h
  0040194B: 8B 55 08           mov         edx,dword ptr [ebp+8]
  0040194E: 52                 push        edx
  0040194F: 68 73 15 40 00     push        401573h
  00401954: E8 97 38 00 00     call        004051F0
  00401959: 83 C4 10           add         esp,10h
  0040195C: 83 C4 F4           add         esp,0FFFFFFF4h
  0040195F: 6A 0A              push        0Ah
  00401961: E8 4A 38 00 00     call        004051B0
  00401966: 31 C0              xor         eax,eax
  00401968: 8D A5 98 DF FF FF  lea         esp,[ebp+FFFFDF98h]
  0040196E: 5B                 pop         ebx
  0040196F: 5E                 pop         esi
  00401970: 5F                 pop         edi
  00401971: C9                 leave
  00401972: C3                 ret
  00401973: 00 72 73           add         byte ptr [edx+73h],dh
  00401976: 00 90 90 90 90 90  add         byte ptr [eax+90909090h],dl
  0040197C: 90                 nop
  0040197D: 90                 nop
  0040197E: 90                 nop
  0040197F: 90                 nop
  00401980: 90                 nop
  00401981: 90                 nop
  00401982: 90                 nop
  00401983: 90                 nop
  00401984: 90                 nop
  00401985: 90                 nop
  00401986: 90                 nop
  00401987: 90                 nop
  00401988: 90                 nop
  00401989: 90                 nop
  0040198A: 90                 nop
  0040198B: 90                 nop
  0040198C: 4B                 dec         ebx
  0040198D: 61                 popad
  0040198E: 79 76              jns         00401A06
  00401990: 61                 popad
  00401991: 6E                 outs        dx,byte ptr [esi]
  00401992: 20 41 67           and         byte ptr [ecx+67h],al
  00401995: 68 61 69 65 70     push        70656961h
  0040199A: 6F                 outs        dx,dword ptr [esi]
  0040199B: 75 72              jne         00401A0F
  0040199D: 20 61 6E           and         byte ptr [ecx+6Eh],ah
  004019A0: 64 20 44 61 76     and         byte ptr fs:[ecx+76h],al
  004019A5: 69 64 20 4D 61 63  imul        esp,dword ptr [eax+4Dh],654B6361h
            4B 65
  004019AD: 6E                 outs        dx,byte ptr [esi]
  004019AE: 7A 69              jp          00401A19
  004019B0: 65 00 32           add         byte ptr gs:[edx],dh
  004019B3: 2E 31 00           xor         dword ptr cs:[eax],eax
  004019B6: 74 65              je          00401A1D
  004019B8: 78 74              js          00401A2E
  004019BA: 75 74              jne         00401A30
  004019BC: 69 6C 73 00 73 75  imul        ebp,dword ptr [ebx+esi*2],6D7573h
            6D 00
  004019C4: 55                 push        ebp
  004019C5: 89 E5              mov         ebp,esp
  004019C7: 83 EC 1C           sub         esp,1Ch
  004019CA: 57                 push        edi
  004019CB: 56                 push        esi
  004019CC: 53                 push        ebx
  004019CD: E8 12 31 00 00     call        00404AE4
  004019D2: C7 45 FC 00 00 00  mov         dword ptr [ebp-4],0
            00
  004019D9: BF 78 15 40 00     mov         edi,401578h
  004019DE: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  004019E1: 8B 02              mov         eax,dword ptr [edx]
  004019E3: A3 C0 71 40 00     mov         dword ptr ds:[004071C0h],eax
  004019E8: 83 C4 F8           add         esp,0FFFFFFF8h
  004019EB: 68 73 19 40 00     push        401973h
  004019F0: 6A 00              push        0
  004019F2: E8 B1 37 00 00     call        004051A8
  004019F7: 83 C4 F4           add         esp,0FFFFFFF4h
  004019FA: 68 B8 2B 40 00     push        402BB8h
  004019FF: E8 9C 37 00 00     call        004051A0
  00401A04: C7 05 00 70 40 00  mov         dword ptr ds:[00407000h],0
            00 00 00 00
  00401A0E: 83 C4 20           add         esp,20h
  00401A11: 89 FE              mov         esi,edi
  00401A13: BB 50 17 40 00     mov         ebx,401750h
  00401A18: EB 77              jmp         00401A91
  00401A1A: 89 F6              mov         esi,esi
  00401A1C: 85 C0              test        eax,eax
  00401A1E: 74 71              je          00401A91
  00401A20: 7F 12              jg          00401A34
  00401A22: 3D 7D FF FF FF     cmp         eax,0FFFFFF7Dh
  00401A27: 74 27              je          00401A50
  00401A29: 3D 7E FF FF FF     cmp         eax,0FFFFFF7Eh
  00401A2E: 74 18              je          00401A48
  00401A30: EB 52              jmp         00401A84
  00401A32: 89 F6              mov         esi,esi
  00401A34: 83 F8 72           cmp         eax,72h
  00401A37: 74 07              je          00401A40
  00401A39: 83 F8 73           cmp         eax,73h
  00401A3C: 74 06              je          00401A44
  00401A3E: EB 44              jmp         00401A84
  00401A40: 89 F7              mov         edi,esi
  00401A42: EB 4D              jmp         00401A91
  00401A44: 89 DF              mov         edi,ebx
  00401A46: EB 49              jmp         00401A91
  00401A48: 83 C4 F4           add         esp,0FFFFFFF4h
  00401A4B: 6A 00              push        0
  00401A4D: EB 3A              jmp         00401A89
  00401A4F: 90                 nop
  00401A50: 83 C4 F4           add         esp,0FFFFFFF4h
  00401A53: 68 8C 19 40 00     push        40198Ch
  00401A58: 68 B2 19 40 00     push        4019B2h
  00401A5D: 68 B6 19 40 00     push        4019B6h
  00401A62: 68 C0 19 40 00     push        4019C0h
  00401A67: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00401A6C: 83 C0 20           add         eax,20h
  00401A6F: 50                 push        eax
  00401A70: E8 8F 0F 00 00     call        00402A04
  00401A75: 83 C4 20           add         esp,20h
  00401A78: 83 C4 F4           add         esp,0FFFFFFF4h
  00401A7B: 6A 00              push        0
  00401A7D: E8 5E 37 00 00     call        004051E0
  00401A82: 89 F6              mov         esi,esi
  00401A84: 83 C4 F4           add         esp,0FFFFFFF4h
  00401A87: 6A 01              push        1
  00401A89: E8 06 FA FF FF     call        00401494
  00401A8E: 83 C4 10           add         esp,10h
  00401A91: 83 C4 F4           add         esp,0FFFFFFF4h
  00401A94: 6A 00              push        0
  00401A96: 68 0C 12 40 00     push        40120Ch
  00401A9B: 68 74 19 40 00     push        401974h
  00401AA0: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  00401AA3: 50                 push        eax
  00401AA4: 8B 55 08           mov         edx,dword ptr [ebp+8]
  00401AA7: 52                 push        edx
  00401AA8: E8 FF 0F 00 00     call        00402AAC
  00401AAD: 83 C4 20           add         esp,20h
  00401AB0: 83 F8 FF           cmp         eax,0FFFFFFFFh
  00401AB3: 0F 85 63 FF FF FF  jne         00401A1C
  00401AB9: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00401ABE: 8B 5D 08           mov         ebx,dword ptr [ebp+8]
  00401AC1: 29 C3              sub         ebx,eax
  00401AC3: 75 4E              jne         00401B13
  00401AC5: 83 C4 F8           add         esp,0FFFFFFF8h
  00401AC8: 6A 00              push        0
  00401ACA: 68 62 15 40 00     push        401562h
  00401ACF: FF D7              call        edi
  00401AD1: 83 C4 10           add         esp,10h
  00401AD4: 85 C0              test        eax,eax
  00401AD6: 7D 40              jge         00401B18
  00401AD8: C7 45 FC 01 00 00  mov         dword ptr [ebp-4],1
            00
  00401ADF: EB 37              jmp         00401B18
  00401AE1: 8D 76 00           lea         esi,[esi]
  00401AE4: 83 C4 F8           add         esp,0FFFFFFF8h
  00401AE7: 53                 push        ebx
  00401AE8: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00401AED: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00401AF0: FF 34 82           push        dword ptr [edx+eax*4]
  00401AF3: FF D7              call        edi
  00401AF5: 83 C4 10           add         esp,10h
  00401AF8: 85 C0              test        eax,eax
  00401AFA: 7D 07              jge         00401B03
  00401AFC: C7 45 FC 01 00 00  mov         dword ptr [ebp-4],1
            00
  00401B03: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00401B08: 8D 50 01           lea         edx,[eax+1]
  00401B0B: 89 15 08 60 40 00  mov         dword ptr ds:[00406008h],edx
  00401B11: 89 D0              mov         eax,edx
  00401B13: 3B 45 08           cmp         eax,dword ptr [ebp+8]
  00401B16: 7C CC              jl          00401AE4
  00401B18: 83 3D 00 70 40 00  cmp         dword ptr ds:[00407000h],0
            00
  00401B1F: 74 30              je          00401B51
  00401B21: 83 C4 F4           add         esp,0FFFFFFF4h
  00401B24: FF 35 7C 81 40 00  push        dword ptr ds:[0040817Ch]
  00401B2A: E8 89 36 00 00     call        004051B8
  00401B2F: 89 C3              mov         ebx,eax
  00401B31: 83 C4 10           add         esp,10h
  00401B34: 83 FB FF           cmp         ebx,0FFFFFFFFh
  00401B37: 75 18              jne         00401B51
  00401B39: 83 C4 FC           add         esp,0FFFFFFFCh
  00401B3C: 68 62 15 40 00     push        401562h
  00401B41: E8 8A 36 00 00     call        004051D0
  00401B46: FF 30              push        dword ptr [eax]
  00401B48: 53                 push        ebx
  00401B49: E8 9A 1A 00 00     call        004035E8
  00401B4E: 83 C4 10           add         esp,10h
  00401B51: 83 C4 F4           add         esp,0FFFFFFF4h
  00401B54: 31 C0              xor         eax,eax
  00401B56: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  00401B5A: 74 05              je          00401B61
  00401B5C: B8 FF FF FF FF     mov         eax,0FFFFFFFFh
  00401B61: 50                 push        eax
  00401B62: E8 79 36 00 00     call        004051E0
  00401B67: 90                 nop
  00401B68: 8D 74 26 00        lea         esi,[esi]
  00401B6C: 55                 push        ebp
  00401B6D: 89 E5              mov         ebp,esp
  00401B6F: 8B 55 08           mov         edx,dword ptr [ebp+8]
  00401B72: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00401B75: 80 3A 00           cmp         byte ptr [edx],0
  00401B78: 74 14              je          00401B8E
  00401B7A: 89 F6              mov         esi,esi
  00401B7C: 0F BE 02           movsx       eax,byte ptr [edx]
  00401B7F: 39 C8              cmp         eax,ecx
  00401B81: 75 05              jne         00401B88
  00401B83: 89 D0              mov         eax,edx
  00401B85: EB 09              jmp         00401B90
  00401B87: 90                 nop
  00401B88: 42                 inc         edx
  00401B89: 80 3A 00           cmp         byte ptr [edx],0
  00401B8C: 75 EE              jne         00401B7C
  00401B8E: 31 C0              xor         eax,eax
  00401B90: C9                 leave
  00401B91: C3                 ret
  00401B92: 89 F6              mov         esi,esi
  00401B94: 55                 push        ebp
  00401B95: 89 E5              mov         ebp,esp
  00401B97: 83 EC 1C           sub         esp,1Ch
  00401B9A: 57                 push        edi
  00401B9B: 56                 push        esi
  00401B9C: 53                 push        ebx
  00401B9D: 8B 3D 40 70 40 00  mov         edi,dword ptr ds:[00407040h]
  00401BA3: A1 50 70 40 00     mov         eax,dword ptr ds:[00407050h]
  00401BA8: 89 45 FC           mov         dword ptr [ebp-4],eax
  00401BAB: 8B 15 08 60 40 00  mov         edx,dword ptr ds:[00406008h]
  00401BB1: 89 55 F8           mov         dword ptr [ebp-8],edx
  00401BB4: 39 C2              cmp         edx,eax
  00401BB6: 0F 8E 80 00 00 00  jle         00401C3C
  00401BBC: 39 F8              cmp         eax,edi
  00401BBE: 7E 7C              jle         00401C3C
  00401BC0: 8B 55 F8           mov         edx,dword ptr [ebp-8]
  00401BC3: 2B 55 FC           sub         edx,dword ptr [ebp-4]
  00401BC6: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  00401BC9: 29 F8              sub         eax,edi
  00401BCB: 39 C2              cmp         edx,eax
  00401BCD: 7E 35              jle         00401C04
  00401BCF: 8B 4D F8           mov         ecx,dword ptr [ebp-8]
  00401BD2: 29 C1              sub         ecx,eax
  00401BD4: 89 4D F0           mov         dword ptr [ebp-10h],ecx
  00401BD7: 85 C0              test        eax,eax
  00401BD9: 7E 1E              jle         00401BF9
  00401BDB: 8B 55 08           mov         edx,dword ptr [ebp+8]
  00401BDE: 8D 1C 8A           lea         ebx,[edx+ecx*4]
  00401BE1: 8D 0C BA           lea         ecx,[edx+edi*4]
  00401BE4: 89 C6              mov         esi,eax
  00401BE6: 89 F6              mov         esi,esi
  00401BE8: 8B 11              mov         edx,dword ptr [ecx]
  00401BEA: 8B 03              mov         eax,dword ptr [ebx]
  00401BEC: 89 01              mov         dword ptr [ecx],eax
  00401BEE: 89 13              mov         dword ptr [ebx],edx
  00401BF0: 83 C3 04           add         ebx,4
  00401BF3: 83 C1 04           add         ecx,4
  00401BF6: 4E                 dec         esi
  00401BF7: 75 EF              jne         00401BE8
  00401BF9: 8B 4D F0           mov         ecx,dword ptr [ebp-10h]
  00401BFC: 89 4D F8           mov         dword ptr [ebp-8],ecx
  00401BFF: EB 2F              jmp         00401C30
  00401C01: 8D 76 00           lea         esi,[esi]
  00401C04: 8D 04 3A           lea         eax,[edx+edi]
  00401C07: 89 45 F4           mov         dword ptr [ebp-0Ch],eax
  00401C0A: 85 D2              test        edx,edx
  00401C0C: 7E 1F              jle         00401C2D
  00401C0E: 8B 4D FC           mov         ecx,dword ptr [ebp-4]
  00401C11: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00401C14: 8D 1C 88           lea         ebx,[eax+ecx*4]
  00401C17: 8D 0C B8           lea         ecx,[eax+edi*4]
  00401C1A: 89 D6              mov         esi,edx
  00401C1C: 8B 11              mov         edx,dword ptr [ecx]
  00401C1E: 8B 03              mov         eax,dword ptr [ebx]
  00401C20: 89 01              mov         dword ptr [ecx],eax
  00401C22: 89 13              mov         dword ptr [ebx],edx
  00401C24: 83 C3 04           add         ebx,4
  00401C27: 83 C1 04           add         ecx,4
  00401C2A: 4E                 dec         esi
  00401C2B: 75 EF              jne         00401C1C
  00401C2D: 8B 7D F4           mov         edi,dword ptr [ebp-0Ch]
  00401C30: 8B 55 FC           mov         edx,dword ptr [ebp-4]
  00401C33: 39 55 F8           cmp         dword ptr [ebp-8],edx
  00401C36: 7E 04              jle         00401C3C
  00401C38: 39 FA              cmp         edx,edi
  00401C3A: 7F 84              jg          00401BC0
  00401C3C: 8B 15 08 60 40 00  mov         edx,dword ptr ds:[00406008h]
  00401C42: 89 D0              mov         eax,edx
  00401C44: 2B 05 50 70 40 00  sub         eax,dword ptr ds:[00407050h]
  00401C4A: 01 05 40 70 40 00  add         dword ptr ds:[00407040h],eax
  00401C50: 89 15 50 70 40 00  mov         dword ptr ds:[00407050h],edx
  00401C56: 5B                 pop         ebx
  00401C57: 5E                 pop         esi
  00401C58: 5F                 pop         edi
  00401C59: C9                 leave
  00401C5A: C3                 ret
  00401C5B: 50                 push        eax
  00401C5C: 4F                 dec         edi
  00401C5D: 53                 push        ebx
  00401C5E: 49                 dec         ecx
  00401C5F: 58                 pop         eax
  00401C60: 4C                 dec         esp
  00401C61: 59                 pop         ecx
  00401C62: 5F                 pop         edi
  00401C63: 43                 inc         ebx
  00401C64: 4F                 dec         edi
  00401C65: 52                 push        edx
  00401C66: 52                 push        edx
  00401C67: 45                 inc         ebp
  00401C68: 43                 inc         ebx
  00401C69: 54                 push        esp
  00401C6A: 00 90 55 89 E5 83  add         byte ptr [eax+83E58955h],dl
  00401C70: EC                 in          al,dx
  00401C71: 14 53              adc         al,53h
  00401C73: 8B 5D 10           mov         ebx,dword ptr [ebp+10h]
  00401C76: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00401C7B: A3 50 70 40 00     mov         dword ptr ds:[00407050h],eax
  00401C80: A3 40 70 40 00     mov         dword ptr ds:[00407040h],eax
  00401C85: C7 05 10 70 40 00  mov         dword ptr ds:[00407010h],0
            00 00 00 00
  00401C8F: 83 C4 F4           add         esp,0FFFFFFF4h
  00401C92: 68 5B 1C 40 00     push        401C5Bh
  00401C97: E8 6C 35 00 00     call        00405208
  00401C9C: A3 30 70 40 00     mov         dword ptr ds:[00407030h],eax
  00401CA1: 8A 13              mov         dl,byte ptr [ebx]
  00401CA3: 80 FA 2D           cmp         dl,2Dh
  00401CA6: 75 10              jne         00401CB8
  00401CA8: C7 05 20 70 40 00  mov         dword ptr ds:[00407020h],2
            02 00 00 00
  00401CB2: 43                 inc         ebx
  00401CB3: EB 31              jmp         00401CE6
  00401CB5: 8D 76 00           lea         esi,[esi]
  00401CB8: 80 FA 2B           cmp         dl,2Bh
  00401CBB: 75 0F              jne         00401CCC
  00401CBD: C7 05 20 70 40 00  mov         dword ptr ds:[00407020h],0
            00 00 00 00
  00401CC7: 43                 inc         ebx
  00401CC8: EB 1C              jmp         00401CE6
  00401CCA: 89 F6              mov         esi,esi
  00401CCC: 85 C0              test        eax,eax
  00401CCE: 74 0C              je          00401CDC
  00401CD0: C7 05 20 70 40 00  mov         dword ptr ds:[00407020h],0
            00 00 00 00
  00401CDA: EB 0A              jmp         00401CE6
  00401CDC: C7 05 20 70 40 00  mov         dword ptr ds:[00407020h],1
            01 00 00 00
  00401CE6: 89 D8              mov         eax,ebx
  00401CE8: 8B 5D E8           mov         ebx,dword ptr [ebp-18h]
  00401CEB: C9                 leave
  00401CEC: C3                 ret
  00401CED: 2D 2D 00 25 73     sub         eax,7325002Dh
  00401CF2: 3A 20              cmp         ah,byte ptr [eax]
  00401CF4: 6F                 outs        dx,dword ptr [esi]
  00401CF5: 70 74              jo          00401D6B
  00401CF7: 69 6F 6E 20 60 25  imul        ebp,dword ptr [edi+6Eh],73256020h
            73
  00401CFE: 27                 daa
  00401CFF: 20 69 73           and         byte ptr [ecx+73h],ch
  00401D02: 20 61 6D           and         byte ptr [ecx+6Dh],ah
  00401D05: 62 69 67           bound       ebp,qword ptr [ecx+67h]
  00401D08: 75 6F              jne         00401D79
  00401D0A: 75 73              jne         00401D7F
  00401D0C: 0A 00              or          al,byte ptr [eax]
  00401D0E: 90                 nop
  00401D0F: 90                 nop
  00401D10: 90                 nop
  00401D11: 90                 nop
  00401D12: 90                 nop
  00401D13: 90                 nop
  00401D14: 90                 nop
  00401D15: 90                 nop
  00401D16: 90                 nop
  00401D17: 90                 nop
  00401D18: 90                 nop
  00401D19: 90                 nop
  00401D1A: 90                 nop
  00401D1B: 90                 nop
  00401D1C: 90                 nop
  00401D1D: 90                 nop
  00401D1E: 90                 nop
  00401D1F: 90                 nop
  00401D20: 90                 nop
  00401D21: 90                 nop
  00401D22: 90                 nop
  00401D23: 90                 nop
  00401D24: 90                 nop
  00401D25: 90                 nop
  00401D26: 90                 nop
  00401D27: 90                 nop
  00401D28: 90                 nop
  00401D29: 90                 nop
  00401D2A: 90                 nop
  00401D2B: 90                 nop
  00401D2C: 25 73 3A 20 6F     and         eax,6F203A73h
  00401D31: 70 74              jo          00401DA7
  00401D33: 69 6F 6E 20 60 2D  imul        ebp,dword ptr [edi+6Eh],2D2D6020h
            2D
  00401D3A: 25 73 27 20 64     and         eax,64202773h
  00401D3F: 6F                 outs        dx,dword ptr [esi]
  00401D40: 65 73 6E           jae         00401DB1
  00401D43: 27                 daa
  00401D44: 74 20              je          00401D66
  00401D46: 61                 popad
  00401D47: 6C                 ins         byte ptr es:[edi],dx
  00401D48: 6C                 ins         byte ptr es:[edi],dx
  00401D49: 6F                 outs        dx,dword ptr [esi]
  00401D4A: 77 20              ja          00401D6C
  00401D4C: 61                 popad
  00401D4D: 6E                 outs        dx,byte ptr [esi]
  00401D4E: 20 61 72           and         byte ptr [ecx+72h],ah
  00401D51: 67 75 6D           jne         00401DC1
  00401D54: 65 6E              outs        dx,byte ptr gs:[esi]
  00401D56: 74 0A              je          00401D62
  00401D58: 00 90 90 90 90 90  add         byte ptr [eax+90909090h],dl
  00401D5E: 90                 nop
  00401D5F: 90                 nop
  00401D60: 90                 nop
  00401D61: 90                 nop
  00401D62: 90                 nop
  00401D63: 90                 nop
  00401D64: 90                 nop
  00401D65: 90                 nop
  00401D66: 90                 nop
  00401D67: 90                 nop
  00401D68: 90                 nop
  00401D69: 90                 nop
  00401D6A: 90                 nop
  00401D6B: 90                 nop
  00401D6C: 25 73 3A 20 6F     and         eax,6F203A73h
  00401D71: 70 74              jo          00401DE7
  00401D73: 69 6F 6E 20 60 25  imul        ebp,dword ptr [edi+6Eh],63256020h
            63
  00401D7A: 25 73 27 20 64     and         eax,64202773h
  00401D7F: 6F                 outs        dx,dword ptr [esi]
  00401D80: 65 73 6E           jae         00401DF1
  00401D83: 27                 daa
  00401D84: 74 20              je          00401DA6
  00401D86: 61                 popad
  00401D87: 6C                 ins         byte ptr es:[edi],dx
  00401D88: 6C                 ins         byte ptr es:[edi],dx
  00401D89: 6F                 outs        dx,dword ptr [esi]
  00401D8A: 77 20              ja          00401DAC
  00401D8C: 61                 popad
  00401D8D: 6E                 outs        dx,byte ptr [esi]
  00401D8E: 20 61 72           and         byte ptr [ecx+72h],ah
  00401D91: 67 75 6D           jne         00401E01
  00401D94: 65 6E              outs        dx,byte ptr gs:[esi]
  00401D96: 74 0A              je          00401DA2
  00401D98: 00 90 90 90 90 90  add         byte ptr [eax+90909090h],dl
  00401D9E: 90                 nop
  00401D9F: 90                 nop
  00401DA0: 90                 nop
  00401DA1: 90                 nop
  00401DA2: 90                 nop
  00401DA3: 90                 nop
  00401DA4: 90                 nop
  00401DA5: 90                 nop
  00401DA6: 90                 nop
  00401DA7: 90                 nop
  00401DA8: 90                 nop
  00401DA9: 90                 nop
  00401DAA: 90                 nop
  00401DAB: 90                 nop
  00401DAC: 25 73 3A 20 6F     and         eax,6F203A73h
  00401DB1: 70 74              jo          00401E27
  00401DB3: 69 6F 6E 20 60 25  imul        ebp,dword ptr [edi+6Eh],73256020h
            73
  00401DBA: 27                 daa
  00401DBB: 20 72 65           and         byte ptr [edx+65h],dh
  00401DBE: 71 75              jno         00401E35
  00401DC0: 69 72 65 73 20 61  imul        esi,dword ptr [edx+65h],6E612073h
            6E
  00401DC7: 20 61 72           and         byte ptr [ecx+72h],ah
  00401DCA: 67 75 6D           jne         00401E3A
  00401DCD: 65 6E              outs        dx,byte ptr gs:[esi]
  00401DCF: 74 0A              je          00401DDB
  00401DD1: 00 90 90 90 90 90  add         byte ptr [eax+90909090h],dl
  00401DD7: 90                 nop
  00401DD8: 90                 nop
  00401DD9: 90                 nop
  00401DDA: 90                 nop
  00401DDB: 90                 nop
  00401DDC: 90                 nop
  00401DDD: 90                 nop
  00401DDE: 90                 nop
  00401DDF: 90                 nop
  00401DE0: 90                 nop
  00401DE1: 90                 nop
  00401DE2: 90                 nop
  00401DE3: 90                 nop
  00401DE4: 90                 nop
  00401DE5: 90                 nop
  00401DE6: 90                 nop
  00401DE7: 90                 nop
  00401DE8: 90                 nop
  00401DE9: 90                 nop
  00401DEA: 90                 nop
  00401DEB: 90                 nop
  00401DEC: 25 73 3A 20 75     and         eax,75203A73h
  00401DF1: 6E                 outs        dx,byte ptr [esi]
  00401DF2: 72 65              jb          00401E59
  00401DF4: 63 6F 67           arpl        word ptr [edi+67h],bp
  00401DF7: 6E                 outs        dx,byte ptr [esi]
  00401DF8: 69 7A 65 64 20 6F  imul        edi,dword ptr [edx+65h],706F2064h
            70
  00401DFF: 74 69              je          00401E6A
  00401E01: 6F                 outs        dx,dword ptr [esi]
  00401E02: 6E                 outs        dx,byte ptr [esi]
  00401E03: 20 60 2D           and         byte ptr [eax+2Dh],ah
  00401E06: 2D 25 73 27 0A     sub         eax,0A277325h
  00401E0B: 00 25 73 3A 20 75  add         byte ptr ds:[75203A73h],ah
  00401E11: 6E                 outs        dx,byte ptr [esi]
  00401E12: 72 65              jb          00401E79
  00401E14: 63 6F 67           arpl        word ptr [edi+67h],bp
  00401E17: 6E                 outs        dx,byte ptr [esi]
  00401E18: 69 7A 65 64 20 6F  imul        edi,dword ptr [edx+65h],706F2064h
            70
  00401E1F: 74 69              je          00401E8A
  00401E21: 6F                 outs        dx,dword ptr [esi]
  00401E22: 6E                 outs        dx,byte ptr [esi]
  00401E23: 20 60 25           and         byte ptr [eax+25h],ah
  00401E26: 63 25 73 27 0A 00  arpl        word ptr ds:[000A2773h],sp
  00401E2C: 00 25 73 3A 20 69  add         byte ptr ds:[69203A73h],ah
  00401E32: 6C                 ins         byte ptr es:[edi],dx
  00401E33: 6C                 ins         byte ptr es:[edi],dx
  00401E34: 65 67 61           popad
  00401E37: 6C                 ins         byte ptr es:[edi],dx
  00401E38: 20 6F 70           and         byte ptr [edi+70h],ch
  00401E3B: 74 69              je          00401EA6
  00401E3D: 6F                 outs        dx,dword ptr [esi]
  00401E3E: 6E                 outs        dx,byte ptr [esi]
  00401E3F: 20 2D 2D 20 25 63  and         byte ptr ds:[6325202Dh],ch
  00401E45: 0A 00              or          al,byte ptr [eax]
  00401E47: 25 73 3A 20 69     and         eax,69203A73h
  00401E4C: 6E                 outs        dx,byte ptr [esi]
  00401E4D: 76 61              jbe         00401EB0
  00401E4F: 6C                 ins         byte ptr es:[edi],dx
  00401E50: 69 64 20 6F 70 74  imul        esp,dword ptr [eax+6Fh],6F697470h
            69 6F
  00401E58: 6E                 outs        dx,byte ptr [esi]
  00401E59: 20 2D 2D 20 25 63  and         byte ptr ds:[6325202Dh],ch
  00401E5F: 0A 00              or          al,byte ptr [eax]
  00401E61: 8D 74 26 00        lea         esi,[esi]
  00401E65: 8D BC 27 00 00 00  lea         edi,[edi+00000000h]
            00
  00401E6C: 25 73 3A 20 6F     and         eax,6F203A73h
  00401E71: 70 74              jo          00401EE7
  00401E73: 69 6F 6E 20 72 65  imul        ebp,dword ptr [edi+6Eh],71657220h
            71
  00401E7A: 75 69              jne         00401EE5
  00401E7C: 72 65              jb          00401EE3
  00401E7E: 73 20              jae         00401EA0
  00401E80: 61                 popad
  00401E81: 6E                 outs        dx,byte ptr [esi]
  00401E82: 20 61 72           and         byte ptr [ecx+72h],ah
  00401E85: 67 75 6D           jne         00401EF5
  00401E88: 65 6E              outs        dx,byte ptr gs:[esi]
  00401E8A: 74 20              je          00401EAC
  00401E8C: 2D 2D 20 25 63     sub         eax,6325202Dh
  00401E91: 0A 00              or          al,byte ptr [eax]
  00401E93: 90                 nop
  00401E94: 90                 nop
  00401E95: 90                 nop
  00401E96: 90                 nop
  00401E97: 90                 nop
  00401E98: 90                 nop
  00401E99: 90                 nop
  00401E9A: 90                 nop
  00401E9B: 90                 nop
  00401E9C: 90                 nop
  00401E9D: 90                 nop
  00401E9E: 90                 nop
  00401E9F: 90                 nop
  00401EA0: 90                 nop
  00401EA1: 90                 nop
  00401EA2: 90                 nop
  00401EA3: 90                 nop
  00401EA4: 90                 nop
  00401EA5: 90                 nop
  00401EA6: 90                 nop
  00401EA7: 90                 nop
  00401EA8: 90                 nop
  00401EA9: 90                 nop
  00401EAA: 90                 nop
  00401EAB: 90                 nop
  00401EAC: 25 73 3A 20 6F     and         eax,6F203A73h
  00401EB1: 70 74              jo          00401F27
  00401EB3: 69 6F 6E 20 60 2D  imul        ebp,dword ptr [edi+6Eh],572D6020h
            57
  00401EBA: 20 25 73 27 20 69  and         byte ptr ds:[69202773h],ah
  00401EC0: 73 20              jae         00401EE2
  00401EC2: 61                 popad
  00401EC3: 6D                 ins         dword ptr es:[edi],dx
  00401EC4: 62 69 67           bound       ebp,qword ptr [ecx+67h]
  00401EC7: 75 6F              jne         00401F38
  00401EC9: 75 73              jne         00401F3E
  00401ECB: 0A 00              or          al,byte ptr [eax]
  00401ECD: 90                 nop
  00401ECE: 90                 nop
  00401ECF: 90                 nop
  00401ED0: 90                 nop
  00401ED1: 90                 nop
  00401ED2: 90                 nop
  00401ED3: 90                 nop
  00401ED4: 90                 nop
  00401ED5: 90                 nop
  00401ED6: 90                 nop
  00401ED7: 90                 nop
  00401ED8: 90                 nop
  00401ED9: 90                 nop
  00401EDA: 90                 nop
  00401EDB: 90                 nop
  00401EDC: 90                 nop
  00401EDD: 90                 nop
  00401EDE: 90                 nop
  00401EDF: 90                 nop
  00401EE0: 90                 nop
  00401EE1: 90                 nop
  00401EE2: 90                 nop
  00401EE3: 90                 nop
  00401EE4: 90                 nop
  00401EE5: 90                 nop
  00401EE6: 90                 nop
  00401EE7: 90                 nop
  00401EE8: 90                 nop
  00401EE9: 90                 nop
  00401EEA: 90                 nop
  00401EEB: 90                 nop
  00401EEC: 25 73 3A 20 6F     and         eax,6F203A73h
  00401EF1: 70 74              jo          00401F67
  00401EF3: 69 6F 6E 20 60 2D  imul        ebp,dword ptr [edi+6Eh],572D6020h
            57
  00401EFA: 20 25 73 27 20 64  and         byte ptr ds:[64202773h],ah
  00401F00: 6F                 outs        dx,dword ptr [esi]
  00401F01: 65 73 6E           jae         00401F72
  00401F04: 27                 daa
  00401F05: 74 20              je          00401F27
  00401F07: 61                 popad
  00401F08: 6C                 ins         byte ptr es:[edi],dx
  00401F09: 6C                 ins         byte ptr es:[edi],dx
  00401F0A: 6F                 outs        dx,dword ptr [esi]
  00401F0B: 77 20              ja          00401F2D
  00401F0D: 61                 popad
  00401F0E: 6E                 outs        dx,byte ptr [esi]
  00401F0F: 20 61 72           and         byte ptr [ecx+72h],ah
  00401F12: 67 75 6D           jne         00401F82
  00401F15: 65 6E              outs        dx,byte ptr gs:[esi]
  00401F17: 74 0A              je          00401F23
  00401F19: 00 89 F6 55 89 E5  add         byte ptr [ecx+E58955F6h],cl
  00401F1F: 83 EC 3C           sub         esp,3Ch
  00401F22: 57                 push        edi
  00401F23: 56                 push        esi
  00401F24: 53                 push        ebx
  00401F25: A1 0C 60 40 00     mov         eax,dword ptr ds:[0040600Ch]
  00401F2A: 89 45 FC           mov         dword ptr [ebp-4],eax
  00401F2D: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  00401F30: 80 3A 3A           cmp         byte ptr [edx],3Ah
  00401F33: 75 07              jne         00401F3C
  00401F35: C7 45 FC 00 00 00  mov         dword ptr [ebp-4],0
            00
  00401F3C: 83 7D 08 00        cmp         dword ptr [ebp+8],0
  00401F40: 0F 8E 8D 01 00 00  jle         004020D3
  00401F46: C7 05 E0 71 40 00  mov         dword ptr ds:[004071E0h],0
            00 00 00 00
  00401F50: 83 3D 08 60 40 00  cmp         dword ptr ds:[00406008h],0
            00
  00401F57: 74 0B              je          00401F64
  00401F59: 83 3D D0 71 40 00  cmp         dword ptr ds:[004071D0h],0
            00
  00401F60: 75 30              jne         00401F92
  00401F62: EB 0A              jmp         00401F6E
  00401F64: C7 05 08 60 40 00  mov         dword ptr ds:[00406008h],1
            01 00 00 00
  00401F6E: 83 C4 FC           add         esp,0FFFFFFFCh
  00401F71: 8B 4D 10           mov         ecx,dword ptr [ebp+10h]
  00401F74: 51                 push        ecx
  00401F75: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  00401F78: 50                 push        eax
  00401F79: 8B 55 08           mov         edx,dword ptr [ebp+8]
  00401F7C: 52                 push        edx
  00401F7D: E8 EA FC FF FF     call        00401C6C
  00401F82: 89 45 10           mov         dword ptr [ebp+10h],eax
  00401F85: C7 05 D0 71 40 00  mov         dword ptr ds:[004071D0h],1
            01 00 00 00
  00401F8F: 83 C4 10           add         esp,10h
  00401F92: A1 10 70 40 00     mov         eax,dword ptr ds:[00407010h]
  00401F97: 85 C0              test        eax,eax
  00401F99: 74 09              je          00401FA4
  00401F9B: 80 38 00           cmp         byte ptr [eax],0
  00401F9E: 0F 85 70 01 00 00  jne         00402114
  00401FA4: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00401FA9: 39 05 50 70 40 00  cmp         dword ptr ds:[00407050h],eax
  00401FAF: 7E 05              jle         00401FB6
  00401FB1: A3 50 70 40 00     mov         dword ptr ds:[00407050h],eax
  00401FB6: 39 05 40 70 40 00  cmp         dword ptr ds:[00407040h],eax
  00401FBC: 7E 05              jle         00401FC3
  00401FBE: A3 40 70 40 00     mov         dword ptr ds:[00407040h],eax
  00401FC3: 83 3D 20 70 40 00  cmp         dword ptr ds:[00407020h],1
            01
  00401FCA: 75 68              jne         00402034
  00401FCC: 8B 0D 40 70 40 00  mov         ecx,dword ptr ds:[00407040h]
  00401FD2: 8B 15 50 70 40 00  mov         edx,dword ptr ds:[00407050h]
  00401FD8: 39 D1              cmp         ecx,edx
  00401FDA: 74 18              je          00401FF4
  00401FDC: 39 C2              cmp         edx,eax
  00401FDE: 74 1D              je          00401FFD
  00401FE0: 83 C4 F4           add         esp,0FFFFFFF4h
  00401FE3: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00401FE6: 51                 push        ecx
  00401FE7: E8 A8 FB FF FF     call        00401B94
  00401FEC: 83 C4 10           add         esp,10h
  00401FEF: EB 0C              jmp         00401FFD
  00401FF1: 8D 76 00           lea         esi,[esi]
  00401FF4: 39 C1              cmp         ecx,eax
  00401FF6: 74 05              je          00401FFD
  00401FF8: A3 40 70 40 00     mov         dword ptr ds:[00407040h],eax
  00401FFD: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402002: EB 10              jmp         00402014
  00402004: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402009: 8D 48 01           lea         ecx,[eax+1]
  0040200C: 89 0D 08 60 40 00  mov         dword ptr ds:[00406008h],ecx
  00402012: 89 C8              mov         eax,ecx
  00402014: 3B 45 08           cmp         eax,dword ptr [ebp+8]
  00402017: 7D 11              jge         0040202A
  00402019: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  0040201C: 8B 04 82           mov         eax,dword ptr [edx+eax*4]
  0040201F: 80 38 2D           cmp         byte ptr [eax],2Dh
  00402022: 75 E0              jne         00402004
  00402024: 80 78 01 00        cmp         byte ptr [eax+1],0
  00402028: 74 DA              je          00402004
  0040202A: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  0040202F: A3 50 70 40 00     mov         dword ptr ds:[00407050h],eax
  00402034: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402039: 3B 45 08           cmp         eax,dword ptr [ebp+8]
  0040203C: 74 63              je          004020A1
  0040203E: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402041: 8B 34 81           mov         esi,dword ptr [ecx+eax*4]
  00402044: BF ED 1C 40 00     mov         edi,401CEDh
  00402049: B9 03 00 00 00     mov         ecx,3
  0040204E: FC                 cld
  0040204F: A8 00              test        al,0
  00402051: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  00402053: 75 42              jne         00402097
  00402055: 8D 50 01           lea         edx,[eax+1]
  00402058: 89 15 08 60 40 00  mov         dword ptr ds:[00406008h],edx
  0040205E: 8B 15 50 70 40 00  mov         edx,dword ptr ds:[00407050h]
  00402064: 39 15 40 70 40 00  cmp         dword ptr ds:[00407040h],edx
  0040206A: 74 18              je          00402084
  0040206C: 40                 inc         eax
  0040206D: 39 C2              cmp         edx,eax
  0040206F: 74 19              je          0040208A
  00402071: 83 C4 F4           add         esp,0FFFFFFF4h
  00402074: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402077: 51                 push        ecx
  00402078: E8 17 FB FF FF     call        00401B94
  0040207D: 83 C4 10           add         esp,10h
  00402080: EB 08              jmp         0040208A
  00402082: 89 F6              mov         esi,esi
  00402084: 40                 inc         eax
  00402085: A3 40 70 40 00     mov         dword ptr ds:[00407040h],eax
  0040208A: 8B 45 08           mov         eax,dword ptr [ebp+8]
  0040208D: A3 50 70 40 00     mov         dword ptr ds:[00407050h],eax
  00402092: A3 08 60 40 00     mov         dword ptr ds:[00406008h],eax
  00402097: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  0040209C: 3B 45 08           cmp         eax,dword ptr [ebp+8]
  0040209F: 75 17              jne         004020B8
  004020A1: A1 40 70 40 00     mov         eax,dword ptr ds:[00407040h]
  004020A6: 3B 05 50 70 40 00  cmp         eax,dword ptr ds:[00407050h]
  004020AC: 74 25              je          004020D3
  004020AE: A3 08 60 40 00     mov         dword ptr ds:[00406008h],eax
  004020B3: EB 1E              jmp         004020D3
  004020B5: 8D 76 00           lea         esi,[esi]
  004020B8: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  004020BB: 8B 14 81           mov         edx,dword ptr [ecx+eax*4]
  004020BE: 80 3A 2D           cmp         byte ptr [edx],2Dh
  004020C1: 75 07              jne         004020CA
  004020C3: 8A 4A 01           mov         cl,byte ptr [edx+1]
  004020C6: 84 C9              test        cl,cl
  004020C8: 75 2E              jne         004020F8
  004020CA: 83 3D 20 70 40 00  cmp         dword ptr ds:[00407020h],0
            00
  004020D1: 75 0D              jne         004020E0
  004020D3: B8 FF FF FF FF     mov         eax,0FFFFFFFFh
  004020D8: E9 F5 07 00 00     jmp         004028D2
  004020DD: 8D 76 00           lea         esi,[esi]
  004020E0: 89 15 E0 71 40 00  mov         dword ptr ds:[004071E0h],edx
  004020E6: FF 05 08 60 40 00  inc         dword ptr ds:[00406008h]
  004020EC: B8 01 00 00 00     mov         eax,1
  004020F1: E9 DC 07 00 00     jmp         004028D2
  004020F6: 89 F6              mov         esi,esi
  004020F8: 31 C0              xor         eax,eax
  004020FA: 83 7D 14 00        cmp         dword ptr [ebp+14h],0
  004020FE: 74 0B              je          0040210B
  00402100: 80 F9 2D           cmp         cl,2Dh
  00402103: 0F 94 C0           sete        al
  00402106: 25 FF 00 00 00     and         eax,0FFh
  0040210B: 40                 inc         eax
  0040210C: 01 C2              add         edx,eax
  0040210E: 89 15 10 70 40 00  mov         dword ptr ds:[00407010h],edx
  00402114: 83 7D 14 00        cmp         dword ptr [ebp+14h],0
  00402118: 0F 84 AE 03 00 00  je          004024CC
  0040211E: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402123: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00402126: 8B 04 82           mov         eax,dword ptr [edx+eax*4]
  00402129: 80 78 01 2D        cmp         byte ptr [eax+1],2Dh
  0040212D: 74 2C              je          0040215B
  0040212F: 83 7D 1C 00        cmp         dword ptr [ebp+1Ch],0
  00402133: 0F 84 93 03 00 00  je          004024CC
  00402139: 80 78 02 00        cmp         byte ptr [eax+2],0
  0040213D: 75 1C              jne         0040215B
  0040213F: 83 C4 F8           add         esp,0FFFFFFF8h
  00402142: 0F BE 40 01        movsx       eax,byte ptr [eax+1]
  00402146: 50                 push        eax
  00402147: 8B 4D 10           mov         ecx,dword ptr [ebp+10h]
  0040214A: 51                 push        ecx
  0040214B: E8 1C FA FF FF     call        00401B6C
  00402150: 83 C4 10           add         esp,10h
  00402153: 85 C0              test        eax,eax
  00402155: 0F 85 71 03 00 00  jne         004024CC
  0040215B: C7 45 F8 00 00 00  mov         dword ptr [ebp-8],0
            00
  00402162: C7 45 F4 00 00 00  mov         dword ptr [ebp-0Ch],0
            00
  00402169: C7 45 F0 00 00 00  mov         dword ptr [ebp-10h],0
            00
  00402170: C7 45 EC FF FF FF  mov         dword ptr [ebp-14h],0FFFFFFFFh
            FF
  00402177: 8B 35 10 70 40 00  mov         esi,dword ptr ds:[00407010h]
  0040217D: EB 02              jmp         00402181
  0040217F: 90                 nop
  00402180: 46                 inc         esi
  00402181: 8A 06              mov         al,byte ptr [esi]
  00402183: 84 C0              test        al,al
  00402185: 74 04              je          0040218B
  00402187: 3C 3D              cmp         al,3Dh
  00402189: 75 F5              jne         00402180
  0040218B: 8B 5D 14           mov         ebx,dword ptr [ebp+14h]
  0040218E: C7 45 E8 00 00 00  mov         dword ptr [ebp-18h],0
            00
  00402195: EB 43              jmp         004021DA
  00402197: 90                 nop
  00402198: 83 7D F8 00        cmp         dword ptr [ebp-8],0
  0040219C: 75 0E              jne         004021AC
  0040219E: 89 5D F8           mov         dword ptr [ebp-8],ebx
  004021A1: 8B 45 E8           mov         eax,dword ptr [ebp-18h]
  004021A4: 89 45 EC           mov         dword ptr [ebp-14h],eax
  004021A7: EB 2B              jmp         004021D4
  004021A9: 8D 76 00           lea         esi,[esi]
  004021AC: 83 7D 1C 00        cmp         dword ptr [ebp+1Ch],0
  004021B0: 75 1B              jne         004021CD
  004021B2: 8B 43 04           mov         eax,dword ptr [ebx+4]
  004021B5: 8B 55 F8           mov         edx,dword ptr [ebp-8]
  004021B8: 39 42 04           cmp         dword ptr [edx+4],eax
  004021BB: 75 10              jne         004021CD
  004021BD: 8B 43 08           mov         eax,dword ptr [ebx+8]
  004021C0: 39 42 08           cmp         dword ptr [edx+8],eax
  004021C3: 75 08              jne         004021CD
  004021C5: 8B 43 0C           mov         eax,dword ptr [ebx+0Ch]
  004021C8: 39 42 0C           cmp         dword ptr [edx+0Ch],eax
  004021CB: 74 07              je          004021D4
  004021CD: C7 45 F0 01 00 00  mov         dword ptr [ebp-10h],1
            00
  004021D4: 83 C3 10           add         ebx,10h
  004021D7: FF 45 E8           inc         dword ptr [ebp-18h]
  004021DA: 8B 0B              mov         ecx,dword ptr [ebx]
  004021DC: 85 C9              test        ecx,ecx
  004021DE: 74 4D              je          0040222D
  004021E0: 83 C4 FC           add         esp,0FFFFFFFCh
  004021E3: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  004021E9: 89 F0              mov         eax,esi
  004021EB: 29 D0              sub         eax,edx
  004021ED: 50                 push        eax
  004021EE: 52                 push        edx
  004021EF: 51                 push        ecx
  004021F0: E8 0B 30 00 00     call        00405200
  004021F5: 83 C4 10           add         esp,10h
  004021F8: 85 C0              test        eax,eax
  004021FA: 75 D8              jne         004021D4
  004021FC: 89 F2              mov         edx,esi
  004021FE: 2B 15 10 70 40 00  sub         edx,dword ptr ds:[00407010h]
  00402204: 8B 3B              mov         edi,dword ptr [ebx]
  00402206: B0 00              mov         al,0
  00402208: FC                 cld
  00402209: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  0040220E: F2 AE              repne scas  byte ptr es:[edi]
  00402210: F7 D1              not         ecx
  00402212: 8D 41 FF           lea         eax,[ecx-1]
  00402215: 39 C2              cmp         edx,eax
  00402217: 0F 85 7B FF FF FF  jne         00402198
  0040221D: 89 5D F8           mov         dword ptr [ebp-8],ebx
  00402220: 8B 55 E8           mov         edx,dword ptr [ebp-18h]
  00402223: 89 55 EC           mov         dword ptr [ebp-14h],edx
  00402226: C7 45 F4 01 00 00  mov         dword ptr [ebp-0Ch],1
            00
  0040222D: 83 7D F0 00        cmp         dword ptr [ebp-10h],0
  00402231: 74 51              je          00402284
  00402233: 83 7D F4 00        cmp         dword ptr [ebp-0Ch],0
  00402237: 75 4B              jne         00402284
  00402239: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  0040223D: 74 20              je          0040225F
  0040223F: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402244: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402247: FF 34 81           push        dword ptr [ecx+eax*4]
  0040224A: FF 31              push        dword ptr [ecx]
  0040224C: 68 F0 1C 40 00     push        401CF0h
  00402251: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402256: 83 C0 40           add         eax,40h
  00402259: 50                 push        eax
  0040225A: E8 99 2F 00 00     call        004051F8
  0040225F: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  00402265: 89 D7              mov         edi,edx
  00402267: B0 00              mov         al,0
  00402269: FC                 cld
  0040226A: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  0040226F: F2 AE              repne scas  byte ptr es:[edi]
  00402271: F7 D1              not         ecx
  00402273: 8D 44 0A FF        lea         eax,[edx+ecx-1]
  00402277: A3 10 70 40 00     mov         dword ptr ds:[00407010h],eax
  0040227C: E9 2E 02 00 00     jmp         004024AF
  00402281: 8D 76 00           lea         esi,[esi]
  00402284: 83 7D F8 00        cmp         dword ptr [ebp-8],0
  00402288: 0F 84 86 01 00 00  je          00402414
  0040228E: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402293: 8D 50 01           lea         edx,[eax+1]
  00402296: 89 15 08 60 40 00  mov         dword ptr ds:[00406008h],edx
  0040229C: 80 3E 00           cmp         byte ptr [esi],0
  0040229F: 0F 84 9B 00 00 00  je          00402340
  004022A5: 8B 4D F8           mov         ecx,dword ptr [ebp-8]
  004022A8: 83 79 04 00        cmp         dword ptr [ecx+4],0
  004022AC: 74 0E              je          004022BC
  004022AE: 46                 inc         esi
  004022AF: 89 35 E0 71 40 00  mov         dword ptr ds:[004071E0h],esi
  004022B5: E9 16 01 00 00     jmp         004023D0
  004022BA: 89 F6              mov         esi,esi
  004022BC: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  004022C0: 74 56              je          00402318
  004022C2: 8D 50 01           lea         edx,[eax+1]
  004022C5: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  004022C8: 8B 44 91 FC        mov         eax,dword ptr [ecx+edx*4-4]
  004022CC: 80 78 01 2D        cmp         byte ptr [eax+1],2Dh
  004022D0: 75 1E              jne         004022F0
  004022D2: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  004022D5: FF 30              push        dword ptr [eax]
  004022D7: FF 31              push        dword ptr [ecx]
  004022D9: 68 2C 1D 40 00     push        401D2Ch
  004022DE: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004022E3: 83 C0 40           add         eax,40h
  004022E6: 50                 push        eax
  004022E7: E8 0C 2F 00 00     call        004051F8
  004022EC: EB 2A              jmp         00402318
  004022EE: 89 F6              mov         esi,esi
  004022F0: 83 C4 F4           add         esp,0FFFFFFF4h
  004022F3: 8B 4D F8           mov         ecx,dword ptr [ebp-8]
  004022F6: FF 31              push        dword ptr [ecx]
  004022F8: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  004022FB: 8B 44 91 FC        mov         eax,dword ptr [ecx+edx*4-4]
  004022FF: 0F BE 00           movsx       eax,byte ptr [eax]
  00402302: 50                 push        eax
  00402303: FF 31              push        dword ptr [ecx]
  00402305: 68 6C 1D 40 00     push        401D6Ch
  0040230A: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  0040230F: 83 C0 40           add         eax,40h
  00402312: 50                 push        eax
  00402313: E8 E0 2E 00 00     call        004051F8
  00402318: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  0040231E: 89 D7              mov         edi,edx
  00402320: B0 00              mov         al,0
  00402322: FC                 cld
  00402323: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  00402328: F2 AE              repne scas  byte ptr es:[edi]
  0040232A: F7 D1              not         ecx
  0040232C: 8D 44 0A FF        lea         eax,[edx+ecx-1]
  00402330: A3 10 70 40 00     mov         dword ptr ds:[00407010h],eax
  00402335: 8B 55 F8           mov         edx,dword ptr [ebp-8]
  00402338: 8B 42 0C           mov         eax,dword ptr [edx+0Ch]
  0040233B: E9 0C 02 00 00     jmp         0040254C
  00402340: 8B 4D F8           mov         ecx,dword ptr [ebp-8]
  00402343: 83 79 04 01        cmp         dword ptr [ecx+4],1
  00402347: 0F 85 83 00 00 00  jne         004023D0
  0040234D: 40                 inc         eax
  0040234E: 3B 45 08           cmp         eax,dword ptr [ebp+8]
  00402351: 7D 15              jge         00402368
  00402353: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00402356: 8B 04 82           mov         eax,dword ptr [edx+eax*4]
  00402359: A3 E0 71 40 00     mov         dword ptr ds:[004071E0h],eax
  0040235E: FF 05 08 60 40 00  inc         dword ptr ds:[00406008h]
  00402364: EB 6A              jmp         004023D0
  00402366: 89 F6              mov         esi,esi
  00402368: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  0040236C: 74 1C              je          0040238A
  0040236E: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402371: FF 74 81 FC        push        dword ptr [ecx+eax*4-4]
  00402375: FF 31              push        dword ptr [ecx]
  00402377: 68 AC 1D 40 00     push        401DACh
  0040237C: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402381: 83 C0 40           add         eax,40h
  00402384: 50                 push        eax
  00402385: E8 6E 2E 00 00     call        004051F8
  0040238A: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  00402390: 89 D7              mov         edi,edx
  00402392: B0 00              mov         al,0
  00402394: FC                 cld
  00402395: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  0040239A: F2 AE              repne scas  byte ptr es:[edi]
  0040239C: F7 D1              not         ecx
  0040239E: 8D 44 0A FF        lea         eax,[edx+ecx-1]
  004023A2: A3 10 70 40 00     mov         dword ptr ds:[00407010h],eax
  004023A7: 8B 55 F8           mov         edx,dword ptr [ebp-8]
  004023AA: 8B 42 0C           mov         eax,dword ptr [edx+0Ch]
  004023AD: A3 10 60 40 00     mov         dword ptr ds:[00406010h],eax
  004023B2: B8 3F 00 00 00     mov         eax,3Fh
  004023B7: 8B 4D 10           mov         ecx,dword ptr [ebp+10h]
  004023BA: 80 39 3A           cmp         byte ptr [ecx],3Ah
  004023BD: 0F 85 0F 05 00 00  jne         004028D2
  004023C3: B8 3A 00 00 00     mov         eax,3Ah
  004023C8: E9 05 05 00 00     jmp         004028D2
  004023CD: 8D 76 00           lea         esi,[esi]
  004023D0: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  004023D6: 89 D7              mov         edi,edx
  004023D8: B0 00              mov         al,0
  004023DA: FC                 cld
  004023DB: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  004023E0: F2 AE              repne scas  byte ptr es:[edi]
  004023E2: F7 D1              not         ecx
  004023E4: 8D 44 0A FF        lea         eax,[edx+ecx-1]
  004023E8: A3 10 70 40 00     mov         dword ptr ds:[00407010h],eax
  004023ED: 83 7D 18 00        cmp         dword ptr [ebp+18h],0
  004023F1: 74 08              je          004023FB
  004023F3: 8B 4D EC           mov         ecx,dword ptr [ebp-14h]
  004023F6: 8B 55 18           mov         edx,dword ptr [ebp+18h]
  004023F9: 89 0A              mov         dword ptr [edx],ecx
  004023FB: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  004023FE: 8B 50 08           mov         edx,dword ptr [eax+8]
  00402401: 85 D2              test        edx,edx
  00402403: 0F 85 08 04 00 00  jne         00402811
  00402409: 8B 55 F8           mov         edx,dword ptr [ebp-8]
  0040240C: 8B 42 0C           mov         eax,dword ptr [edx+0Ch]
  0040240F: E9 BE 04 00 00     jmp         004028D2
  00402414: 83 7D 1C 00        cmp         dword ptr [ebp+1Ch],0
  00402418: 74 31              je          0040244B
  0040241A: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  0040241F: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402422: 8B 04 81           mov         eax,dword ptr [ecx+eax*4]
  00402425: 80 78 01 2D        cmp         byte ptr [eax+1],2Dh
  00402429: 74 20              je          0040244B
  0040242B: 83 C4 F8           add         esp,0FFFFFFF8h
  0040242E: A1 10 70 40 00     mov         eax,dword ptr ds:[00407010h]
  00402433: 0F BE 00           movsx       eax,byte ptr [eax]
  00402436: 50                 push        eax
  00402437: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  0040243A: 50                 push        eax
  0040243B: E8 2C F7 FF FF     call        00401B6C
  00402440: 83 C4 10           add         esp,10h
  00402443: 85 C0              test        eax,eax
  00402445: 0F 85 81 00 00 00  jne         004024CC
  0040244B: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  0040244F: 74 54              je          004024A5
  00402451: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402456: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00402459: 8B 04 82           mov         eax,dword ptr [edx+eax*4]
  0040245C: 80 78 01 2D        cmp         byte ptr [eax+1],2Dh
  00402460: 75 1E              jne         00402480
  00402462: FF 35 10 70 40 00  push        dword ptr ds:[00407010h]
  00402468: FF 32              push        dword ptr [edx]
  0040246A: 68 EC 1D 40 00     push        401DECh
  0040246F: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402474: 83 C0 40           add         eax,40h
  00402477: 50                 push        eax
  00402478: E8 7B 2D 00 00     call        004051F8
  0040247D: EB 26              jmp         004024A5
  0040247F: 90                 nop
  00402480: 83 C4 F4           add         esp,0FFFFFFF4h
  00402483: FF 35 10 70 40 00  push        dword ptr ds:[00407010h]
  00402489: 0F BE 00           movsx       eax,byte ptr [eax]
  0040248C: 50                 push        eax
  0040248D: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402490: FF 31              push        dword ptr [ecx]
  00402492: 68 0C 1E 40 00     push        401E0Ch
  00402497: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  0040249C: 83 C0 40           add         eax,40h
  0040249F: 50                 push        eax
  004024A0: E8 53 2D 00 00     call        004051F8
  004024A5: C7 05 10 70 40 00  mov         dword ptr ds:[00407010h],401E2Ch
            2C 1E 40 00
  004024AF: FF 05 08 60 40 00  inc         dword ptr ds:[00406008h]
  004024B5: C7 05 10 60 40 00  mov         dword ptr ds:[00406010h],0
            00 00 00 00
  004024BF: B8 3F 00 00 00     mov         eax,3Fh
  004024C4: E9 09 04 00 00     jmp         004028D2
  004024C9: 8D 76 00           lea         esi,[esi]
  004024CC: A1 10 70 40 00     mov         eax,dword ptr ds:[00407010h]
  004024D1: 8A 18              mov         bl,byte ptr [eax]
  004024D3: FF 05 10 70 40 00  inc         dword ptr ds:[00407010h]
  004024D9: 83 C4 F8           add         esp,0FFFFFFF8h
  004024DC: 0F BE F3           movsx       esi,bl
  004024DF: 56                 push        esi
  004024E0: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  004024E3: 50                 push        eax
  004024E4: E8 83 F6 FF FF     call        00401B6C
  004024E9: 8B 0D 10 70 40 00  mov         ecx,dword ptr ds:[00407010h]
  004024EF: 83 C4 10           add         esp,10h
  004024F2: 80 39 00           cmp         byte ptr [ecx],0
  004024F5: 75 06              jne         004024FD
  004024F7: FF 05 08 60 40 00  inc         dword ptr ds:[00406008h]
  004024FD: 85 C0              test        eax,eax
  004024FF: 74 05              je          00402506
  00402501: 80 FB 3A           cmp         bl,3Ah
  00402504: 75 56              jne         0040255C
  00402506: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  0040250A: 74 3D              je          00402549
  0040250C: 83 3D 30 70 40 00  cmp         dword ptr ds:[00407030h],0
            00
  00402513: 74 1B              je          00402530
  00402515: 56                 push        esi
  00402516: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00402519: FF 32              push        dword ptr [edx]
  0040251B: 68 2D 1E 40 00     push        401E2Dh
  00402520: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402525: 83 C0 40           add         eax,40h
  00402528: 50                 push        eax
  00402529: E8 CA 2C 00 00     call        004051F8
  0040252E: EB 19              jmp         00402549
  00402530: 56                 push        esi
  00402531: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402534: FF 31              push        dword ptr [ecx]
  00402536: 68 47 1E 40 00     push        401E47h
  0040253B: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402540: 83 C0 40           add         eax,40h
  00402543: 50                 push        eax
  00402544: E8 AF 2C 00 00     call        004051F8
  00402549: 0F BE C3           movsx       eax,bl
  0040254C: A3 10 60 40 00     mov         dword ptr ds:[00406010h],eax
  00402551: B8 3F 00 00 00     mov         eax,3Fh
  00402556: E9 77 03 00 00     jmp         004028D2
  0040255B: 90                 nop
  0040255C: 8A 50 01           mov         dl,byte ptr [eax+1]
  0040255F: 80 38 57           cmp         byte ptr [eax],57h
  00402562: 0F 85 D8 02 00 00  jne         00402840
  00402568: 80 FA 3B           cmp         dl,3Bh
  0040256B: 0F 85 CF 02 00 00  jne         00402840
  00402571: C7 45 E4 00 00 00  mov         dword ptr [ebp-1Ch],0
            00
  00402578: C7 45 E0 00 00 00  mov         dword ptr [ebp-20h],0
            00
  0040257F: C7 45 DC 00 00 00  mov         dword ptr [ebp-24h],0
            00
  00402586: C7 45 D8 00 00 00  mov         dword ptr [ebp-28h],0
            00
  0040258D: 80 39 00           cmp         byte ptr [ecx],0
  00402590: 74 0A              je          0040259C
  00402592: 89 0D E0 71 40 00  mov         dword ptr ds:[004071E0h],ecx
  00402598: EB 51              jmp         004025EB
  0040259A: 89 F6              mov         esi,esi
  0040259C: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  004025A1: 3B 45 08           cmp         eax,dword ptr [ebp+8]
  004025A4: 75 3A              jne         004025E0
  004025A6: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  004025AA: 74 19              je          004025C5
  004025AC: 56                 push        esi
  004025AD: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  004025B0: FF 30              push        dword ptr [eax]
  004025B2: 68 6C 1E 40 00     push        401E6Ch
  004025B7: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004025BC: 83 C0 40           add         eax,40h
  004025BF: 50                 push        eax
  004025C0: E8 33 2C 00 00     call        004051F8
  004025C5: 89 35 10 60 40 00  mov         dword ptr ds:[00406010h],esi
  004025CB: B3 3F              mov         bl,3Fh
  004025CD: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  004025D0: 80 3A 3A           cmp         byte ptr [edx],3Ah
  004025D3: 0F 85 F6 02 00 00  jne         004028CF
  004025D9: B3 3A              mov         bl,3Ah
  004025DB: E9 EF 02 00 00     jmp         004028CF
  004025E0: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  004025E3: 8B 04 81           mov         eax,dword ptr [ecx+eax*4]
  004025E6: A3 E0 71 40 00     mov         dword ptr ds:[004071E0h],eax
  004025EB: FF 05 08 60 40 00  inc         dword ptr ds:[00406008h]
  004025F1: 8B 35 E0 71 40 00  mov         esi,dword ptr ds:[004071E0h]
  004025F7: 89 35 10 70 40 00  mov         dword ptr ds:[00407010h],esi
  004025FD: EB 02              jmp         00402601
  004025FF: 90                 nop
  00402600: 46                 inc         esi
  00402601: 8A 06              mov         al,byte ptr [esi]
  00402603: 84 C0              test        al,al
  00402605: 74 04              je          0040260B
  00402607: 3C 3D              cmp         al,3Dh
  00402609: 75 F5              jne         00402600
  0040260B: 8B 5D 14           mov         ebx,dword ptr [ebp+14h]
  0040260E: C7 45 D4 00 00 00  mov         dword ptr [ebp-2Ch],0
            00
  00402615: EB 22              jmp         00402639
  00402617: 90                 nop
  00402618: 83 7D E4 00        cmp         dword ptr [ebp-1Ch],0
  0040261C: 75 0E              jne         0040262C
  0040261E: 89 5D E4           mov         dword ptr [ebp-1Ch],ebx
  00402621: 8B 45 D4           mov         eax,dword ptr [ebp-2Ch]
  00402624: 89 45 D8           mov         dword ptr [ebp-28h],eax
  00402627: EB 0A              jmp         00402633
  00402629: 8D 76 00           lea         esi,[esi]
  0040262C: C7 45 DC 01 00 00  mov         dword ptr [ebp-24h],1
            00
  00402633: 83 C3 10           add         ebx,10h
  00402636: FF 45 D4           inc         dword ptr [ebp-2Ch]
  00402639: 8B 0B              mov         ecx,dword ptr [ebx]
  0040263B: 85 C9              test        ecx,ecx
  0040263D: 74 49              je          00402688
  0040263F: 83 C4 FC           add         esp,0FFFFFFFCh
  00402642: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  00402648: 89 F0              mov         eax,esi
  0040264A: 29 D0              sub         eax,edx
  0040264C: 50                 push        eax
  0040264D: 52                 push        edx
  0040264E: 51                 push        ecx
  0040264F: E8 AC 2B 00 00     call        00405200
  00402654: 83 C4 10           add         esp,10h
  00402657: 85 C0              test        eax,eax
  00402659: 75 D8              jne         00402633
  0040265B: 89 F2              mov         edx,esi
  0040265D: 2B 15 10 70 40 00  sub         edx,dword ptr ds:[00407010h]
  00402663: 8B 3B              mov         edi,dword ptr [ebx]
  00402665: B0 00              mov         al,0
  00402667: FC                 cld
  00402668: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  0040266D: F2 AE              repne scas  byte ptr es:[edi]
  0040266F: F7 D1              not         ecx
  00402671: 8D 41 FF           lea         eax,[ecx-1]
  00402674: 39 C2              cmp         edx,eax
  00402676: 75 A0              jne         00402618
  00402678: 89 5D E4           mov         dword ptr [ebp-1Ch],ebx
  0040267B: 8B 55 D4           mov         edx,dword ptr [ebp-2Ch]
  0040267E: 89 55 D8           mov         dword ptr [ebp-28h],edx
  00402681: C7 45 E0 01 00 00  mov         dword ptr [ebp-20h],1
            00
  00402688: 83 7D DC 00        cmp         dword ptr [ebp-24h],0
  0040268C: 74 5A              je          004026E8
  0040268E: 83 7D E0 00        cmp         dword ptr [ebp-20h],0
  00402692: 75 54              jne         004026E8
  00402694: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  00402698: 74 20              je          004026BA
  0040269A: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  0040269F: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  004026A2: FF 34 81           push        dword ptr [ecx+eax*4]
  004026A5: FF 31              push        dword ptr [ecx]
  004026A7: 68 AC 1E 40 00     push        401EACh
  004026AC: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004026B1: 83 C0 40           add         eax,40h
  004026B4: 50                 push        eax
  004026B5: E8 3E 2B 00 00     call        004051F8
  004026BA: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  004026C0: 89 D7              mov         edi,edx
  004026C2: B0 00              mov         al,0
  004026C4: FC                 cld
  004026C5: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  004026CA: F2 AE              repne scas  byte ptr es:[edi]
  004026CC: F7 D1              not         ecx
  004026CE: 8D 44 0A FF        lea         eax,[edx+ecx-1]
  004026D2: A3 10 70 40 00     mov         dword ptr ds:[00407010h],eax
  004026D7: FF 05 08 60 40 00  inc         dword ptr ds:[00406008h]
  004026DD: B8 3F 00 00 00     mov         eax,3Fh
  004026E2: E9 EB 01 00 00     jmp         004028D2
  004026E7: 90                 nop
  004026E8: 83 7D E4 00        cmp         dword ptr [ebp-1Ch],0
  004026EC: 0F 84 3A 01 00 00  je          0040282C
  004026F2: 80 3E 00           cmp         byte ptr [esi],0
  004026F5: 74 61              je          00402758
  004026F7: 8B 55 E4           mov         edx,dword ptr [ebp-1Ch]
  004026FA: 83 7A 04 00        cmp         dword ptr [edx+4],0
  004026FE: 74 0C              je          0040270C
  00402700: 46                 inc         esi
  00402701: 89 35 E0 71 40 00  mov         dword ptr ds:[004071E0h],esi
  00402707: E9 D0 00 00 00     jmp         004027DC
  0040270C: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  00402710: 74 1D              je          0040272F
  00402712: 8B 4D E4           mov         ecx,dword ptr [ebp-1Ch]
  00402715: FF 31              push        dword ptr [ecx]
  00402717: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  0040271A: FF 30              push        dword ptr [eax]
  0040271C: 68 EC 1E 40 00     push        401EECh
  00402721: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402726: 83 C0 40           add         eax,40h
  00402729: 50                 push        eax
  0040272A: E8 C9 2A 00 00     call        004051F8
  0040272F: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  00402735: 89 D7              mov         edi,edx
  00402737: B0 00              mov         al,0
  00402739: FC                 cld
  0040273A: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  0040273F: F2 AE              repne scas  byte ptr es:[edi]
  00402741: F7 D1              not         ecx
  00402743: 8D 44 0A FF        lea         eax,[edx+ecx-1]
  00402747: A3 10 70 40 00     mov         dword ptr ds:[00407010h],eax
  0040274C: B8 3F 00 00 00     mov         eax,3Fh
  00402751: E9 7C 01 00 00     jmp         004028D2
  00402756: 89 F6              mov         esi,esi
  00402758: 8B 55 E4           mov         edx,dword ptr [ebp-1Ch]
  0040275B: 83 7A 04 01        cmp         dword ptr [edx+4],1
  0040275F: 75 7B              jne         004027DC
  00402761: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402766: 3B 45 08           cmp         eax,dword ptr [ebp+8]
  00402769: 7D 15              jge         00402780
  0040276B: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  0040276E: 8B 04 81           mov         eax,dword ptr [ecx+eax*4]
  00402771: A3 E0 71 40 00     mov         dword ptr ds:[004071E0h],eax
  00402776: FF 05 08 60 40 00  inc         dword ptr ds:[00406008h]
  0040277C: EB 5E              jmp         004027DC
  0040277E: 89 F6              mov         esi,esi
  00402780: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  00402784: 74 1C              je          004027A2
  00402786: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00402789: FF 74 82 FC        push        dword ptr [edx+eax*4-4]
  0040278D: FF 32              push        dword ptr [edx]
  0040278F: 68 AC 1D 40 00     push        401DACh
  00402794: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402799: 83 C0 40           add         eax,40h
  0040279C: 50                 push        eax
  0040279D: E8 56 2A 00 00     call        004051F8
  004027A2: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  004027A8: 89 D7              mov         edi,edx
  004027AA: B0 00              mov         al,0
  004027AC: FC                 cld
  004027AD: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  004027B2: F2 AE              repne scas  byte ptr es:[edi]
  004027B4: F7 D1              not         ecx
  004027B6: 8D 44 0A FF        lea         eax,[edx+ecx-1]
  004027BA: A3 10 70 40 00     mov         dword ptr ds:[00407010h],eax
  004027BF: B8 3F 00 00 00     mov         eax,3Fh
  004027C4: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  004027C7: 80 3A 3A           cmp         byte ptr [edx],3Ah
  004027CA: 0F 85 02 01 00 00  jne         004028D2
  004027D0: B8 3A 00 00 00     mov         eax,3Ah
  004027D5: E9 F8 00 00 00     jmp         004028D2
  004027DA: 89 F6              mov         esi,esi
  004027DC: 8B 15 10 70 40 00  mov         edx,dword ptr ds:[00407010h]
  004027E2: 89 D7              mov         edi,edx
  004027E4: B0 00              mov         al,0
  004027E6: FC                 cld
  004027E7: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  004027EC: F2 AE              repne scas  byte ptr es:[edi]
  004027EE: F7 D1              not         ecx
  004027F0: 8D 44 0A FF        lea         eax,[edx+ecx-1]
  004027F4: A3 10 70 40 00     mov         dword ptr ds:[00407010h],eax
  004027F9: 83 7D 18 00        cmp         dword ptr [ebp+18h],0
  004027FD: 74 08              je          00402807
  004027FF: 8B 4D D8           mov         ecx,dword ptr [ebp-28h]
  00402802: 8B 55 18           mov         edx,dword ptr [ebp+18h]
  00402805: 89 0A              mov         dword ptr [edx],ecx
  00402807: 8B 45 E4           mov         eax,dword ptr [ebp-1Ch]
  0040280A: 8B 50 08           mov         edx,dword ptr [eax+8]
  0040280D: 85 D2              test        edx,edx
  0040280F: 74 0F              je          00402820
  00402811: 8B 40 0C           mov         eax,dword ptr [eax+0Ch]
  00402814: 89 02              mov         dword ptr [edx],eax
  00402816: 31 C0              xor         eax,eax
  00402818: E9 B5 00 00 00     jmp         004028D2
  0040281D: 8D 76 00           lea         esi,[esi]
  00402820: 8B 55 E4           mov         edx,dword ptr [ebp-1Ch]
  00402823: 8B 42 0C           mov         eax,dword ptr [edx+0Ch]
  00402826: E9 A7 00 00 00     jmp         004028D2
  0040282B: 90                 nop
  0040282C: C7 05 10 70 40 00  mov         dword ptr ds:[00407010h],0
            00 00 00 00
  00402836: B8 57 00 00 00     mov         eax,57h
  0040283B: E9 92 00 00 00     jmp         004028D2
  00402840: 80 FA 3A           cmp         dl,3Ah
  00402843: 0F 85 86 00 00 00  jne         004028CF
  00402849: 80 78 02 3A        cmp         byte ptr [eax+2],3Ah
  0040284D: 75 19              jne         00402868
  0040284F: A1 10 70 40 00     mov         eax,dword ptr ds:[00407010h]
  00402854: 80 38 00           cmp         byte ptr [eax],0
  00402857: 75 61              jne         004028BA
  00402859: C7 05 E0 71 40 00  mov         dword ptr ds:[004071E0h],0
            00 00 00 00
  00402863: EB 60              jmp         004028C5
  00402865: 8D 76 00           lea         esi,[esi]
  00402868: A1 10 70 40 00     mov         eax,dword ptr ds:[00407010h]
  0040286D: 80 38 00           cmp         byte ptr [eax],0
  00402870: 75 48              jne         004028BA
  00402872: A1 08 60 40 00     mov         eax,dword ptr ds:[00406008h]
  00402877: 3B 45 08           cmp         eax,dword ptr [ebp+8]
  0040287A: 75 38              jne         004028B4
  0040287C: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  00402880: 74 1C              je          0040289E
  00402882: 0F BE C3           movsx       eax,bl
  00402885: 50                 push        eax
  00402886: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402889: FF 31              push        dword ptr [ecx]
  0040288B: 68 6C 1E 40 00     push        401E6Ch
  00402890: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402895: 83 C0 40           add         eax,40h
  00402898: 50                 push        eax
  00402899: E8 5A 29 00 00     call        004051F8
  0040289E: 0F BE C3           movsx       eax,bl
  004028A1: A3 10 60 40 00     mov         dword ptr ds:[00406010h],eax
  004028A6: B3 3F              mov         bl,3Fh
  004028A8: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  004028AB: 80 38 3A           cmp         byte ptr [eax],3Ah
  004028AE: 75 15              jne         004028C5
  004028B0: B3 3A              mov         bl,3Ah
  004028B2: EB 11              jmp         004028C5
  004028B4: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  004028B7: 8B 04 82           mov         eax,dword ptr [edx+eax*4]
  004028BA: A3 E0 71 40 00     mov         dword ptr ds:[004071E0h],eax
  004028BF: FF 05 08 60 40 00  inc         dword ptr ds:[00406008h]
  004028C5: C7 05 10 70 40 00  mov         dword ptr ds:[00407010h],0
            00 00 00 00
  004028CF: 0F BE C3           movsx       eax,bl
  004028D2: 8D 65 B8           lea         esp,[ebp-48h]
  004028D5: 5B                 pop         ebx
  004028D6: 5E                 pop         esi
  004028D7: 5F                 pop         edi
  004028D8: C9                 leave
  004028D9: C3                 ret
  004028DA: 89 F6              mov         esi,esi
  004028DC: 55                 push        ebp
  004028DD: 89 E5              mov         ebp,esp
  004028DF: 83 EC 08           sub         esp,8
  004028E2: 83 C4 F8           add         esp,0FFFFFFF8h
  004028E5: 6A 00              push        0
  004028E7: 6A 00              push        0
  004028E9: 6A 00              push        0
  004028EB: FF 75 10           push        dword ptr [ebp+10h]
  004028EE: FF 75 0C           push        dword ptr [ebp+0Ch]
  004028F1: FF 75 08           push        dword ptr [ebp+8]
  004028F4: E8 23 F6 FF FF     call        00401F1C
  004028F9: C9                 leave
  004028FA: C3                 ret
  004028FB: 90                 nop
  004028FC: 90                 nop
  004028FD: 90                 nop
  004028FE: 90                 nop
  004028FF: 90                 nop
  00402900: 90                 nop
  00402901: 90                 nop
  00402902: 90                 nop
  00402903: 90                 nop
  00402904: 90                 nop
  00402905: 90                 nop
  00402906: 90                 nop
  00402907: 90                 nop
  00402908: 90                 nop
  00402909: 90                 nop
  0040290A: 90                 nop
  0040290B: 90                 nop
  0040290C: 43                 inc         ebx
  0040290D: 6F                 outs        dx,dword ptr [esi]
  0040290E: 70 79              jo          00402989
  00402910: 72 69              jb          0040297B
  00402912: 67 68 74 20 28 43  push        43282074h
  00402918: 29 20              sub         dword ptr [eax],esp
  0040291A: 32 30              xor         dh,byte ptr [eax]
  0040291C: 30 32              xor         byte ptr [edx],dh
  0040291E: 20 46 72           and         byte ptr [esi+72h],al
  00402921: 65
  00402922: 65 20 53 6F        and         byte ptr gs:[ebx+6Fh],dl
  00402926: 66 74 77           je          000029A0
  00402929: 61                 popad
  0040292A: 72 65              jb          00402991
  0040292C: 20 46 6F           and         byte ptr [esi+6Fh],al
  0040292F: 75 6E              jne         0040299F
  00402931: 64 61              popad
  00402933: 74 69              je          0040299E
  00402935: 6F                 outs        dx,dword ptr [esi]
  00402936: 6E                 outs        dx,byte ptr [esi]
  00402937: 2C 20              sub         al,20h
  00402939: 49                 dec         ecx
  0040293A: 6E                 outs        dx,byte ptr [esi]
  0040293B: 63 2E              arpl        word ptr [esi],bp
  0040293D: 00 25 73 20 28 25  add         byte ptr ds:[25282073h],ah
  00402943: 73 29              jae         0040296E
  00402945: 20 25 73 0A 00 25  and         byte ptr ds:[25000A73h],ah
  0040294B: 73 20              jae         0040296D
  0040294D: 25 73 0A 00 57     and         eax,57000A73h
  00402952: 72 69              jb          004029BD
  00402954: 74 74              je          004029CA
  00402956: 65 6E              outs        dx,byte ptr gs:[esi]
  00402958: 20 62 79           and         byte ptr [edx+79h],ah
  0040295B: 20 25 73 2E 0A 00  and         byte ptr ds:[000A2E73h],ah
  00402961: 8D 74 26 00        lea         esi,[esi]
  00402965: 8D BC 27 00 00 00  lea         edi,[edi+00000000h]
            00
  0040296C: 54                 push        esp
  0040296D: 68 69 73 20 69     push        69207369h
  00402972: 73 20              jae         00402994
  00402974: 66 72 65           jb          000029DC
  00402977: 65 20 73 6F        and         byte ptr gs:[ebx+6Fh],dh
  0040297B: 66 74 77           je          000029F5
  0040297E: 61                 popad
  0040297F: 72 65              jb          004029E6
  00402981: 3B 20              cmp         esp,dword ptr [eax]
  00402983: 73 65              jae         004029EA
  00402985: 65 20 74 68 65     and         byte ptr gs:[eax+ebp*2+65h],dh
  0040298A: 20 73 6F           and         byte ptr [ebx+6Fh],dh
  0040298D: 75 72              jne         00402A01
  0040298F: 63 65 20           arpl        word ptr [ebp+20h],sp
  00402992: 66 6F              outs        dx,word ptr [esi]
  00402994: 72 20              jb          004029B6
  00402996: 63 6F 70           arpl        word ptr [edi+70h],bp
  00402999: 79 69              jns         00402A04
  0040299B: 6E                 outs        dx,byte ptr [esi]
  0040299C: 67 20 63 6F        and         byte ptr [bp+di+6Fh],ah
  004029A0: 6E                 outs        dx,byte ptr [esi]
  004029A1: 64 69 74 69 6F 6E  imul        esi,dword ptr fs:[ecx+ebp*2+6Fh],202E736Eh
            73 2E 20
  004029AA: 20 54 68 65        and         byte ptr [eax+ebp*2+65h],dl
  004029AE: 72 65              jb          00402A15
  004029B0: 20 69 73           and         byte ptr [ecx+73h],ch
  004029B3: 20 4E 4F           and         byte ptr [esi+4Fh],cl
  004029B6: 0A 77 61           or          dh,byte ptr [edi+61h]
  004029B9: 72 72              jb          00402A2D
  004029BB: 61                 popad
  004029BC: 6E                 outs        dx,byte ptr [esi]
  004029BD: 74 79              je          00402A38
  004029BF: 3B 20              cmp         esp,dword ptr [eax]
  004029C1: 6E                 outs        dx,byte ptr [esi]
  004029C2: 6F                 outs        dx,dword ptr [esi]
  004029C3: 74 20              je          004029E5
  004029C5: 65 76 65           jbe         00402A2D
  004029C8: 6E                 outs        dx,byte ptr [esi]
  004029C9: 20 66 6F           and         byte ptr [esi+6Fh],ah
  004029CC: 72 20              jb          004029EE
  004029CE: 4D                 dec         ebp
  004029CF: 45                 inc         ebp
  004029D0: 52                 push        edx
  004029D1: 43                 inc         ebx
  004029D2: 48                 dec         eax
  004029D3: 41                 inc         ecx
  004029D4: 4E                 dec         esi
  004029D5: 54                 push        esp
  004029D6: 41                 inc         ecx
  004029D7: 42                 inc         edx
  004029D8: 49                 dec         ecx
  004029D9: 4C                 dec         esp
  004029DA: 49                 dec         ecx
  004029DB: 54                 push        esp
  004029DC: 59                 pop         ecx
  004029DD: 20 6F 72           and         byte ptr [edi+72h],ch
  004029E0: 20 46 49           and         byte ptr [esi+49h],al
  004029E3: 54                 push        esp
  004029E4: 4E                 dec         esi
  004029E5: 45                 inc         ebp
  004029E6: 53                 push        ebx
  004029E7: 53                 push        ebx
  004029E8: 20 46 4F           and         byte ptr [esi+4Fh],al
  004029EB: 52                 push        edx
  004029EC: 20 41 20           and         byte ptr [ecx+20h],al
  004029EF: 50                 push        eax
  004029F0: 41                 inc         ecx
  004029F1: 52                 push        edx
  004029F2: 54                 push        esp
  004029F3: 49                 dec         ecx
  004029F4: 43                 inc         ebx
  004029F5: 55                 push        ebp
  004029F6: 4C                 dec         esp
  004029F7: 41                 inc         ecx
  004029F8: 52                 push        edx
  004029F9: 20 50 55           and         byte ptr [eax+55h],dl
  004029FC: 52                 push        edx
  004029FD: 50                 push        eax
  004029FE: 4F                 dec         edi
  004029FF: 53                 push        ebx
  00402A00: 45                 inc         ebp
  00402A01: 2E 0A 00           or          al,byte ptr cs:[eax]
  00402A04: 55                 push        ebp
  00402A05: 89 E5              mov         ebp,esp
  00402A07: 83 EC 14           sub         esp,14h
  00402A0A: 53                 push        ebx
  00402A0B: 8B 5D 08           mov         ebx,dword ptr [ebp+8]
  00402A0E: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00402A11: 8B 4D 10           mov         ecx,dword ptr [ebp+10h]
  00402A14: 8B 45 14           mov         eax,dword ptr [ebp+14h]
  00402A17: 85 D2              test        edx,edx
  00402A19: 74 19              je          00402A34
  00402A1B: 83 C4 F4           add         esp,0FFFFFFF4h
  00402A1E: 50                 push        eax
  00402A1F: 51                 push        ecx
  00402A20: 52                 push        edx
  00402A21: 68 3E 29 40 00     push        40293Eh
  00402A26: 53                 push        ebx
  00402A27: E8 CC 27 00 00     call        004051F8
  00402A2C: 83 C4 20           add         esp,20h
  00402A2F: EB 13              jmp         00402A44
  00402A31: 8D 76 00           lea         esi,[esi]
  00402A34: 50                 push        eax
  00402A35: 51                 push        ecx
  00402A36: 68 4A 29 40 00     push        40294Ah
  00402A3B: 53                 push        ebx
  00402A3C: E8 B7 27 00 00     call        004051F8
  00402A41: 83 C4 10           add         esp,10h
  00402A44: 83 C4 FC           add         esp,0FFFFFFFCh
  00402A47: FF 75 18           push        dword ptr [ebp+18h]
  00402A4A: 68 51 29 40 00     push        402951h
  00402A4F: 53                 push        ebx
  00402A50: E8 A3 27 00 00     call        004051F8
  00402A55: 83 C4 F8           add         esp,0FFFFFFF8h
  00402A58: 53                 push        ebx
  00402A59: 6A 0A              push        0Ah
  00402A5B: E8 B0 27 00 00     call        00405210
  00402A60: 83 C4 20           add         esp,20h
  00402A63: 83 C4 F8           add         esp,0FFFFFFF8h
  00402A66: 53                 push        ebx
  00402A67: FF 35 14 60 40 00  push        dword ptr ds:[00406014h]
  00402A6D: E8 76 27 00 00     call        004051E8
  00402A72: 83 C4 F8           add         esp,0FFFFFFF8h
  00402A75: 53                 push        ebx
  00402A76: 6A 0A              push        0Ah
  00402A78: E8 93 27 00 00     call        00405210
  00402A7D: 83 C4 20           add         esp,20h
  00402A80: 83 C4 F8           add         esp,0FFFFFFF8h
  00402A83: 53                 push        ebx
  00402A84: 68 6C 29 40 00     push        40296Ch
  00402A89: E8 5A 27 00 00     call        004051E8
  00402A8E: 8B 5D E8           mov         ebx,dword ptr [ebp-18h]
  00402A91: C9                 leave
  00402A92: C3                 ret
  00402A93: 90                 nop
  00402A94: 90                 nop
  00402A95: 90                 nop
  00402A96: 90                 nop
  00402A97: 90                 nop
  00402A98: 90                 nop
  00402A99: 90                 nop
  00402A9A: 90                 nop
  00402A9B: 90                 nop
  00402A9C: 90                 nop
  00402A9D: 90                 nop
  00402A9E: 90                 nop
  00402A9F: 90                 nop
  00402AA0: 90                 nop
  00402AA1: 90                 nop
  00402AA2: 90                 nop
  00402AA3: 90                 nop
  00402AA4: 90                 nop
  00402AA5: 90                 nop
  00402AA6: 90                 nop
  00402AA7: 90                 nop
  00402AA8: 90                 nop
  00402AA9: 90                 nop
  00402AAA: 90                 nop
  00402AAB: 90                 nop
  00402AAC: 55                 push        ebp
  00402AAD: 89 E5              mov         ebp,esp
  00402AAF: 83 EC 08           sub         esp,8
  00402AB2: 83 C4 F8           add         esp,0FFFFFFF8h
  00402AB5: 6A 00              push        0
  00402AB7: FF 75 18           push        dword ptr [ebp+18h]
  00402ABA: FF 75 14           push        dword ptr [ebp+14h]
  00402ABD: FF 75 10           push        dword ptr [ebp+10h]
  00402AC0: FF 75 0C           push        dword ptr [ebp+0Ch]
  00402AC3: FF 75 08           push        dword ptr [ebp+8]
  00402AC6: E8 51 F4 FF FF     call        00401F1C
  00402ACB: C9                 leave
  00402ACC: C3                 ret
  00402ACD: 8D 76 00           lea         esi,[esi]
  00402AD0: 55                 push        ebp
  00402AD1: 89 E5              mov         ebp,esp
  00402AD3: 83 EC 08           sub         esp,8
  00402AD6: 83 C4 F8           add         esp,0FFFFFFF8h
  00402AD9: 6A 01              push        1
  00402ADB: FF 75 18           push        dword ptr [ebp+18h]
  00402ADE: FF 75 14           push        dword ptr [ebp+14h]
  00402AE1: FF 75 10           push        dword ptr [ebp+10h]
  00402AE4: FF 75 0C           push        dword ptr [ebp+0Ch]
  00402AE7: FF 75 08           push        dword ptr [ebp+8]
  00402AEA: E8 2D F4 FF FF     call        00401F1C
  00402AEF: C9                 leave
  00402AF0: C3                 ret
  00402AF1: 8D 76 00           lea         esi,[esi]
  00402AF4: 55                 push        ebp
  00402AF5: 89 E5              mov         ebp,esp
  00402AF7: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00402AFA: A3 18 60 40 00     mov         dword ptr ds:[00406018h],eax
  00402AFF: C9                 leave
  00402B00: C3                 ret
  00402B01: 8D 76 00           lea         esi,[esi]
  00402B04: 55                 push        ebp
  00402B05: 89 E5              mov         ebp,esp
  00402B07: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00402B0A: A3 60 70 40 00     mov         dword ptr ds:[00407060h],eax
  00402B0F: C9                 leave
  00402B10: C3                 ret
  00402B11: 77 72              ja          00402B85
  00402B13: 69 74 65 20 65 72  imul        esi,dword ptr [ebp+20h],6F727265h
            72 6F
  00402B1B: 72 00              jb          00402B1D
  00402B1D: 25 73 3A 20 25     and         eax,25203A73h
  00402B22: 73 00              jae         00402B24
  00402B24: 25 73 00 90 55     and         eax,55900073h
  00402B29: 89 E5              mov         ebp,esp
  00402B2B: 83 EC 10           sub         esp,10h
  00402B2E: 56                 push        esi
  00402B2F: 53                 push        ebx
  00402B30: 8B 75 08           mov         esi,dword ptr [ebp+8]
  00402B33: 83 C4 F4           add         esp,0FFFFFFF4h
  00402B36: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402B3B: 83 C0 20           add         eax,20h
  00402B3E: 50                 push        eax
  00402B3F: E8 7C 26 00 00     call        004051C0
  00402B44: 83 C4 10           add         esp,10h
  00402B47: 31 DB              xor         ebx,ebx
  00402B49: 85 C0              test        eax,eax
  00402B4B: 75 05              jne         00402B52
  00402B4D: BB FF FF FF FF     mov         ebx,0FFFFFFFFh
  00402B52: 83 C4 F4           add         esp,0FFFFFFF4h
  00402B55: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00402B5A: 83 C0 20           add         eax,20h
  00402B5D: 50                 push        eax
  00402B5E: E8 55 26 00 00     call        004051B8
  00402B63: 83 C4 10           add         esp,10h
  00402B66: 85 C0              test        eax,eax
  00402B68: 74 07              je          00402B71
  00402B6A: E8 61 26 00 00     call        004051D0
  00402B6F: 8B 18              mov         ebx,dword ptr [eax]
  00402B71: 85 DB              test        ebx,ebx
  00402B73: 7C 3C              jl          00402BB1
  00402B75: BA 11 2B 40 00     mov         edx,402B11h
  00402B7A: A1 60 70 40 00     mov         eax,dword ptr ds:[00407060h]
  00402B7F: 85 C0              test        eax,eax
  00402B81: 74 21              je          00402BA4
  00402B83: 83 C4 F4           add         esp,0FFFFFFF4h
  00402B86: 52                 push        edx
  00402B87: 83 C4 F4           add         esp,0FFFFFFF4h
  00402B8A: 50                 push        eax
  00402B8B: E8 D4 16 00 00     call        00404264
  00402B90: 83 C4 10           add         esp,10h
  00402B93: 50                 push        eax
  00402B94: 68 1D 2B 40 00     push        402B1Dh
  00402B99: 53                 push        ebx
  00402B9A: 56                 push        esi
  00402B9B: E8 48 0A 00 00     call        004035E8
  00402BA0: EB 0F              jmp         00402BB1
  00402BA2: 89 F6              mov         esi,esi
  00402BA4: 52                 push        edx
  00402BA5: 68 24 2B 40 00     push        402B24h
  00402BAA: 53                 push        ebx
  00402BAB: 56                 push        esi
  00402BAC: E8 37 0A 00 00     call        004035E8
  00402BB1: 8D 65 E8           lea         esp,[ebp-18h]
  00402BB4: 5B                 pop         ebx
  00402BB5: 5E                 pop         esi
  00402BB6: C9                 leave
  00402BB7: C3                 ret
  00402BB8: 55                 push        ebp
  00402BB9: 89 E5              mov         ebp,esp
  00402BBB: 83 EC 08           sub         esp,8
  00402BBE: 83 C4 F4           add         esp,0FFFFFFF4h
  00402BC1: FF 35 18 60 40 00  push        dword ptr ds:[00406018h]
  00402BC7: E8 5C FF FF FF     call        00402B28
  00402BCC: C9                 leave
  00402BCD: C3                 ret
  00402BCE: 89 F6              mov         esi,esi
  00402BD0: 55                 push        ebp
  00402BD1: 89 E5              mov         ebp,esp
  00402BD3: 83 EC 0C           sub         esp,0Ch
  00402BD6: 57                 push        edi
  00402BD7: 56                 push        esi
  00402BD8: 53                 push        ebx
  00402BD9: 8B 7D 0C           mov         edi,dword ptr [ebp+0Ch]
  00402BDC: 8B 75 10           mov         esi,dword ptr [ebp+10h]
  00402BDF: 85 F6              test        esi,esi
  00402BE1: 75 05              jne         00402BE8
  00402BE3: 31 C0              xor         eax,eax
  00402BE5: EB 24              jmp         00402C0B
  00402BE7: 90                 nop
  00402BE8: 83 C4 FC           add         esp,0FFFFFFFCh
  00402BEB: 56                 push        esi
  00402BEC: 57                 push        edi
  00402BED: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00402BF0: 50                 push        eax
  00402BF1: E8 16 25 00 00     call        0040510C
  00402BF6: 89 C3              mov         ebx,eax
  00402BF8: 83 C4 10           add         esp,10h
  00402BFB: 85 DB              test        ebx,ebx
  00402BFD: 7D 0A              jge         00402C09
  00402BFF: E8 CC 25 00 00     call        004051D0
  00402C04: 83 38 04           cmp         dword ptr [eax],4
  00402C07: 74 DF              je          00402BE8
  00402C09: 89 D8              mov         eax,ebx
  00402C0B: 8D 65 E8           lea         esp,[ebp-18h]
  00402C0E: 5B                 pop         ebx
  00402C0F: 5E                 pop         esi
  00402C10: 5F                 pop         edi
  00402C11: C9                 leave
  00402C12: C3                 ret
  00402C13: 90                 nop
  00402C14: 00 4B 4D           add         byte ptr [ebx+4Dh],cl
  00402C17: 47                 inc         edi
  00402C18: 54                 push        esp
  00402C19: 50                 push        eax
  00402C1A: 45                 inc         ebp
  00402C1B: 5A                 pop         edx
  00402C1C: 59                 pop         ecx
  00402C1D: 8D 76 00           lea         esi,[esi]
  00402C20: 55                 push        ebp
  00402C21: 89 E5              mov         ebp,esp
  00402C23: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00402C26: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00402C29: 8A 91 14 2C 40 00  mov         dl,byte ptr [ecx+00402C14h]
  00402C2F: 81 7D 10 E8 03 00  cmp         dword ptr [ebp+10h],3E8h
            00
  00402C36: 75 0B              jne         00402C43
  00402C38: 48                 dec         eax
  00402C39: C6 00 42           mov         byte ptr [eax],42h
  00402C3C: 83 F9 01           cmp         ecx,1
  00402C3F: 75 02              jne         00402C43
  00402C41: B2 6B              mov         dl,6Bh
  00402C43: 48                 dec         eax
  00402C44: 88 10              mov         byte ptr [eax],dl
  00402C46: C9                 leave
  00402C47: C3                 ret
  00402C48: 8D 74 26 00        lea         esi,[esi]
  00402C4C: 00 00              add         byte ptr [eax],al
  00402C4E: 00 00              add         byte ptr [eax],al
  00402C50: 00 00              add         byte ptr [eax],al
  00402C52: F0 43              lock inc    ebx
  00402C54: 00 00              add         byte ptr [eax],al
  00402C56: 00 00              add         byte ptr [eax],al
  00402C58: 00 00              add         byte ptr [eax],al
  00402C5A: 00 80 3F 40 00 00  add         byte ptr [eax+0000403Fh],al
  00402C60: 55                 push        ebp
  00402C61: 89 E5              mov         ebp,esp
  00402C63: 83 EC 4C           sub         esp,4Ch
  00402C66: 57                 push        edi
  00402C67: 56                 push        esi
  00402C68: 53                 push        ebx
  00402C69: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00402C6C: DD 45 0C           fld         qword ptr [ebp+0Ch]
  00402C6F: DD 55 E8           fst         qword ptr [ebp-18h]
  00402C72: 85 FF              test        edi,edi
  00402C74: 0F 84 CB 00 00 00  je          00402D45
  00402C7A: DC 15 4C 2C 40 00  fcom        qword ptr ds:[00402C4Ch]
  00402C80: DF E0              fnstsw      ax
  00402C82: 80 E4 45           and         ah,45h
  00402C85: 80 FC 01           cmp         ah,1
  00402C88: 0F 85 B7 00 00 00  jne         00402D45
  00402C8E: 83 C4 F8           add         esp,0FFFFFFF8h
  00402C91: 83 EC 08           sub         esp,8
  00402C94: DD 1C 24           fstp        qword ptr [esp]
  00402C97: E8 B4 1E 00 00     call        00404B50
  00402C9C: 83 C4 10           add         esp,10h
  00402C9F: 89 C3              mov         ebx,eax
  00402CA1: 89 D6              mov         esi,edx
  00402CA3: C7 45 E0 00 00 00  mov         dword ptr [ebp-20h],0
            00
  00402CAA: C7 45 E4 00 00 00  mov         dword ptr [ebp-1Ch],0
            00
  00402CB1: 83 FF 01           cmp         edi,1
  00402CB4: 75 53              jne         00402D09
  00402CB6: 89 5D F8           mov         dword ptr [ebp-8],ebx
  00402CB9: 89 75 FC           mov         dword ptr [ebp-4],esi
  00402CBC: DF 6D F8           fild        qword ptr [ebp-8]
  00402CBF: DB 7D D0           fstp        tbyte ptr [ebp-30h]
  00402CC2: 6A 00              push        0
  00402CC4: 6A 00              push        0
  00402CC6: 56                 push        esi
  00402CC7: 53                 push        ebx
  00402CC8: E8 77 1F 00 00     call        00404C44
  00402CCD: 83 C4 10           add         esp,10h
  00402CD0: 83 F8 01           cmp         eax,1
  00402CD3: 7D 0E              jge         00402CE3
  00402CD5: DB 2D 54 2C 40 00  fld         tbyte ptr ds:[00402C54h]
  00402CDB: DB 6D D0           fld         tbyte ptr [ebp-30h]
  00402CDE: DE C1              faddp       st(1),st
  00402CE0: DB 7D D0           fstp        tbyte ptr [ebp-30h]
  00402CE3: DB 6D D0           fld         tbyte ptr [ebp-30h]
  00402CE6: DD 5D F0           fstp        qword ptr [ebp-10h]
  00402CE9: DD 45 F0           fld         qword ptr [ebp-10h]
  00402CEC: DD 45 E8           fld         qword ptr [ebp-18h]
  00402CEF: DA E9              fucompp
  00402CF1: DF E0              fnstsw      ax
  00402CF3: 80 E4 45           and         ah,45h
  00402CF6: 80 FC 40           cmp         ah,40h
  00402CF9: 74 0E              je          00402D09
  00402CFB: C7 45 E0 01 00 00  mov         dword ptr [ebp-20h],1
            00
  00402D02: C7 45 E4 00 00 00  mov         dword ptr [ebp-1Ch],0
            00
  00402D09: 89 D8              mov         eax,ebx
  00402D0B: 89 F2              mov         edx,esi
  00402D0D: 03 45 E0           add         eax,dword ptr [ebp-20h]
  00402D10: 13 55 E4           adc         edx,dword ptr [ebp-1Ch]
  00402D13: 89 45 F8           mov         dword ptr [ebp-8],eax
  00402D16: 89 55 FC           mov         dword ptr [ebp-4],edx
  00402D19: DF 6D F8           fild        qword ptr [ebp-8]
  00402D1C: DB 7D C0           fstp        tbyte ptr [ebp-40h]
  00402D1F: 6A 00              push        0
  00402D21: 6A 00              push        0
  00402D23: 52                 push        edx
  00402D24: 50                 push        eax
  00402D25: E8 1A 1F 00 00     call        00404C44
  00402D2A: 83 F8 01           cmp         eax,1
  00402D2D: 7D 0E              jge         00402D3D
  00402D2F: DB 2D 54 2C 40 00  fld         tbyte ptr ds:[00402C54h]
  00402D35: DB 6D C0           fld         tbyte ptr [ebp-40h]
  00402D38: DE C1              faddp       st(1),st
  00402D3A: DB 7D C0           fstp        tbyte ptr [ebp-40h]
  00402D3D: DB 6D C0           fld         tbyte ptr [ebp-40h]
  00402D40: DD 5D E8           fstp        qword ptr [ebp-18h]
  00402D43: EB 02              jmp         00402D47
  00402D45: DD D8              fstp        st(0)
  00402D47: DD 45 E8           fld         qword ptr [ebp-18h]
  00402D4A: 8D 65 A8           lea         esp,[ebp-58h]
  00402D4D: 5B                 pop         ebx
  00402D4E: 5E                 pop         esi
  00402D4F: 5F                 pop         edi
  00402D50: C9                 leave
  00402D51: C3                 ret
  00402D52: 89 F6              mov         esi,esi
  00402D54: 55                 push        ebp
  00402D55: 89 E5              mov         ebp,esp
  00402D57: 83 EC 08           sub         esp,8
  00402D5A: 83 C4 F8           add         esp,0FFFFFFF8h
  00402D5D: 6A 00              push        0
  00402D5F: FF 75 18           push        dword ptr [ebp+18h]
  00402D62: FF 75 14           push        dword ptr [ebp+14h]
  00402D65: FF 75 10           push        dword ptr [ebp+10h]
  00402D68: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00402D6B: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00402D6E: 52                 push        edx
  00402D6F: 50                 push        eax
  00402D70: E8 37 00 00 00     call        00402DAC
  00402D75: C9                 leave
  00402D76: C3                 ret
  00402D77: 25 2E 30 66 00     and         eax,66302Eh
  00402D7C: 25 2E 31 66 25     and         eax,2566312Eh
  00402D81: 73 00              jae         00402D83
  00402D83: 25 2E 30 66 25     and         eax,2566302Eh
  00402D88: 73 00              jae         00402D8A
  00402D8A: 8D 76 00           lea         esi,[esi]
  00402D8D: 8D BC 27 00 00 00  lea         edi,[edi+00000000h]
            00
  00402D94: 00 00              add         byte ptr [eax],al
  00402D96: 00 00              add         byte ptr [eax],al
  00402D98: 00 00              add         byte ptr [eax],al
  00402D9A: 00 80 3F 40 00 00  add         byte ptr [eax+0000403Fh],al
  00402DA0: 8D 74 26 00        lea         esi,[esi]
  00402DA4: 00 00              add         byte ptr [eax],al
  00402DA6: 00 00              add         byte ptr [eax],al
  00402DA8: 00 00              add         byte ptr [eax],al
  00402DAA: 24 40              and         al,40h
  00402DAC: 55                 push        ebp
  00402DAD: 89 E5              mov         ebp,esp
  00402DAF: 81 EC AC 00 00 00  sub         esp,0ACh
  00402DB5: 57                 push        edi
  00402DB6: 56                 push        esi
  00402DB7: 53                 push        ebx
  00402DB8: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00402DBB: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00402DBE: 89 45 C8           mov         dword ptr [ebp-38h],eax
  00402DC1: 89 55 CC           mov         dword ptr [ebp-34h],edx
  00402DC4: 8B 5D 14           mov         ebx,dword ptr [ebp+14h]
  00402DC7: 8B 45 18           mov         eax,dword ptr [ebp+18h]
  00402DCA: C7 45 BC 00 00 00  mov         dword ptr [ebp-44h],0
            00
  00402DD1: C7 45 B0 00 00 00  mov         dword ptr [ebp-50h],0
            00
  00402DD8: 85 C0              test        eax,eax
  00402DDA: 7D 10              jge         00402DEC
  00402DDC: F7 D8              neg         eax
  00402DDE: 89 45 C4           mov         dword ptr [ebp-3Ch],eax
  00402DE1: C7 45 C0 01 00 00  mov         dword ptr [ebp-40h],1
            00
  00402DE8: EB 0C              jmp         00402DF6
  00402DEA: 89 F6              mov         esi,esi
  00402DEC: C7 45 C4 00 00 00  mov         dword ptr [ebp-3Ch],0
            00
  00402DF3: 89 45 C0           mov         dword ptr [ebp-40h],eax
  00402DF6: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  00402DF9: 83 C2 20           add         edx,20h
  00402DFC: 89 55 B4           mov         dword ptr [ebp-4Ch],edx
  00402DFF: 8B 4D 10           mov         ecx,dword ptr [ebp+10h]
  00402E02: C6 41 20 00        mov         byte ptr [ecx+20h],0
  00402E06: 39 5D C0           cmp         dword ptr [ebp-40h],ebx
  00402E09: 7F 71              jg          00402E7C
  00402E0B: 89 D8              mov         eax,ebx
  00402E0D: 99                 cdq
  00402E0E: F7 7D C0           idiv        eax,dword ptr [ebp-40h]
  00402E11: 85 D2              test        edx,edx
  00402E13: 0F 85 0F 01 00 00  jne         00402F28
  00402E19: 89 85 68 FF FF FF  mov         dword ptr [ebp+FFFFFF68h],eax
  00402E1F: C1 F8 1F           sar         eax,1Fh
  00402E22: 89 85 6C FF FF FF  mov         dword ptr [ebp+FFFFFF6Ch],eax
  00402E28: 8B 45 C8           mov         eax,dword ptr [ebp-38h]
  00402E2B: F7 A5 68 FF FF FF  mul         eax,dword ptr [ebp+FFFFFF68h]
  00402E31: 89 C6              mov         esi,eax
  00402E33: 89 D7              mov         edi,edx
  00402E35: 8B 45 C8           mov         eax,dword ptr [ebp-38h]
  00402E38: 0F AF 85 6C FF FF  imul        eax,dword ptr [ebp+FFFFFF6Ch]
            FF
  00402E3F: 01 C7              add         edi,eax
  00402E41: 8B 45 CC           mov         eax,dword ptr [ebp-34h]
  00402E44: 0F AF 85 68 FF FF  imul        eax,dword ptr [ebp+FFFFFF68h]
            FF
  00402E4B: 01 C7              add         edi,eax
  00402E4D: 8B 95 68 FF FF FF  mov         edx,dword ptr [ebp+FFFFFF68h]
  00402E53: 8B 8D 6C FF FF FF  mov         ecx,dword ptr [ebp+FFFFFF6Ch]
  00402E59: 51                 push        ecx
  00402E5A: 52                 push        edx
  00402E5B: 57                 push        edi
  00402E5C: 56                 push        esi
  00402E5D: E8 16 1F 00 00     call        00404D78
  00402E62: 83 C4 10           add         esp,10h
  00402E65: 3B 45 C8           cmp         eax,dword ptr [ebp-38h]
  00402E68: 0F 85 BA 00 00 00  jne         00402F28
  00402E6E: 3B 55 CC           cmp         edx,dword ptr [ebp-34h]
  00402E71: 0F 85 B1 00 00 00  jne         00402F28
  00402E77: E9 18 02 00 00     jmp         00403094
  00402E7C: 85 DB              test        ebx,ebx
  00402E7E: 0F 84 A4 00 00 00  je          00402F28
  00402E84: 8B 45 C0           mov         eax,dword ptr [ebp-40h]
  00402E87: 99                 cdq
  00402E88: F7 FB              idiv        eax,ebx
  00402E8A: 89 45 A8           mov         dword ptr [ebp-58h],eax
  00402E8D: 85 D2              test        edx,edx
  00402E8F: 0F 85 93 00 00 00  jne         00402F28
  00402E95: 89 C3              mov         ebx,eax
  00402E97: 89 C6              mov         esi,eax
  00402E99: C1 FE 1F           sar         esi,1Fh
  00402E9C: 56                 push        esi
  00402E9D: 53                 push        ebx
  00402E9E: 8B 55 C8           mov         edx,dword ptr [ebp-38h]
  00402EA1: 8B 4D CC           mov         ecx,dword ptr [ebp-34h]
  00402EA4: 51                 push        ecx
  00402EA5: 52                 push        edx
  00402EA6: E8 BD 20 00 00     call        00404F68
  00402EAB: 83 C4 10           add         esp,10h
  00402EAE: 89 45 A0           mov         dword ptr [ebp-60h],eax
  00402EB1: 89 55 A4           mov         dword ptr [ebp-5Ch],edx
  00402EB4: 0F A4 C2 02        shld        edx,eax,2
  00402EB8: C1 E0 02           shl         eax,2
  00402EBB: 03 45 A0           add         eax,dword ptr [ebp-60h]
  00402EBE: 13 55 A4           adc         edx,dword ptr [ebp-5Ch]
  00402EC1: 01 C0              add         eax,eax
  00402EC3: 99                 cdq
  00402EC4: F7 7D A8           idiv        eax,dword ptr [ebp-58h]
  00402EC7: 89 45 9C           mov         dword ptr [ebp-64h],eax
  00402ECA: 01 D2              add         edx,edx
  00402ECC: 89 55 AC           mov         dword ptr [ebp-54h],edx
  00402ECF: 56                 push        esi
  00402ED0: 53                 push        ebx
  00402ED1: 8B 45 C8           mov         eax,dword ptr [ebp-38h]
  00402ED4: 8B 55 CC           mov         edx,dword ptr [ebp-34h]
  00402ED7: 52                 push        edx
  00402ED8: 50                 push        eax
  00402ED9: E8 9A 1E 00 00     call        00404D78
  00402EDE: 83 C4 10           add         esp,10h
  00402EE1: 89 C6              mov         esi,eax
  00402EE3: 89 D7              mov         edi,edx
  00402EE5: 8B 55 9C           mov         edx,dword ptr [ebp-64h]
  00402EE8: 89 55 BC           mov         dword ptr [ebp-44h],edx
  00402EEB: 8B 4D A8           mov         ecx,dword ptr [ebp-58h]
  00402EEE: 39 4D AC           cmp         dword ptr [ebp-54h],ecx
  00402EF1: 7D 15              jge         00402F08
  00402EF3: 83 7D AC 00        cmp         dword ptr [ebp-54h],0
  00402EF7: 0F 9F C0           setg        al
  00402EFA: 0F B6 D0           movzx       edx,al
  00402EFD: 89 55 B0           mov         dword ptr [ebp-50h],edx
  00402F00: E9 8F 01 00 00     jmp         00403094
  00402F05: 8D 76 00           lea         esi,[esi]
  00402F08: C7 45 B0 02 00 00  mov         dword ptr [ebp-50h],2
            00
  00402F0F: 8B 4D AC           mov         ecx,dword ptr [ebp-54h]
  00402F12: 39 4D A8           cmp         dword ptr [ebp-58h],ecx
  00402F15: 0F 8D 79 01 00 00  jge         00403094
  00402F1B: C7 45 B0 03 00 00  mov         dword ptr [ebp-50h],3
            00
  00402F22: E9 6D 01 00 00     jmp         00403094
  00402F27: 90                 nop
  00402F28: DF 6D C8           fild        qword ptr [ebp-38h]
  00402F2B: DB 7D 80           fstp        tbyte ptr [ebp-80h]
  00402F2E: 6A 00              push        0
  00402F30: 6A 00              push        0
  00402F32: 8B 45 C8           mov         eax,dword ptr [ebp-38h]
  00402F35: 8B 55 CC           mov         edx,dword ptr [ebp-34h]
  00402F38: 52                 push        edx
  00402F39: 50                 push        eax
  00402F3A: E8 05 1D 00 00     call        00404C44
  00402F3F: 83 C4 10           add         esp,10h
  00402F42: 83 F8 01           cmp         eax,1
  00402F45: 7D 0E              jge         00402F55
  00402F47: DB 2D 94 2D 40 00  fld         tbyte ptr ds:[00402D94h]
  00402F4D: DB 6D 80           fld         tbyte ptr [ebp-80h]
  00402F50: DE C1              faddp       st(1),st
  00402F52: DB 7D 80           fstp        tbyte ptr [ebp-80h]
  00402F55: DB 6D 80           fld         tbyte ptr [ebp-80h]
  00402F58: DD 5D 90           fstp        qword ptr [ebp-70h]
  00402F5B: 89 5D EC           mov         dword ptr [ebp-14h],ebx
  00402F5E: DB 45 EC           fild        dword ptr [ebp-14h]
  00402F61: DB 45 C0           fild        dword ptr [ebp-40h]
  00402F64: DE F9              fdivp       st(1),st
  00402F66: DC 4D 90           fmul        qword ptr [ebp-70h]
  00402F69: DD 55 90           fst         qword ptr [ebp-70h]
  00402F6C: 83 7D C4 00        cmp         dword ptr [ebp-3Ch],0
  00402F70: 75 2B              jne         00402F9D
  00402F72: 83 C4 FC           add         esp,0FFFFFFFCh
  00402F75: 83 EC 08           sub         esp,8
  00402F78: DD 1C 24           fstp        qword ptr [esp]
  00402F7B: 8B 45 1C           mov         eax,dword ptr [ebp+1Ch]
  00402F7E: 50                 push        eax
  00402F7F: E8 DC FC FF FF     call        00402C60
  00402F84: 83 EC 08           sub         esp,8
  00402F87: DD 1C 24           fstp        qword ptr [esp]
  00402F8A: 68 77 2D 40 00     push        402D77h
  00402F8F: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  00402F92: 52                 push        edx
  00402F93: E8 88 22 00 00     call        00405220
  00402F98: E9 EF 00 00 00     jmp         0040308C
  00402F9D: DD D8              fstp        st(0)
  00402F9F: C7 45 B8 00 00 00  mov         dword ptr [ebp-48h],0
            00
  00402FA6: 8D 55 D2           lea         edx,[ebp-2Eh]
  00402FA9: 8B 4D EC           mov         ecx,dword ptr [ebp-14h]
  00402FAC: D9 E8              fld1
  00402FAE: DB 45 C4           fild        dword ptr [ebp-3Ch]
  00402FB1: 8D 76 00           lea         esi,[esi]
  00402FB4: DC C9              fmul        st(1),st
  00402FB6: FF 45 B8           inc         dword ptr [ebp-48h]
  00402FB9: D9 C1              fld         st(1)
  00402FBB: D8 C9              fmul        st,st(1)
  00402FBD: DC 5D 90           fcomp       qword ptr [ebp-70h]
  00402FC0: DF E0              fnstsw      ax
  00402FC2: 80 E4 45           and         ah,45h
  00402FC5: FE CC              dec         ah
  00402FC7: 80 FC 40           cmp         ah,40h
  00402FCA: 73 06              jae         00402FD2
  00402FCC: 83 7D B8 07        cmp         dword ptr [ebp-48h],7
  00402FD0: 76 E2              jbe         00402FB4
  00402FD2: DD D8              fstp        st(0)
  00402FD4: DC 7D 90           fdivr       qword ptr [ebp-70h]
  00402FD7: 89 4D EC           mov         dword ptr [ebp-14h],ecx
  00402FDA: C6 45 D2 00        mov         byte ptr [ebp-2Eh],0
  00402FDE: 83 C4 FC           add         esp,0FFFFFFFCh
  00402FE1: 8B 45 C4           mov         eax,dword ptr [ebp-3Ch]
  00402FE4: DD 5D 90           fstp        qword ptr [ebp-70h]
  00402FE7: 50                 push        eax
  00402FE8: 8B 4D B8           mov         ecx,dword ptr [ebp-48h]
  00402FEB: 51                 push        ecx
  00402FEC: 52                 push        edx
  00402FED: E8 2E FC FF FF     call        00402C20
  00402FF2: 89 C3              mov         ebx,eax
  00402FF4: 83 C4 F4           add         esp,0FFFFFFF4h
  00402FF7: 53                 push        ebx
  00402FF8: 83 C4 FC           add         esp,0FFFFFFFCh
  00402FFB: FF 75 94           push        dword ptr [ebp-6Ch]
  00402FFE: FF 75 90           push        dword ptr [ebp-70h]
  00403001: 8B 45 1C           mov         eax,dword ptr [ebp+1Ch]
  00403004: 50                 push        eax
  00403005: E8 56 FC FF FF     call        00402C60
  0040300A: 83 C4 10           add         esp,10h
  0040300D: 83 EC 08           sub         esp,8
  00403010: DD 1C 24           fstp        qword ptr [esp]
  00403013: 68 7C 2D 40 00     push        402D7Ch
  00403018: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  0040301B: 52                 push        edx
  0040301C: E8 FF 21 00 00     call        00405220
  00403021: 8B 7D 10           mov         edi,dword ptr [ebp+10h]
  00403024: B0 00              mov         al,0
  00403026: FC                 cld
  00403027: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  0040302C: F2 AE              repne scas  byte ptr es:[edi]
  0040302E: F7 D1              not         ecx
  00403030: 8D 41 FF           lea         eax,[ecx-1]
  00403033: 83 C4 30           add         esp,30h
  00403036: 81 7D C4 E8 03 00  cmp         dword ptr [ebp-3Ch],3E8h
            00
  0040303D: 75 09              jne         00403048
  0040303F: 83 F8 05           cmp         eax,5
  00403042: 77 09              ja          0040304D
  00403044: EB 46              jmp         0040308C
  00403046: 89 F6              mov         esi,esi
  00403048: 83 F8 04           cmp         eax,4
  0040304B: 76 3F              jbe         0040308C
  0040304D: 83 C4 F4           add         esp,0FFFFFFF4h
  00403050: 53                 push        ebx
  00403051: 83 C4 FC           add         esp,0FFFFFFFCh
  00403054: DD 45 90           fld         qword ptr [ebp-70h]
  00403057: DC 0D A4 2D 40 00  fmul        qword ptr ds:[00402DA4h]
  0040305D: DD 55 90           fst         qword ptr [ebp-70h]
  00403060: 83 EC 08           sub         esp,8
  00403063: DD 1C 24           fstp        qword ptr [esp]
  00403066: 8B 45 1C           mov         eax,dword ptr [ebp+1Ch]
  00403069: 50                 push        eax
  0040306A: E8 F1 FB FF FF     call        00402C60
  0040306F: DC 35 A4 2D 40 00  fdiv        qword ptr ds:[00402DA4h]
  00403075: 83 C4 10           add         esp,10h
  00403078: 83 EC 08           sub         esp,8
  0040307B: DD 1C 24           fstp        qword ptr [esp]
  0040307E: 68 83 2D 40 00     push        402D83h
  00403083: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  00403086: 52                 push        edx
  00403087: E8 94 21 00 00     call        00405220
  0040308C: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  0040308F: E9 59 02 00 00     jmp         004032ED
  00403094: 83 7D C4 00        cmp         dword ptr [ebp-3Ch],0
  00403098: 0F 84 94 01 00 00  je          00403232
  0040309E: 8B 45 C4           mov         eax,dword ptr [ebp-3Ch]
  004030A1: 89 C1              mov         ecx,eax
  004030A3: 89 C3              mov         ebx,eax
  004030A5: C1 FB 1F           sar         ebx,1Fh
  004030A8: 39 FB              cmp         ebx,edi
  004030AA: 0F 87 82 01 00 00  ja          00403232
  004030B0: 75 08              jne         004030BA
  004030B2: 39 F1              cmp         ecx,esi
  004030B4: 0F 87 78 01 00 00  ja          00403232
  004030BA: C7 45 B8 00 00 00  mov         dword ptr [ebp-48h],0
            00
  004030C1: 89 8D 78 FF FF FF  mov         dword ptr [ebp+FFFFFF78h],ecx
  004030C7: 89 9D 7C FF FF FF  mov         dword ptr [ebp+FFFFFF7Ch],ebx
  004030CD: EB 17              jmp         004030E6
  004030CF: 90                 nop
  004030D0: 39 FB              cmp         ebx,edi
  004030D2: 75 08              jne         004030DC
  004030D4: 39 F1              cmp         ecx,esi
  004030D6: 0F 87 B1 00 00 00  ja          0040318D
  004030DC: 83 7D B8 07        cmp         dword ptr [ebp-48h],7
  004030E0: 0F 87 A7 00 00 00  ja          0040318D
  004030E6: 8B 95 78 FF FF FF  mov         edx,dword ptr [ebp+FFFFFF78h]
  004030EC: 8B 8D 7C FF FF FF  mov         ecx,dword ptr [ebp+FFFFFF7Ch]
  004030F2: 51                 push        ecx
  004030F3: 52                 push        edx
  004030F4: 57                 push        edi
  004030F5: 56                 push        esi
  004030F6: E8 6D 1E 00 00     call        00404F68
  004030FB: 83 C4 10           add         esp,10h
  004030FE: 89 C1              mov         ecx,eax
  00403100: 89 D3              mov         ebx,edx
  00403102: 0F A4 C2 02        shld        edx,eax,2
  00403106: C1 E0 02           shl         eax,2
  00403109: 01 C8              add         eax,ecx
  0040310B: 11 DA              adc         edx,ebx
  0040310D: 0F A4 C2 01        shld        edx,eax,1
  00403111: D1 E0              shl         eax,1
  00403113: 03 45 BC           add         eax,dword ptr [ebp-44h]
  00403116: 99                 cdq
  00403117: F7 7D C4           idiv        eax,dword ptr [ebp-3Ch]
  0040311A: 89 85 74 FF FF FF  mov         dword ptr [ebp+FFFFFF74h],eax
  00403120: 8B 45 B0           mov         eax,dword ptr [ebp-50h]
  00403123: D1 F8              sar         eax,1
  00403125: 8D 1C 50           lea         ebx,[eax+edx*2]
  00403128: 8B 85 78 FF FF FF  mov         eax,dword ptr [ebp+FFFFFF78h]
  0040312E: 8B 95 7C FF FF FF  mov         edx,dword ptr [ebp+FFFFFF7Ch]
  00403134: 52                 push        edx
  00403135: 50                 push        eax
  00403136: 57                 push        edi
  00403137: 56                 push        esi
  00403138: E8 3B 1C 00 00     call        00404D78
  0040313D: 83 C4 10           add         esp,10h
  00403140: 89 C6              mov         esi,eax
  00403142: 89 D7              mov         edi,edx
  00403144: 8B 95 74 FF FF FF  mov         edx,dword ptr [ebp+FFFFFF74h]
  0040314A: 89 55 BC           mov         dword ptr [ebp-44h],edx
  0040314D: 3B 5D C4           cmp         ebx,dword ptr [ebp-3Ch]
  00403150: 7D 0E              jge         00403160
  00403152: 03 5D B0           add         ebx,dword ptr [ebp-50h]
  00403155: 85 DB              test        ebx,ebx
  00403157: 0F 9F C0           setg        al
  0040315A: 0F B6 D0           movzx       edx,al
  0040315D: EB 16              jmp         00403175
  0040315F: 90                 nop
  00403160: 8B 55 B0           mov         edx,dword ptr [ebp-50h]
  00403163: 8D 04 1A           lea         eax,[edx+ebx]
  00403166: BA 02 00 00 00     mov         edx,2
  0040316B: 39 45 C4           cmp         dword ptr [ebp-3Ch],eax
  0040316E: 7D 05              jge         00403175
  00403170: BA 03 00 00 00     mov         edx,3
  00403175: 89 55 B0           mov         dword ptr [ebp-50h],edx
  00403178: FF 45 B8           inc         dword ptr [ebp-48h]
  0040317B: 8B 45 C4           mov         eax,dword ptr [ebp-3Ch]
  0040317E: 89 C1              mov         ecx,eax
  00403180: 89 C3              mov         ebx,eax
  00403182: C1 FB 1F           sar         ebx,1Fh
  00403185: 39 FB              cmp         ebx,edi
  00403187: 0F 86 43 FF FF FF  jbe         004030D0
  0040318D: 83 C4 FC           add         esp,0FFFFFFFCh
  00403190: 8B 55 C4           mov         edx,dword ptr [ebp-3Ch]
  00403193: 52                 push        edx
  00403194: 8B 4D B8           mov         ecx,dword ptr [ebp-48h]
  00403197: 51                 push        ecx
  00403198: 8B 45 B4           mov         eax,dword ptr [ebp-4Ch]
  0040319B: 50                 push        eax
  0040319C: E8 7F FA FF FF     call        00402C20
  004031A1: 89 45 B4           mov         dword ptr [ebp-4Ch],eax
  004031A4: 83 C4 10           add         esp,10h
  004031A7: 85 FF              test        edi,edi
  004031A9: 0F 87 83 00 00 00  ja          00403232
  004031AF: 75 05              jne         004031B6
  004031B1: 83 FE 09           cmp         esi,9
  004031B4: 77 7C              ja          00403232
  004031B6: B8 01 00 00 00     mov         eax,1
  004031BB: 2B 45 1C           sub         eax,dword ptr [ebp+1Ch]
  004031BE: 8D 14 00           lea         edx,[eax+eax]
  004031C1: 83 7D 1C 00        cmp         dword ptr [ebp+1Ch],0
  004031C5: 75 15              jne         004031DC
  004031C7: 8B 85 74 FF FF FF  mov         eax,dword ptr [ebp+FFFFFF74h]
  004031CD: 83 E0 01           and         eax,1
  004031D0: 03 45 B0           add         eax,dword ptr [ebp-50h]
  004031D3: 39 C2              cmp         edx,eax
  004031D5: 7C 0A              jl          004031E1
  004031D7: EB 2B              jmp         00403204
  004031D9: 8D 76 00           lea         esi,[esi]
  004031DC: 3B 55 B0           cmp         edx,dword ptr [ebp-50h]
  004031DF: 7D 23              jge         00403204
  004031E1: 8B 95 74 FF FF FF  mov         edx,dword ptr [ebp+FFFFFF74h]
  004031E7: 42                 inc         edx
  004031E8: 89 55 BC           mov         dword ptr [ebp-44h],edx
  004031EB: C7 45 B0 00 00 00  mov         dword ptr [ebp-50h],0
            00
  004031F2: 83 FA 0A           cmp         edx,0Ah
  004031F5: 75 0D              jne         00403204
  004031F7: 83 C6 01           add         esi,1
  004031FA: 83 D7 00           adc         edi,0
  004031FD: C7 45 BC 00 00 00  mov         dword ptr [ebp-44h],0
            00
  00403204: 85 FF              test        edi,edi
  00403206: 77 2A              ja          00403232
  00403208: 75 05              jne         0040320F
  0040320A: 83 FE 09           cmp         esi,9
  0040320D: 77 23              ja          00403232
  0040320F: FF 4D B4           dec         dword ptr [ebp-4Ch]
  00403212: 8A 4D BC           mov         cl,byte ptr [ebp-44h]
  00403215: 80 C1 30           add         cl,30h
  00403218: 8B 45 B4           mov         eax,dword ptr [ebp-4Ch]
  0040321B: 88 08              mov         byte ptr [eax],cl
  0040321D: 48                 dec         eax
  0040321E: 89 45 B4           mov         dword ptr [ebp-4Ch],eax
  00403221: C6 00 2E           mov         byte ptr [eax],2Eh
  00403224: C7 45 B0 00 00 00  mov         dword ptr [ebp-50h],0
            00
  0040322B: C7 45 BC 00 00 00  mov         dword ptr [ebp-44h],0
            00
  00403232: 83 7D 1C 01        cmp         dword ptr [ebp+1Ch],1
  00403236: 75 0C              jne         00403244
  00403238: 8B 45 BC           mov         eax,dword ptr [ebp-44h]
  0040323B: 03 45 B0           add         eax,dword ptr [ebp-50h]
  0040323E: 85 C0              test        eax,eax
  00403240: 7F 3C              jg          0040327E
  00403242: EB 78              jmp         004032BC
  00403244: 83 7D 1C 00        cmp         dword ptr [ebp+1Ch],0
  00403248: 75 72              jne         004032BC
  0040324A: 8B 55 B0           mov         edx,dword ptr [ebp-50h]
  0040324D: 89 D1              mov         ecx,edx
  0040324F: 89 D3              mov         ebx,edx
  00403251: C1 FB 1F           sar         ebx,1Fh
  00403254: 89 F0              mov         eax,esi
  00403256: 89 FA              mov         edx,edi
  00403258: 83 E0 01           and         eax,1
  0040325B: 83 E2 00           and         edx,0
  0040325E: 01 C8              add         eax,ecx
  00403260: 11 DA              adc         edx,ebx
  00403262: 75 07              jne         0040326B
  00403264: 75 12              jne         00403278
  00403266: 83 F8 02           cmp         eax,2
  00403269: 76 0D              jbe         00403278
  0040326B: 8B 45 BC           mov         eax,dword ptr [ebp-44h]
  0040326E: 40                 inc         eax
  0040326F: 83 F8 05           cmp         eax,5
  00403272: 7F 0A              jg          0040327E
  00403274: EB 46              jmp         004032BC
  00403276: 89 F6              mov         esi,esi
  00403278: 83 7D BC 05        cmp         dword ptr [ebp-44h],5
  0040327C: 7E 3E              jle         004032BC
  0040327E: 83 C6 01           add         esi,1
  00403281: 83 D7 00           adc         edi,0
  00403284: 8B 45 C4           mov         eax,dword ptr [ebp-3Ch]
  00403287: 89 C1              mov         ecx,eax
  00403289: 89 C3              mov         ebx,eax
  0040328B: C1 FB 1F           sar         ebx,1Fh
  0040328E: 39 CE              cmp         esi,ecx
  00403290: 75 2A              jne         004032BC
  00403292: 39 DF              cmp         edi,ebx
  00403294: 75 26              jne         004032BC
  00403296: 83 7D B8 07        cmp         dword ptr [ebp-48h],7
  0040329A: 77 20              ja          004032BC
  0040329C: 8B 55 B8           mov         edx,dword ptr [ebp-48h]
  0040329F: 8A 82 15 2C 40 00  mov         al,byte ptr [edx+00402C15h]
  004032A5: 8B 4D B4           mov         ecx,dword ptr [ebp-4Ch]
  004032A8: 88 01              mov         byte ptr [ecx],al
  004032AA: 49                 dec         ecx
  004032AB: C6 01 30           mov         byte ptr [ecx],30h
  004032AE: 49                 dec         ecx
  004032AF: 89 4D B4           mov         dword ptr [ebp-4Ch],ecx
  004032B2: C6 01 2E           mov         byte ptr [ecx],2Eh
  004032B5: BE 01 00 00 00     mov         esi,1
  004032BA: 31 FF              xor         edi,edi
  004032BC: FF 4D B4           dec         dword ptr [ebp-4Ch]
  004032BF: 6A 00              push        0
  004032C1: 6A 0A              push        0Ah
  004032C3: 57                 push        edi
  004032C4: 56                 push        esi
  004032C5: E8 9E 1C 00 00     call        00404F68
  004032CA: 83 C4 10           add         esp,10h
  004032CD: 04 30              add         al,30h
  004032CF: 8B 4D B4           mov         ecx,dword ptr [ebp-4Ch]
  004032D2: 88 01              mov         byte ptr [ecx],al
  004032D4: 6A 00              push        0
  004032D6: 6A 0A              push        0Ah
  004032D8: 57                 push        edi
  004032D9: 56                 push        esi
  004032DA: E8 99 1A 00 00     call        00404D78
  004032DF: 83 C4 10           add         esp,10h
  004032E2: 89 C6              mov         esi,eax
  004032E4: 89 D7              mov         edi,edx
  004032E6: 09 F8              or          eax,edi
  004032E8: 75 D2              jne         004032BC
  004032EA: 8B 45 B4           mov         eax,dword ptr [ebp-4Ch]
  004032ED: 8D A5 48 FF FF FF  lea         esp,[ebp+FFFFFF48h]
  004032F3: 5B                 pop         ebx
  004032F4: 5E                 pop         esi
  004032F5: 5F                 pop         edi
  004032F6: C9                 leave
  004032F7: C3                 ret
  004032F8: 07                 pop         es
  004032F9: 33 40 00           xor         eax,dword ptr [eax]
  004032FC: 04 33              add         al,33h
  004032FE: 40                 inc         eax
  004032FF: 00 00              add         byte ptr [eax],al
  00403301: 00 00              add         byte ptr [eax],al
  00403303: 00 73 69           add         byte ptr [ebx+69h],dh
  00403306: 00 68 75           add         byte ptr [eax+75h],ch
  00403309: 6D                 ins         dword ptr es:[edi],dx
  0040330A: 61                 popad
  0040330B: 6E                 outs        dx,byte ptr [esi]
  0040330C: 2D 72 65 61 64     sub         eax,64616572h
  00403311: 61                 popad
  00403312: 62 6C 65 00        bound       ebp,qword ptr [ebp]
  00403316: 89 F6              mov         esi,esi
  00403318: 00 FC              add         ah,bh
  0040331A: FF
  0040331B: FF 18              call        fword ptr [eax]
  0040331D: FC                 cld
  0040331E: FF
  0040331F: FF 50 4F           call        dword ptr [eax+4Fh]
  00403322: 53                 push        ebx
  00403323: 49                 dec         ecx
  00403324: 58                 pop         eax
  00403325: 4C                 dec         esp
  00403326: 59                 pop         ecx
  00403327: 5F                 pop         edi
  00403328: 43                 inc         ebx
  00403329: 4F                 dec         edi
  0040332A: 52                 push        edx
  0040332B: 52                 push        edx
  0040332C: 45                 inc         ebp
  0040332D: 43                 inc         ebx
  0040332E: 54                 push        esp
  0040332F: 00 55 89           add         byte ptr [ebp-77h],dl
  00403332: E5 83              in          eax,83h
  00403334: EC                 in          al,dx
  00403335: 08 83 C4 F4 68 20  or          byte ptr [ebx+2068F4C4h],al
  0040333B: 33 40 00           xor         eax,dword ptr [eax]
  0040333E: E8 C5 1E 00 00     call        00405208
  00403343: BA 00 04 00 00     mov         edx,400h
  00403348: 85 C0              test        eax,eax
  0040334A: 74 05              je          00403351
  0040334C: BA 00 02 00 00     mov         edx,200h
  00403351: 89 D0              mov         eax,edx
  00403353: C9                 leave
  00403354: C3                 ret
  00403355: 42                 inc         edx
  00403356: 4C                 dec         esp
  00403357: 4F                 dec         edi
  00403358: 43                 inc         ebx
  00403359: 4B                 dec         ebx
  0040335A: 5F                 pop         edi
  0040335B: 53                 push        ebx
  0040335C: 49                 dec         ecx
  0040335D: 5A                 pop         edx
  0040335E: 45                 inc         ebp
  0040335F: 00 65 45           add         byte ptr [ebp+45h],ah
  00403362: 67 47              inc         edi
  00403364: 6B 4B 6D 4D        imul        ecx,dword ptr [ebx+6Dh],4Dh
  00403368: 70 50              jo          004033BA
  0040336A: 74 54              je          004033C0
  0040336C: 79 59              jns         004033C7
  0040336E: 7A 5A              jp          004033CA
  00403370: 30 00              xor         byte ptr [eax],al
  00403372: 89 F6              mov         esi,esi
  00403374: 55                 push        ebp
  00403375: 89 E5              mov         ebp,esp
  00403377: 83 EC 20           sub         esp,20h
  0040337A: 56                 push        esi
  0040337B: 53                 push        ebx
  0040337C: 8B 5D 08           mov         ebx,dword ptr [ebp+8]
  0040337F: 8B 75 0C           mov         esi,dword ptr [ebp+0Ch]
  00403382: 85 DB              test        ebx,ebx
  00403384: 75 1E              jne         004033A4
  00403386: 83 C4 F4           add         esp,0FFFFFFF4h
  00403389: 68 55 33 40 00     push        403355h
  0040338E: E8 75 1E 00 00     call        00405208
  00403393: 89 C3              mov         ebx,eax
  00403395: 83 C4 10           add         esp,10h
  00403398: 85 DB              test        ebx,ebx
  0040339A: 75 08              jne         004033A4
  0040339C: E8 8F FF FF FF     call        00403330
  004033A1: EB 61              jmp         00403404
  004033A3: 90                 nop
  004033A4: 6A 04              push        4
  004033A6: 68 18 33 40 00     push        403318h
  004033AB: 68 F8 32 40 00     push        4032F8h
  004033B0: 53                 push        ebx
  004033B1: E8 5A 13 00 00     call        00404710
  004033B6: 83 C4 10           add         esp,10h
  004033B9: 85 C0              test        eax,eax
  004033BB: 7C 0B              jl          004033C8
  004033BD: 8B 04 85 18 33 40  mov         eax,dword ptr [eax*4+00403318h]
            00
  004033C4: EB 3E              jmp         00403404
  004033C6: 89 F6              mov         esi,esi
  004033C8: 83 C4 F4           add         esp,0FFFFFFF4h
  004033CB: 68 60 33 40 00     push        403360h
  004033D0: 8D 45 FC           lea         eax,[ebp-4]
  004033D3: 50                 push        eax
  004033D4: 6A 00              push        0
  004033D6: 8D 45 F8           lea         eax,[ebp-8]
  004033D9: 50                 push        eax
  004033DA: 53                 push        ebx
  004033DB: E8 44 0F 00 00     call        00404324
  004033E0: 85 C0              test        eax,eax
  004033E2: 75 24              jne         00403408
  004033E4: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  004033E7: 80 38 00           cmp         byte ptr [eax],0
  004033EA: 74 08              je          004033F4
  004033EC: B8 02 00 00 00     mov         eax,2
  004033F1: EB 15              jmp         00403408
  004033F3: 90                 nop
  004033F4: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  004033F7: 85 C0              test        eax,eax
  004033F9: 7D 09              jge         00403404
  004033FB: B8 03 00 00 00     mov         eax,3
  00403400: EB 06              jmp         00403408
  00403402: 89 F6              mov         esi,esi
  00403404: 89 06              mov         dword ptr [esi],eax
  00403406: 31 C0              xor         eax,eax
  00403408: 8D 65 D8           lea         esp,[ebp-28h]
  0040340B: 5B                 pop         ebx
  0040340C: 5E                 pop         esi
  0040340D: C9                 leave
  0040340E: C3                 ret
  0040340F: 62 6C 6F 63        bound       ebp,qword ptr [edi+ebp*2+63h]
  00403413: 6B 20 73           imul        esp,dword ptr [eax],73h
  00403416: 69 7A 65 00 69 6E  imul        edi,dword ptr [edx+65h],766E6900h
            76
  0040341D: 61                 popad
  0040341E: 6C                 ins         byte ptr es:[edi],dx
  0040341F: 69 64 20 25 73 20  imul        esp,dword ptr [eax+25h],25602073h
            60 25
  00403427: 73 27              jae         00403450
  00403429: 00 8D 76 00 8D BC  add         byte ptr [ebp+BC8D0076h],cl
  0040342F: 27                 daa
  00403430: 00 00              add         byte ptr [eax],al
  00403432: 00 00              add         byte ptr [eax],al
  00403434: 69 6E 76 61 6C 69  imul        ebp,dword ptr [esi+76h],64696C61h
            64
  0040343B: 20 63 68           and         byte ptr [ebx+68h],ah
  0040343E: 61                 popad
  0040343F: 72 61              jb          004034A2
  00403441: 63 74 65 72        arpl        word ptr [ebp+72h],si
  00403445: 20 66 6F           and         byte ptr [esi+6Fh],ah
  00403448: 6C                 ins         byte ptr es:[edi],dx
  00403449: 6C                 ins         byte ptr es:[edi],dx
  0040344A: 6F                 outs        dx,dword ptr [esi]
  0040344B: 77 69              ja          004034B6
  0040344D: 6E                 outs        dx,byte ptr [esi]
  0040344E: 67 20 25           and         byte ptr [di],ah
  00403451: 73 20              jae         00403473
  00403453: 69 6E 20 60 25 73  imul        ebp,dword ptr [esi+20h],27732560h
            27
  0040345A: 00 25 73 20 60 25  add         byte ptr ds:[25602073h],ah
  00403460: 73 27              jae         00403489
  00403462: 20 74 6F 6F        and         byte ptr [edi+ebp*2+6Fh],dh
  00403466: 20 6C 61 72        and         byte ptr [ecx+72h],ch
  0040346A: 67 65 00 8D 76 00  add         byte ptr gs:[di+0076h],cl
  00403470: 55                 push        ebp
  00403471: 89 E5              mov         ebp,esp
  00403473: 83 EC 10           sub         esp,10h
  00403476: 56                 push        esi
  00403477: 53                 push        ebx
  00403478: 8B 5D 08           mov         ebx,dword ptr [ebp+8]
  0040347B: 8B 75 10           mov         esi,dword ptr [ebp+10h]
  0040347E: 83 C4 F8           add         esp,0FFFFFFF8h
  00403481: 56                 push        esi
  00403482: 53                 push        ebx
  00403483: E8 EC FE FF FF     call        00403374
  00403488: 83 C4 10           add         esp,10h
  0040348B: 83 3E 00           cmp         dword ptr [esi],0
  0040348E: 75 0C              jne         0040349C
  00403490: E8 9B FE FF FF     call        00403330
  00403495: 89 06              mov         dword ptr [esi],eax
  00403497: B8 01 00 00 00     mov         eax,1
  0040349C: 85 C0              test        eax,eax
  0040349E: 74 67              je          00403507
  004034A0: 83 7D 0C 00        cmp         dword ptr [ebp+0Ch],0
  004034A4: 74 61              je          00403507
  004034A6: 83 F8 01           cmp         eax,1
  004034A9: 74 19              je          004034C4
  004034AB: 72 0F              jb          004034BC
  004034AD: 83 F8 02           cmp         eax,2
  004034B0: 74 22              je          004034D4
  004034B2: 83 F8 03           cmp         eax,3
  004034B5: 74 39              je          004034F0
  004034B7: EB 4E              jmp         00403507
  004034B9: 8D 76 00           lea         esi,[esi]
  004034BC: E8 57 1D 00 00     call        00405218
  004034C1: 8D 76 00           lea         esi,[esi]
  004034C4: 83 C4 F4           add         esp,0FFFFFFF4h
  004034C7: 53                 push        ebx
  004034C8: 68 0F 34 40 00     push        40340Fh
  004034CD: 68 1A 34 40 00     push        40341Ah
  004034D2: EB 0E              jmp         004034E2
  004034D4: 83 C4 F4           add         esp,0FFFFFFF4h
  004034D7: 53                 push        ebx
  004034D8: 68 0F 34 40 00     push        40340Fh
  004034DD: 68 34 34 40 00     push        403434h
  004034E2: 6A 00              push        0
  004034E4: 6A 02              push        2
  004034E6: E8 FD 00 00 00     call        004035E8
  004034EB: EB 1A              jmp         00403507
  004034ED: 8D 76 00           lea         esi,[esi]
  004034F0: 83 C4 F4           add         esp,0FFFFFFF4h
  004034F3: 53                 push        ebx
  004034F4: 68 0F 34 40 00     push        40340Fh
  004034F9: 68 5B 34 40 00     push        40345Bh
  004034FE: 6A 00              push        0
  00403500: 6A 02              push        2
  00403502: E8 E1 00 00 00     call        004035E8
  00403507: 8D 65 E8           lea         esp,[ebp-18h]
  0040350A: 5B                 pop         ebx
  0040350B: 5E                 pop         esi
  0040350C: C9                 leave
  0040350D: C3                 ret
  0040350E: 8D B6 00 00 00 00  lea         esi,[esi+00000000h]
  00403514: 55                 push        ebp
  00403515: 6E                 outs        dx,byte ptr [esi]
  00403516: 6B 6E 6F 77        imul        ebp,dword ptr [esi+6Fh],77h
  0040351A: 6E                 outs        dx,byte ptr [esi]
  0040351B: 20 73 79           and         byte ptr [ebx+79h],dh
  0040351E: 73 74              jae         00403594
  00403520: 65 6D              ins         dword ptr es:[edi],dx
  00403522: 20 65 72           and         byte ptr [ebp+72h],ah
  00403525: 72 6F              jb          00403596
  00403527: 72 00              jb          00403529
  00403529: 3A 20              cmp         ah,byte ptr [eax]
  0040352B: 25 73 00 89 F6     and         eax,0F6890073h
  00403530: 55                 push        ebp
  00403531: 89 E5              mov         ebp,esp
  00403533: 83 EC 08           sub         esp,8
  00403536: 83 C4 F4           add         esp,0FFFFFFF4h
  00403539: FF 75 08           push        dword ptr [ebp+8]
  0040353C: E8 FF 1C 00 00     call        00405240
  00403541: 83 C4 10           add         esp,10h
  00403544: 85 C0              test        eax,eax
  00403546: 75 05              jne         0040354D
  00403548: B8 14 35 40 00     mov         eax,403514h
  0040354D: 83 C4 FC           add         esp,0FFFFFFFCh
  00403550: 50                 push        eax
  00403551: 68 29 35 40 00     push        403529h
  00403556: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  0040355B: 83 C0 40           add         eax,40h
  0040355E: 50                 push        eax
  0040355F: E8 94 1C 00 00     call        004051F8
  00403564: C9                 leave
  00403565: C3                 ret
  00403566: 89 F6              mov         esi,esi
  00403568: 55                 push        ebp
  00403569: 89 E5              mov         ebp,esp
  0040356B: 83 EC 10           sub         esp,10h
  0040356E: 56                 push        esi
  0040356F: 53                 push        ebx
  00403570: 8B 75 08           mov         esi,dword ptr [ebp+8]
  00403573: 8B 5D 0C           mov         ebx,dword ptr [ebp+0Ch]
  00403576: 83 C4 FC           add         esp,0FFFFFFFCh
  00403579: FF 75 14           push        dword ptr [ebp+14h]
  0040357C: FF 75 10           push        dword ptr [ebp+10h]
  0040357F: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00403584: 83 C0 40           add         eax,40h
  00403587: 50                 push        eax
  00403588: E8 AB 1C 00 00     call        00405238
  0040358D: FF 05 00 72 40 00  inc         dword ptr ds:[00407200h]
  00403593: 83 C4 10           add         esp,10h
  00403596: 85 DB              test        ebx,ebx
  00403598: 74 0C              je          004035A6
  0040359A: 83 C4 F4           add         esp,0FFFFFFF4h
  0040359D: 53                 push        ebx
  0040359E: E8 8D FF FF FF     call        00403530
  004035A3: 83 C4 10           add         esp,10h
  004035A6: 83 C4 F8           add         esp,0FFFFFFF8h
  004035A9: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004035AE: 83 C0 40           add         eax,40h
  004035B1: 50                 push        eax
  004035B2: 6A 0A              push        0Ah
  004035B4: E8 57 1C 00 00     call        00405210
  004035B9: 83 C4 F4           add         esp,0FFFFFFF4h
  004035BC: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004035C1: 83 C0 40           add         eax,40h
  004035C4: 50                 push        eax
  004035C5: E8 66 1C 00 00     call        00405230
  004035CA: 83 C4 20           add         esp,20h
  004035CD: 85 F6              test        esi,esi
  004035CF: 74 0B              je          004035DC
  004035D1: 83 C4 F4           add         esp,0FFFFFFF4h
  004035D4: 56                 push        esi
  004035D5: E8 06 1C 00 00     call        004051E0
  004035DA: 89 F6              mov         esi,esi
  004035DC: 8D 65 E8           lea         esp,[ebp-18h]
  004035DF: 5B                 pop         ebx
  004035E0: 5E                 pop         esi
  004035E1: C9                 leave
  004035E2: C3                 ret
  004035E3: 25 73 3A 20 00     and         eax,203A73h
  004035E8: 55                 push        ebp
  004035E9: 89 E5              mov         ebp,esp
  004035EB: 83 EC 08           sub         esp,8
  004035EE: 83 C4 F4           add         esp,0FFFFFFF4h
  004035F1: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004035F6: 83 C0 20           add         eax,20h
  004035F9: 50                 push        eax
  004035FA: E8 31 1C 00 00     call        00405230
  004035FF: 83 C4 10           add         esp,10h
  00403602: A1 F0 71 40 00     mov         eax,dword ptr ds:[004071F0h]
  00403607: 85 C0              test        eax,eax
  00403609: 74 05              je          00403610
  0040360B: FF D0              call        eax
  0040360D: EB 20              jmp         0040362F
  0040360F: 90                 nop
  00403610: 83 C4 FC           add         esp,0FFFFFFFCh
  00403613: FF 35 C0 71 40 00  push        dword ptr ds:[004071C0h]
  00403619: 68 E3 35 40 00     push        4035E3h
  0040361E: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00403623: 83 C0 40           add         eax,40h
  00403626: 50                 push        eax
  00403627: E8 CC 1B 00 00     call        004051F8
  0040362C: 83 C4 10           add         esp,10h
  0040362F: 8D 45 14           lea         eax,[ebp+14h]
  00403632: 50                 push        eax
  00403633: FF 75 10           push        dword ptr [ebp+10h]
  00403636: FF 75 0C           push        dword ptr [ebp+0Ch]
  00403639: FF 75 08           push        dword ptr [ebp+8]
  0040363C: E8 27 FF FF FF     call        00403568
  00403641: C9                 leave
  00403642: C3                 ret
  00403643: 25 73 3A 00 25     and         eax,25003A73h
  00403648: 73 3A              jae         00403684
  0040364A: 25 64 3A 20 00     and         eax,203A64h
  0040364F: 90                 nop
  00403650: 55                 push        ebp
  00403651: 89 E5              mov         ebp,esp
  00403653: 83 EC 10           sub         esp,10h
  00403656: 56                 push        esi
  00403657: 53                 push        ebx
  00403658: 8B 5D 10           mov         ebx,dword ptr [ebp+10h]
  0040365B: 8B 75 14           mov         esi,dword ptr [ebp+14h]
  0040365E: 83 3D 10 72 40 00  cmp         dword ptr ds:[00407210h],0
            00
  00403665: 74 32              je          00403699
  00403667: 39 35 80 70 40 00  cmp         dword ptr ds:[00407080h],esi
  0040366D: 75 1E              jne         0040368D
  0040366F: A1 70 70 40 00     mov         eax,dword ptr ds:[00407070h]
  00403674: 39 C3              cmp         ebx,eax
  00403676: 0F 84 8D 00 00 00  je          00403709
  0040367C: 83 C4 F8           add         esp,0FFFFFFF8h
  0040367F: 53                 push        ebx
  00403680: 50                 push        eax
  00403681: E8 A2 1B 00 00     call        00405228
  00403686: 83 C4 10           add         esp,10h
  00403689: 85 C0              test        eax,eax
  0040368B: 74 7C              je          00403709
  0040368D: 89 1D 70 70 40 00  mov         dword ptr ds:[00407070h],ebx
  00403693: 89 35 80 70 40 00  mov         dword ptr ds:[00407080h],esi
  00403699: 83 C4 F4           add         esp,0FFFFFFF4h
  0040369C: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004036A1: 83 C0 20           add         eax,20h
  004036A4: 50                 push        eax
  004036A5: E8 86 1B 00 00     call        00405230
  004036AA: 83 C4 10           add         esp,10h
  004036AD: A1 F0 71 40 00     mov         eax,dword ptr ds:[004071F0h]
  004036B2: 85 C0              test        eax,eax
  004036B4: 74 06              je          004036BC
  004036B6: FF D0              call        eax
  004036B8: EB 21              jmp         004036DB
  004036BA: 89 F6              mov         esi,esi
  004036BC: 83 C4 FC           add         esp,0FFFFFFFCh
  004036BF: FF 35 C0 71 40 00  push        dword ptr ds:[004071C0h]
  004036C5: 68 43 36 40 00     push        403643h
  004036CA: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004036CF: 83 C0 40           add         eax,40h
  004036D2: 50                 push        eax
  004036D3: E8 20 1B 00 00     call        004051F8
  004036D8: 83 C4 10           add         esp,10h
  004036DB: 85 DB              test        ebx,ebx
  004036DD: 74 18              je          004036F7
  004036DF: 56                 push        esi
  004036E0: 53                 push        ebx
  004036E1: 68 47 36 40 00     push        403647h
  004036E6: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004036EB: 83 C0 40           add         eax,40h
  004036EE: 50                 push        eax
  004036EF: E8 04 1B 00 00     call        004051F8
  004036F4: 83 C4 10           add         esp,10h
  004036F7: 8D 45 1C           lea         eax,[ebp+1Ch]
  004036FA: 50                 push        eax
  004036FB: FF 75 18           push        dword ptr [ebp+18h]
  004036FE: FF 75 0C           push        dword ptr [ebp+0Ch]
  00403701: FF 75 08           push        dword ptr [ebp+8]
  00403704: E8 5F FE FF FF     call        00403568
  00403709: 8D 65 E8           lea         esp,[ebp-18h]
  0040370C: 5B                 pop         ebx
  0040370D: 5E                 pop         esi
  0040370E: C9                 leave
  0040370F: C3                 ret
  00403710: 5B                 pop         ebx
  00403711: 37                 aaa
  00403712: 40                 inc         eax
  00403713: 00 55 37           add         byte ptr [ebp+37h],dl
  00403716: 40                 inc         eax
  00403717: 00 48 37           add         byte ptr [eax+37h],cl
  0040371A: 40                 inc         eax
  0040371B: 00 46 37           add         byte ptr [esi+37h],al
  0040371E: 40                 inc         eax
  0040371F: 00 3F              add         byte ptr [edi],bh
  00403721: 37                 aaa
  00403722: 40                 inc         eax
  00403723: 00 38              add         byte ptr [eax],bh
  00403725: 37                 aaa
  00403726: 40                 inc         eax
  00403727: 00 30              add         byte ptr [eax],dh
  00403729: 37                 aaa
  0040372A: 40                 inc         eax
  0040372B: 00 00              add         byte ptr [eax],al
  0040372D: 00 00              add         byte ptr [eax],al
  0040372F: 00 63 6C           add         byte ptr [ebx+6Ch],ah
  00403732: 6F                 outs        dx,dword ptr [esi]
  00403733: 63 61 6C           arpl        word ptr [ecx+6Ch],sp
  00403736: 65 00 6C 6F 63     add         byte ptr gs:[edi+ebp*2+63h],ch
  0040373B: 61                 popad
  0040373C: 6C                 ins         byte ptr es:[edi],dx
  0040373D: 65 00 65 73        add         byte ptr gs:[ebp+73h],ah
  00403741: 63 61 70           arpl        word ptr [ecx+70h],sp
  00403744: 65 00 63 00        add         byte ptr gs:[ebx],ah
  00403748: 73 68              jae         004037B2
  0040374A: 65 6C              ins         byte ptr es:[edi],dx
  0040374C: 6C                 ins         byte ptr es:[edi],dx
  0040374D: 2D 61 6C 77 61     sub         eax,61776C61h
  00403752: 79 73              jns         004037C7
  00403754: 00 73 68           add         byte ptr [ebx+68h],dh
  00403757: 65 6C              ins         byte ptr es:[edi],dx
  00403759: 6C                 ins         byte ptr es:[edi],dx
  0040375A: 00 6C 69 74        add         byte ptr [ecx+ebp*2+74h],ch
  0040375E: 65 72 61           jb          004037C2
  00403761: 6C                 ins         byte ptr es:[edi],dx
  00403762: 00 90 00 00 00 00  add         byte ptr [eax+00000000h],dl
  00403768: 01 00              add         dword ptr [eax],eax
  0040376A: 00 00              add         byte ptr [eax],al
  0040376C: 02 00              add         al,byte ptr [eax]
  0040376E: 00 00              add         byte ptr [eax],al
  00403770: 03 00              add         eax,dword ptr [eax]
  00403772: 00 00              add         byte ptr [eax],al
  00403774: 04 00              add         al,0
  00403776: 00 00              add         byte ptr [eax],al
  00403778: 05 00 00 00 06     add         eax,6000000h
  0040377D: 00 00              add         byte ptr [eax],al
  0040377F: 00 55 89           add         byte ptr [ebp-77h],dl
  00403782: E5 83              in          eax,83h
  00403784: EC                 in          al,dx
  00403785: 0C 57              or          al,57h
  00403787: 56                 push        esi
  00403788: 53                 push        ebx
  00403789: 8B 5D 08           mov         ebx,dword ptr [ebp+8]
  0040378C: 83 C4 F4           add         esp,0FFFFFFF4h
  0040378F: 6A 24              push        24h
  00403791: E8 2E 12 00 00     call        004049C4
  00403796: 89 DE              mov         esi,ebx
  00403798: 85 F6              test        esi,esi
  0040379A: 75 05              jne         004037A1
  0040379C: BE 90 71 40 00     mov         esi,407190h
  004037A1: 89 C7              mov         edi,eax
  004037A3: FC                 cld
  004037A4: B9 09 00 00 00     mov         ecx,9
  004037A9: F3 A5              rep movs    dword ptr es:[edi],dword ptr [esi]
  004037AB: 8D 65 E8           lea         esp,[ebp-18h]
  004037AE: 5B                 pop         ebx
  004037AF: 5E                 pop         esi
  004037B0: 5F                 pop         edi
  004037B1: C9                 leave
  004037B2: C3                 ret
  004037B3: 90                 nop
  004037B4: 55                 push        ebp
  004037B5: 89 E5              mov         ebp,esp
  004037B7: 8B 45 08           mov         eax,dword ptr [ebp+8]
  004037BA: 85 C0              test        eax,eax
  004037BC: 75 05              jne         004037C3
  004037BE: B8 90 71 40 00     mov         eax,407190h
  004037C3: 8B 00              mov         eax,dword ptr [eax]
  004037C5: C9                 leave
  004037C6: C3                 ret
  004037C7: 90                 nop
  004037C8: 55                 push        ebp
  004037C9: 89 E5              mov         ebp,esp
  004037CB: 8B 55 08           mov         edx,dword ptr [ebp+8]
  004037CE: 85 D2              test        edx,edx
  004037D0: 75 05              jne         004037D7
  004037D2: BA 90 71 40 00     mov         edx,407190h
  004037D7: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  004037DA: 89 02              mov         dword ptr [edx],eax
  004037DC: C9                 leave
  004037DD: C3                 ret
  004037DE: 89 F6              mov         esi,esi
  004037E0: 55                 push        ebp
  004037E1: 89 E5              mov         ebp,esp
  004037E3: 57                 push        edi
  004037E4: 56                 push        esi
  004037E5: 53                 push        ebx
  004037E6: 8B 4D 08           mov         ecx,dword ptr [ebp+8]
  004037E9: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  004037EC: 8A 5D 0C           mov         bl,byte ptr [ebp+0Ch]
  004037EF: 88 D8              mov         al,bl
  004037F1: C0 E8 05           shr         al,5
  004037F4: 25 FF 00 00 00     and         eax,0FFh
  004037F9: C1 E0 02           shl         eax,2
  004037FC: 85 C9              test        ecx,ecx
  004037FE: 74 08              je          00403808
  00403800: 8D 7C 01 04        lea         edi,[ecx+eax+4]
  00403804: EB 08              jmp         0040380E
  00403806: 89 F6              mov         esi,esi
  00403808: 8D B8 94 71 40 00  lea         edi,[eax+00407194h]
  0040380E: 83 E3 1F           and         ebx,1Fh
  00403811: 8B 37              mov         esi,dword ptr [edi]
  00403813: 89 F0              mov         eax,esi
  00403815: 89 D9              mov         ecx,ebx
  00403817: D3 F8              sar         eax,cl
  00403819: 83 E0 01           and         eax,1
  0040381C: 83 E2 01           and         edx,1
  0040381F: 31 C2              xor         edx,eax
  00403821: D3 E2              shl         edx,cl
  00403823: 31 D6              xor         esi,edx
  00403825: 89 37              mov         dword ptr [edi],esi
  00403827: 5B                 pop         ebx
  00403828: 5E                 pop         esi
  00403829: 5F                 pop         edi
  0040382A: C9                 leave
  0040382B: C3                 ret
  0040382C: 22 00              and         al,byte ptr [eax]
  0040382E: 89 F6              mov         esi,esi
  00403830: 55                 push        ebp
  00403831: 89 E5              mov         ebp,esp
  00403833: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00403836: 83 7D 0C 06        cmp         dword ptr [ebp+0Ch],6
  0040383A: 75 05              jne         00403841
  0040383C: B8 2C 38 40 00     mov         eax,40382Ch
  00403841: C9                 leave
  00403842: C3                 ret
  00403843: 60                 pushad
  00403844: 00 27              add         byte ptr [edi],ah
  00403846: 00 90 55 89 E5 83  add         byte ptr [eax+83E58955h],dl
  0040384C: EC                 in          al,dx
  0040384D: 3C 57              cmp         al,57h
  0040384F: 56                 push        esi
  00403850: 53                 push        ebx
  00403851: 31 DB              xor         ebx,ebx
  00403853: C7 45 F8 00 00 00  mov         dword ptr [ebp-8],0
            00
  0040385A: C7 45 F4 00 00 00  mov         dword ptr [ebp-0Ch],0
            00
  00403861: C7 45 F0 00 00 00  mov         dword ptr [ebp-10h],0
            00
  00403868: 8B 45 18           mov         eax,dword ptr [ebp+18h]
  0040386B: 83 C0 FE           add         eax,0FFFFFFFEh
  0040386E: 83 F8 04           cmp         eax,4
  00403871: 0F 87 DC 00 00 00  ja          00403953
  00403877: FF 24 85 80 38 40  jmp         dword ptr [eax*4+00403880h]
            00
  0040387E: 89 F6              mov         esi,esi
  00403880: 34 39              xor         al,39h
  00403882: 40                 inc         eax
  00403883: 00 94 38 40 00 B8  add         byte ptr [eax+edi+38B80040h],dl
            38
  0040388A: 40                 inc         eax
  0040388B: 00 C4              add         ah,al
  0040388D: 38 40 00           cmp         byte ptr [eax],al
  00403890: C4 38              les         edi,fword ptr [eax]
  00403892: 40                 inc         eax
  00403893: 00 3B              add         byte ptr [ebx],bh
  00403895: 5D                 pop         ebp
  00403896: 0C 73              or          al,73h
  00403898: 07                 pop         es
  00403899: 8B 45 08           mov         eax,dword ptr [ebp+8]
  0040389C: C6 00 22           mov         byte ptr [eax],22h
  0040389F: 90                 nop
  004038A0: BB 01 00 00 00     mov         ebx,1
  004038A5: C7 45 F0 01 00 00  mov         dword ptr [ebp-10h],1
            00
  004038AC: C7 45 F8 2C 38 40  mov         dword ptr [ebp-8],40382Ch
            00
  004038B3: E9 94 00 00 00     jmp         0040394C
  004038B8: C7 45 F0 01 00 00  mov         dword ptr [ebp-10h],1
            00
  004038BF: E9 8F 00 00 00     jmp         00403953
  004038C4: 83 C4 F8           add         esp,0FFFFFFF8h
  004038C7: 8B 55 18           mov         edx,dword ptr [ebp+18h]
  004038CA: 52                 push        edx
  004038CB: 68 43 38 40 00     push        403843h
  004038D0: E8 5B FF FF FF     call        00403830
  004038D5: 89 C6              mov         esi,eax
  004038D7: 83 C4 F8           add         esp,0FFFFFFF8h
  004038DA: 8B 4D 18           mov         ecx,dword ptr [ebp+18h]
  004038DD: 51                 push        ecx
  004038DE: 68 45 38 40 00     push        403845h
  004038E3: E8 48 FF FF FF     call        00403830
  004038E8: 89 C2              mov         edx,eax
  004038EA: 89 75 F8           mov         dword ptr [ebp-8],esi
  004038ED: 83 C4 20           add         esp,20h
  004038F0: 80 3E 00           cmp         byte ptr [esi],0
  004038F3: 74 1F              je          00403914
  004038F5: 8D 76 00           lea         esi,[esi]
  004038F8: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  004038FB: 73 0B              jae         00403908
  004038FD: 8B 75 F8           mov         esi,dword ptr [ebp-8]
  00403900: 8A 06              mov         al,byte ptr [esi]
  00403902: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00403905: 88 04 3B           mov         byte ptr [ebx+edi],al
  00403908: 43                 inc         ebx
  00403909: FF 45 F8           inc         dword ptr [ebp-8]
  0040390C: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  0040390F: 80 38 00           cmp         byte ptr [eax],0
  00403912: 75 E4              jne         004038F8
  00403914: C7 45 F0 01 00 00  mov         dword ptr [ebp-10h],1
            00
  0040391B: 89 55 F8           mov         dword ptr [ebp-8],edx
  0040391E: 89 D7              mov         edi,edx
  00403920: B0 00              mov         al,0
  00403922: FC                 cld
  00403923: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  00403928: F2 AE              repne scas  byte ptr es:[edi]
  0040392A: F7 D1              not         ecx
  0040392C: 49                 dec         ecx
  0040392D: 89 4D F4           mov         dword ptr [ebp-0Ch],ecx
  00403930: EB 21              jmp         00403953
  00403932: 89 F6              mov         esi,esi
  00403934: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403937: 73 07              jae         00403940
  00403939: 8B 55 08           mov         edx,dword ptr [ebp+8]
  0040393C: C6 02 27           mov         byte ptr [edx],27h
  0040393F: 90                 nop
  00403940: BB 01 00 00 00     mov         ebx,1
  00403945: C7 45 F8 45 38 40  mov         dword ptr [ebp-8],403845h
            00
  0040394C: C7 45 F4 01 00 00  mov         dword ptr [ebp-0Ch],1
            00
  00403953: C7 45 FC 00 00 00  mov         dword ptr [ebp-4],0
            00
  0040395A: E9 11 06 00 00     jmp         00403F70
  0040395F: 90                 nop
  00403960: 83 7D F0 00        cmp         dword ptr [ebp-10h],0
  00403964: 74 33              je          00403999
  00403966: 83 7D F4 00        cmp         dword ptr [ebp-0Ch],0
  0040396A: 74 2D              je          00403999
  0040396C: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  0040396F: 03 45 F4           add         eax,dword ptr [ebp-0Ch]
  00403972: 3B 45 14           cmp         eax,dword ptr [ebp+14h]
  00403975: 77 22              ja          00403999
  00403977: 8B 75 10           mov         esi,dword ptr [ebp+10h]
  0040397A: 03 75 FC           add         esi,dword ptr [ebp-4]
  0040397D: 8B 7D F8           mov         edi,dword ptr [ebp-8]
  00403980: 8B 4D F4           mov         ecx,dword ptr [ebp-0Ch]
  00403983: FC                 cld
  00403984: A8 00              test        al,0
  00403986: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  00403988: 75 0F              jne         00403999
  0040398A: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  0040398D: 73 09              jae         00403998
  0040398F: 8B 4D 08           mov         ecx,dword ptr [ebp+8]
  00403992: C6 04 0B 5C        mov         byte ptr [ebx+ecx],5Ch
  00403996: 89 F6              mov         esi,esi
  00403998: 43                 inc         ebx
  00403999: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  0040399C: 8B 55 FC           mov         edx,dword ptr [ebp-4]
  0040399F: 8A 04 02           mov         al,byte ptr [edx+eax]
  004039A2: 88 45 E0           mov         byte ptr [ebp-20h],al
  004039A5: 0F B6 45 E0        movzx       eax,byte ptr [ebp-20h]
  004039A9: 8A 4D E0           mov         cl,byte ptr [ebp-20h]
  004039AC: 88 4D D7           mov         byte ptr [ebp-29h],cl
  004039AF: 83 F8 7E           cmp         eax,7Eh
  004039B2: 0F 87 FC 03 00 00  ja          00403DB4
  004039B8: FF 24 85 C0 39 40  jmp         dword ptr [eax*4+004039C0h]
            00
  004039BF: 90                 nop
  004039C0: BC 3B 40 00 B4     mov         esp,0B400403Bh
  004039C5: 3D 40 00 B4 3D     cmp         eax,3DB40040h
  004039CA: 40                 inc         eax
  004039CB: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  004039D2: 40                 inc         eax
  004039D3: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  004039DA: 40                 inc         eax
  004039DB: 00 10              add         byte ptr [eax],dl
  004039DD: 3D 40 00 14 3D     cmp         eax,3D140040h
  004039E2: 40                 inc         eax
  004039E3: 00 24 3D 40 00 1C  add         byte ptr [edi+3D1C0040h],ah
            3D
  004039EA: 40                 inc         eax
  004039EB: 00 28              add         byte ptr [eax],ch
  004039ED: 3D 40 00 18 3D     cmp         eax,3D180040h
  004039F2: 40                 inc         eax
  004039F3: 00 20              add         byte ptr [eax],ah
  004039F5: 3D 40 00 B4 3D     cmp         eax,3DB40040h
  004039FA: 40                 inc         eax
  004039FB: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  00403A02: 40                 inc         eax
  00403A03: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  00403A0A: 40                 inc         eax
  00403A0B: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  00403A12: 40                 inc         eax
  00403A13: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  00403A1A: 40                 inc         eax
  00403A1B: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  00403A22: 40                 inc         eax
  00403A23: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  00403A2A: 40                 inc         eax
  00403A2B: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  00403A32: 40                 inc         eax
  00403A33: 00 B4 3D 40 00 B4  add         byte ptr [ebp+edi+3DB40040h],dh
            3D
  00403A3A: 40                 inc         eax
  00403A3B: 00 B4 3D 40 00 5A  add         byte ptr [ebp+edi+3D5A0040h],dh
            3D
  00403A42: 40                 inc         eax
  00403A43: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403A46: 40                 inc         eax
  00403A47: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403A4A: 40                 inc         eax
  00403A4B: 00 50 3D           add         byte ptr [eax+3Dh],dl
  00403A4E: 40                 inc         eax
  00403A4F: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403A52: 40                 inc         eax
  00403A53: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A56: 40                 inc         eax
  00403A57: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403A5A: 40                 inc         eax
  00403A5B: 00 6C 3D 40        add         byte ptr [ebp+edi+40h],ch
  00403A5F: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403A62: 40                 inc         eax
  00403A63: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403A66: 40                 inc         eax
  00403A67: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403A6A: 40                 inc         eax
  00403A6B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A6E: 40                 inc         eax
  00403A6F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A72: 40                 inc         eax
  00403A73: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A76: 40                 inc         eax
  00403A77: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A7A: 40                 inc         eax
  00403A7B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A7E: 40                 inc         eax
  00403A7F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A82: 40                 inc         eax
  00403A83: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A86: 40                 inc         eax
  00403A87: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A8A: 40                 inc         eax
  00403A8B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A8E: 40                 inc         eax
  00403A8F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A92: 40                 inc         eax
  00403A93: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A96: 40                 inc         eax
  00403A97: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A9A: 40                 inc         eax
  00403A9B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403A9E: 40                 inc         eax
  00403A9F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AA2: 40                 inc         eax
  00403AA3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AA6: 40                 inc         eax
  00403AA7: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AAA: 40                 inc         eax
  00403AAB: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403AAE: 40                 inc         eax
  00403AAF: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403AB2: 40                 inc         eax
  00403AB3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AB6: 40                 inc         eax
  00403AB7: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403ABA: 40                 inc         eax
  00403ABB: 00 04 3C           add         byte ptr [esp+edi],al
  00403ABE: 40                 inc         eax
  00403ABF: 00 B4 3D 40 00 24  add         byte ptr [ebp+edi+3F240040h],dh
            3F
  00403AC6: 40                 inc         eax
  00403AC7: 00 24 3F           add         byte ptr [edi+edi],ah
  00403ACA: 40                 inc         eax
  00403ACB: 00 24 3F           add         byte ptr [edi+edi],ah
  00403ACE: 40                 inc         eax
  00403ACF: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AD2: 40                 inc         eax
  00403AD3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AD6: 40                 inc         eax
  00403AD7: 00 24 3F           add         byte ptr [edi+edi],ah
  00403ADA: 40                 inc         eax
  00403ADB: 00 24 3F           add         byte ptr [edi+edi],ah
  00403ADE: 40                 inc         eax
  00403ADF: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AE2: 40                 inc         eax
  00403AE3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AE6: 40                 inc         eax
  00403AE7: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AEA: 40                 inc         eax
  00403AEB: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AEE: 40                 inc         eax
  00403AEF: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AF2: 40                 inc         eax
  00403AF3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AF6: 40                 inc         eax
  00403AF7: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AFA: 40                 inc         eax
  00403AFB: 00 24 3F           add         byte ptr [edi+edi],ah
  00403AFE: 40                 inc         eax
  00403AFF: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B02: 40                 inc         eax
  00403B03: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B06: 40                 inc         eax
  00403B07: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B0A: 40                 inc         eax
  00403B0B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B0E: 40                 inc         eax
  00403B0F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B12: 40                 inc         eax
  00403B13: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B16: 40                 inc         eax
  00403B17: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B1A: 40                 inc         eax
  00403B1B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B1E: 40                 inc         eax
  00403B1F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B22: 40                 inc         eax
  00403B23: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B26: 40                 inc         eax
  00403B27: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B2A: 40                 inc         eax
  00403B2B: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403B2E: 40                 inc         eax
  00403B2F: 00 2C 3D 40 00 24  add         byte ptr [edi+3F240040h],ch
            3F
  00403B36: 40                 inc         eax
  00403B37: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403B3A: 40                 inc         eax
  00403B3B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B3E: 40                 inc         eax
  00403B3F: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403B42: 40                 inc         eax
  00403B43: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B46: 40                 inc         eax
  00403B47: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B4A: 40                 inc         eax
  00403B4B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B4E: 40                 inc         eax
  00403B4F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B52: 40                 inc         eax
  00403B53: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B56: 40                 inc         eax
  00403B57: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B5A: 40                 inc         eax
  00403B5B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B5E: 40                 inc         eax
  00403B5F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B62: 40                 inc         eax
  00403B63: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B66: 40                 inc         eax
  00403B67: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B6A: 40                 inc         eax
  00403B6B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B6E: 40                 inc         eax
  00403B6F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B72: 40                 inc         eax
  00403B73: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B76: 40                 inc         eax
  00403B77: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B7A: 40                 inc         eax
  00403B7B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B7E: 40                 inc         eax
  00403B7F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B82: 40                 inc         eax
  00403B83: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B86: 40                 inc         eax
  00403B87: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B8A: 40                 inc         eax
  00403B8B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B8E: 40                 inc         eax
  00403B8F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B92: 40                 inc         eax
  00403B93: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B96: 40                 inc         eax
  00403B97: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B9A: 40                 inc         eax
  00403B9B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403B9E: 40                 inc         eax
  00403B9F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403BA2: 40                 inc         eax
  00403BA3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403BA6: 40                 inc         eax
  00403BA7: 00 24 3F           add         byte ptr [edi+edi],ah
  00403BAA: 40                 inc         eax
  00403BAB: 00 24 3F           add         byte ptr [edi+edi],ah
  00403BAE: 40                 inc         eax
  00403BAF: 00 5A 3D           add         byte ptr [edx+3Dh],bl
  00403BB2: 40                 inc         eax
  00403BB3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403BB6: 40                 inc         eax
  00403BB7: 00 50 3D           add         byte ptr [eax+3Dh],dl
  00403BBA: 40                 inc         eax
  00403BBB: 00 8B 7D FC 47 83  add         byte ptr [ebx+8347FC7Dh],cl
  00403BC1: 7D F0              jge         00403BB3
  00403BC3: 00 0F              add         byte ptr [edi],cl
  00403BC5: 84 93 03 00 00 3B  test        byte ptr [ebx+3B000003h],dl
  00403BCB: 5D                 pop         ebp
  00403BCC: 0C 73              or          al,73h
  00403BCE: 09 8B 75 08 C6 04  or          dword ptr [ebx+04C60875h],ecx
  00403BD4: 33 5C 89 F6        xor         ebx,dword ptr [ecx+ecx*4-0Ah]
  00403BD8: 43                 inc         ebx
  00403BD9: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403BDC: 73 0A              jae         00403BE8
  00403BDE: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00403BE1: C6 04 3B 30        mov         byte ptr [ebx+edi],30h
  00403BE5: 8D 76 00           lea         esi,[esi]
  00403BE8: 43                 inc         ebx
  00403BE9: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403BEC: 73 0A              jae         00403BF8
  00403BEE: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00403BF1: C6 04 03 30        mov         byte ptr [ebx+eax],30h
  00403BF5: 8D 76 00           lea         esi,[esi]
  00403BF8: 43                 inc         ebx
  00403BF9: C6 45 E0 30        mov         byte ptr [ebp-20h],30h
  00403BFD: E9 22 03 00 00     jmp         00403F24
  00403C02: 89 F6              mov         esi,esi
  00403C04: 83 7D 18 01        cmp         dword ptr [ebp+18h],1
  00403C08: 0F 84 C2 03 00 00  je          00403FD0
  00403C0E: 83 7D 18 03        cmp         dword ptr [ebp+18h],3
  00403C12: 0F 85 0C 03 00 00  jne         00403F24
  00403C18: 8B 55 FC           mov         edx,dword ptr [ebp-4]
  00403C1B: 83 C2 02           add         edx,2
  00403C1E: 3B 55 14           cmp         edx,dword ptr [ebp+14h]
  00403C21: 0F 83 FD 02 00 00  jae         00403F24
  00403C27: 8B 4D FC           mov         ecx,dword ptr [ebp-4]
  00403C2A: 8B 75 10           mov         esi,dword ptr [ebp+10h]
  00403C2D: 80 7C 0E 01 3F     cmp         byte ptr [esi+ecx+1],3Fh
  00403C32: 0F 85 EC 02 00 00  jne         00403F24
  00403C38: 8A 44 0E 02        mov         al,byte ptr [esi+ecx+2]
  00403C3C: 04 DF              add         al,0DFh
  00403C3E: 0F BE C0           movsx       eax,al
  00403C41: 83 F8 1D           cmp         eax,1Dh
  00403C44: 0F 87 DA 02 00 00  ja          00403F24
  00403C4A: FF 24 85 54 3C 40  jmp         dword ptr [eax*4+00403C54h]
            00
  00403C51: 8D 76 00           lea         esi,[esi]
  00403C54: CC                 int         3
  00403C55: 3C 40              cmp         al,40h
  00403C57: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C5A: 40                 inc         eax
  00403C5B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C5E: 40                 inc         eax
  00403C5F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C62: 40                 inc         eax
  00403C63: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C66: 40                 inc         eax
  00403C67: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C6A: 40                 inc         eax
  00403C6B: 00 CC              add         ah,cl
  00403C6D: 3C 40              cmp         al,40h
  00403C6F: 00 CC              add         ah,cl
  00403C71: 3C 40              cmp         al,40h
  00403C73: 00 CC              add         ah,cl
  00403C75: 3C 40              cmp         al,40h
  00403C77: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C7A: 40                 inc         eax
  00403C7B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C7E: 40                 inc         eax
  00403C7F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C82: 40                 inc         eax
  00403C83: 00 CC              add         ah,cl
  00403C85: 3C 40              cmp         al,40h
  00403C87: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C8A: 40                 inc         eax
  00403C8B: 00 CC              add         ah,cl
  00403C8D: 3C 40              cmp         al,40h
  00403C8F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C92: 40                 inc         eax
  00403C93: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C96: 40                 inc         eax
  00403C97: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C9A: 40                 inc         eax
  00403C9B: 00 24 3F           add         byte ptr [edi+edi],ah
  00403C9E: 40                 inc         eax
  00403C9F: 00 24 3F           add         byte ptr [edi+edi],ah
  00403CA2: 40                 inc         eax
  00403CA3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403CA6: 40                 inc         eax
  00403CA7: 00 24 3F           add         byte ptr [edi+edi],ah
  00403CAA: 40                 inc         eax
  00403CAB: 00 24 3F           add         byte ptr [edi+edi],ah
  00403CAE: 40                 inc         eax
  00403CAF: 00 24 3F           add         byte ptr [edi+edi],ah
  00403CB2: 40                 inc         eax
  00403CB3: 00 24 3F           add         byte ptr [edi+edi],ah
  00403CB6: 40                 inc         eax
  00403CB7: 00 24 3F           add         byte ptr [edi+edi],ah
  00403CBA: 40                 inc         eax
  00403CBB: 00 24 3F           add         byte ptr [edi+edi],ah
  00403CBE: 40                 inc         eax
  00403CBF: 00 CC              add         ah,cl
  00403CC1: 3C 40              cmp         al,40h
  00403CC3: 00 CC              add         ah,cl
  00403CC5: 3C 40              cmp         al,40h
  00403CC7: 00 CC              add         ah,cl
  00403CC9: 3C 40              cmp         al,40h
  00403CCB: 00 89 55 FC 8B 45  add         byte ptr [ecx+458BFC55h],cl
  00403CD1: 10 8A 44 10 02 88  adc         byte ptr [edx+88021044h],cl
  00403CD7: 45                 inc         ebp
  00403CD8: E0 3B              loopne      00403D15
  00403CDA: 5D                 pop         ebp
  00403CDB: 0C 73              or          al,73h
  00403CDD: 0A 8B 55 08 C6 04  or          cl,byte ptr [ebx+04C60855h]
  00403CE3: 13 3F              adc         edi,dword ptr [edi]
  00403CE5: 8D 76 00           lea         esi,[esi]
  00403CE8: 43                 inc         ebx
  00403CE9: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403CEC: 73 0A              jae         00403CF8
  00403CEE: 8B 4D 08           mov         ecx,dword ptr [ebp+8]
  00403CF1: C6 04 0B 5C        mov         byte ptr [ebx+ecx],5Ch
  00403CF5: 8D 76 00           lea         esi,[esi]
  00403CF8: 43                 inc         ebx
  00403CF9: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403CFC: 0F 83 AA 00 00 00  jae         00403DAC
  00403D02: 8B 75 08           mov         esi,dword ptr [ebp+8]
  00403D05: C6 04 33 3F        mov         byte ptr [ebx+esi],3Fh
  00403D09: E9 9E 00 00 00     jmp         00403DAC
  00403D0E: 89 F6              mov         esi,esi
  00403D10: B0 61              mov         al,61h
  00403D12: EB 25              jmp         00403D39
  00403D14: B0 62              mov         al,62h
  00403D16: EB 21              jmp         00403D39
  00403D18: B0 66              mov         al,66h
  00403D1A: EB 1D              jmp         00403D39
  00403D1C: B0 6E              mov         al,6Eh
  00403D1E: EB 0F              jmp         00403D2F
  00403D20: B0 72              mov         al,72h
  00403D22: EB 0B              jmp         00403D2F
  00403D24: B0 74              mov         al,74h
  00403D26: EB 07              jmp         00403D2F
  00403D28: B0 76              mov         al,76h
  00403D2A: EB 0D              jmp         00403D39
  00403D2C: 8A 45 E0           mov         al,byte ptr [ebp-20h]
  00403D2F: 83 7D 18 01        cmp         dword ptr [ebp+18h],1
  00403D33: 0F 84 97 02 00 00  je          00403FD0
  00403D39: 8B 7D FC           mov         edi,dword ptr [ebp-4]
  00403D3C: 47                 inc         edi
  00403D3D: 83 7D F0 00        cmp         dword ptr [ebp-10h],0
  00403D41: 0F 84 16 02 00 00  je          00403F5D
  00403D47: 88 45 E0           mov         byte ptr [ebp-20h],al
  00403D4A: E9 FD 01 00 00     jmp         00403F4C
  00403D4F: 90                 nop
  00403D50: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  00403D54: 0F 85 CA 01 00 00  jne         00403F24
  00403D5A: 83 7D 18 01        cmp         dword ptr [ebp+18h],1
  00403D5E: 0F 84 6C 02 00 00  je          00403FD0
  00403D64: E9 BB 01 00 00     jmp         00403F24
  00403D69: 8D 76 00           lea         esi,[esi]
  00403D6C: 83 7D 18 01        cmp         dword ptr [ebp+18h],1
  00403D70: 0F 84 5A 02 00 00  je          00403FD0
  00403D76: 83 7D 18 02        cmp         dword ptr [ebp+18h],2
  00403D7A: 0F 85 A4 01 00 00  jne         00403F24
  00403D80: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403D83: 73 07              jae         00403D8C
  00403D85: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00403D88: C6 04 3B 27        mov         byte ptr [ebx+edi],27h
  00403D8C: 43                 inc         ebx
  00403D8D: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403D90: 73 0A              jae         00403D9C
  00403D92: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00403D95: C6 04 03 5C        mov         byte ptr [ebx+eax],5Ch
  00403D99: 8D 76 00           lea         esi,[esi]
  00403D9C: 43                 inc         ebx
  00403D9D: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403DA0: 73 0A              jae         00403DAC
  00403DA2: 8B 55 08           mov         edx,dword ptr [ebp+8]
  00403DA5: C6 04 13 27        mov         byte ptr [ebx+edx],27h
  00403DA9: 8D 76 00           lea         esi,[esi]
  00403DAC: 43                 inc         ebx
  00403DAD: E9 72 01 00 00     jmp         00403F24
  00403DB2: 89 F6              mov         esi,esi
  00403DB4: B9 01 00 00 00     mov         ecx,1
  00403DB9: 85 C9              test        ecx,ecx
  00403DBB: 74 27              je          00403DE4
  00403DBD: 89 4D DC           mov         dword ptr [ebp-24h],ecx
  00403DC0: 83 C4 F4           add         esp,0FFFFFFF4h
  00403DC3: 0F B6 45 E0        movzx       eax,byte ptr [ebp-20h]
  00403DC7: 50                 push        eax
  00403DC8: E8 83 14 00 00     call        00405250
  00403DCD: 83 C4 10           add         esp,10h
  00403DD0: 85 C0              test        eax,eax
  00403DD2: 0F 95 C0           setne       al
  00403DD5: 0F B6 D0           movzx       edx,al
  00403DD8: 89 55 D8           mov         dword ptr [ebp-28h],edx
  00403DDB: 8B 7D FC           mov         edi,dword ptr [ebp-4]
  00403DDE: 47                 inc         edi
  00403DDF: E9 A5 00 00 00     jmp         00403E89
  00403DE4: C7 45 DC 00 00 00  mov         dword ptr [ebp-24h],0
            00
  00403DEB: C7 45 D8 01 00 00  mov         dword ptr [ebp-28h],1
            00
  00403DF2: 83 7D 14 FF        cmp         dword ptr [ebp+14h],0FFFFFFFFh
  00403DF6: 75 13              jne         00403E0B
  00403DF8: 8B 7D 10           mov         edi,dword ptr [ebp+10h]
  00403DFB: B0 00              mov         al,0
  00403DFD: FC                 cld
  00403DFE: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  00403E03: F2 AE              repne scas  byte ptr es:[edi]
  00403E05: F7 D1              not         ecx
  00403E07: 49                 dec         ecx
  00403E08: 89 4D 14           mov         dword ptr [ebp+14h],ecx
  00403E0B: 8B 4D 10           mov         ecx,dword ptr [ebp+10h]
  00403E0E: 8B 75 FC           mov         esi,dword ptr [ebp-4]
  00403E11: 66 0F BE 14 0E     movsx       dx,byte ptr [esi+ecx]
  00403E16: 66 85 D2           test        dx,dx
  00403E19: 0F 95 C0           setne       al
  00403E1C: 0F B6 F0           movzx       esi,al
  00403E1F: 8B 7D FC           mov         edi,dword ptr [ebp-4]
  00403E22: 47                 inc         edi
  00403E23: 85 F6              test        esi,esi
  00403E25: 74 62              je          00403E89
  00403E27: 83 FE FF           cmp         esi,0FFFFFFFFh
  00403E2A: 75 0C              jne         00403E38
  00403E2C: C7 45 D8 00 00 00  mov         dword ptr [ebp-28h],0
            00
  00403E33: EB 54              jmp         00403E89
  00403E35: 8D 76 00           lea         esi,[esi]
  00403E38: 83 FE FE           cmp         esi,0FFFFFFFEh
  00403E3B: 75 2F              jne         00403E6C
  00403E3D: C7 45 D8 00 00 00  mov         dword ptr [ebp-28h],0
            00
  00403E44: 8B 45 14           mov         eax,dword ptr [ebp+14h]
  00403E47: 39 45 FC           cmp         dword ptr [ebp-4],eax
  00403E4A: 73 3D              jae         00403E89
  00403E4C: 80 7D D7 00        cmp         byte ptr [ebp-29h],0
  00403E50: 74 37              je          00403E89
  00403E52: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  00403E55: 8D 76 00           lea         esi,[esi]
  00403E58: 40                 inc         eax
  00403E59: FF 45 DC           inc         dword ptr [ebp-24h]
  00403E5C: 3B 45 14           cmp         eax,dword ptr [ebp+14h]
  00403E5F: 73 28              jae         00403E89
  00403E61: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  00403E64: 80 3C 02 00        cmp         byte ptr [edx+eax],0
  00403E68: 75 EE              jne         00403E58
  00403E6A: EB 1D              jmp         00403E89
  00403E6C: 83 C4 F4           add         esp,0FFFFFFF4h
  00403E6F: 0F B6 C2           movzx       eax,dl
  00403E72: 50                 push        eax
  00403E73: E8 D8 13 00 00     call        00405250
  00403E78: 83 C4 10           add         esp,10h
  00403E7B: 85 C0              test        eax,eax
  00403E7D: 75 07              jne         00403E86
  00403E7F: C7 45 D8 00 00 00  mov         dword ptr [ebp-28h],0
            00
  00403E86: 89 75 DC           mov         dword ptr [ebp-24h],esi
  00403E89: 83 7D DC 01        cmp         dword ptr [ebp-24h],1
  00403E8D: 77 14              ja          00403EA3
  00403E8F: 83 7D F0 00        cmp         dword ptr [ebp-10h],0
  00403E93: 0F 84 C4 00 00 00  je          00403F5D
  00403E99: 83 7D D8 00        cmp         dword ptr [ebp-28h],0
  00403E9D: 0F 85 81 00 00 00  jne         00403F24
  00403EA3: 8B 75 FC           mov         esi,dword ptr [ebp-4]
  00403EA6: 03 75 DC           add         esi,dword ptr [ebp-24h]
  00403EA9: 8B 55 FC           mov         edx,dword ptr [ebp-4]
  00403EAC: 42                 inc         edx
  00403EAD: 89 D1              mov         ecx,edx
  00403EAF: 90                 nop
  00403EB0: 83 7D F0 00        cmp         dword ptr [ebp-10h],0
  00403EB4: 74 49              je          00403EFF
  00403EB6: 83 7D D8 00        cmp         dword ptr [ebp-28h],0
  00403EBA: 75 43              jne         00403EFF
  00403EBC: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403EBF: 73 07              jae         00403EC8
  00403EC1: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00403EC4: C6 04 3B 5C        mov         byte ptr [ebx+edi],5Ch
  00403EC8: 43                 inc         ebx
  00403EC9: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403ECC: 73 0E              jae         00403EDC
  00403ECE: 8A 45 E0           mov         al,byte ptr [ebp-20h]
  00403ED1: C0 E8 06           shr         al,6
  00403ED4: 0C 30              or          al,30h
  00403ED6: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00403ED9: 88 04 3B           mov         byte ptr [ebx+edi],al
  00403EDC: 43                 inc         ebx
  00403EDD: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403EE0: 73 12              jae         00403EF4
  00403EE2: 8A 45 E0           mov         al,byte ptr [ebp-20h]
  00403EE5: C0 E8 03           shr         al,3
  00403EE8: 24 07              and         al,7
  00403EEA: 0C 30              or          al,30h
  00403EEC: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00403EEF: 88 04 3B           mov         byte ptr [ebx+edi],al
  00403EF2: 89 F6              mov         esi,esi
  00403EF4: 43                 inc         ebx
  00403EF5: 8A 45 E0           mov         al,byte ptr [ebp-20h]
  00403EF8: 24 07              and         al,7
  00403EFA: 04 30              add         al,30h
  00403EFC: 88 45 E0           mov         byte ptr [ebp-20h],al
  00403EFF: 89 CF              mov         edi,ecx
  00403F01: 39 FE              cmp         esi,edi
  00403F03: 76 58              jbe         00403F5D
  00403F05: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403F08: 73 0A              jae         00403F14
  00403F0A: 8A 45 E0           mov         al,byte ptr [ebp-20h]
  00403F0D: 8B 4D 08           mov         ecx,dword ptr [ebp+8]
  00403F10: 88 04 0B           mov         byte ptr [ebx+ecx],al
  00403F13: 90                 nop
  00403F14: 43                 inc         ebx
  00403F15: 42                 inc         edx
  00403F16: 89 D1              mov         ecx,edx
  00403F18: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  00403F1B: 8A 44 10 FF        mov         al,byte ptr [eax+edx-1]
  00403F1F: 88 45 E0           mov         byte ptr [ebp-20h],al
  00403F22: EB 8C              jmp         00403EB0
  00403F24: 8B 7D FC           mov         edi,dword ptr [ebp-4]
  00403F27: 47                 inc         edi
  00403F28: 83 7D F0 00        cmp         dword ptr [ebp-10h],0
  00403F2C: 74 2F              je          00403F5D
  00403F2E: 8A 45 E0           mov         al,byte ptr [ebp-20h]
  00403F31: C0 E8 05           shr         al,5
  00403F34: 0F B6 D0           movzx       edx,al
  00403F37: 8B 45 1C           mov         eax,dword ptr [ebp+1Ch]
  00403F3A: 83 C0 04           add         eax,4
  00403F3D: 8A 4D E0           mov         cl,byte ptr [ebp-20h]
  00403F40: 83 E1 1F           and         ecx,1Fh
  00403F43: 8B 04 90           mov         eax,dword ptr [eax+edx*4]
  00403F46: D3 F8              sar         eax,cl
  00403F48: A8 01              test        al,1
  00403F4A: 74 11              je          00403F5D
  00403F4C: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403F4F: 73 07              jae         00403F58
  00403F51: 8B 55 08           mov         edx,dword ptr [ebp+8]
  00403F54: C6 04 13 5C        mov         byte ptr [ebx+edx],5Ch
  00403F58: 43                 inc         ebx
  00403F59: 8B 7D FC           mov         edi,dword ptr [ebp-4]
  00403F5C: 47                 inc         edi
  00403F5D: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403F60: 73 0A              jae         00403F6C
  00403F62: 8A 4D E0           mov         cl,byte ptr [ebp-20h]
  00403F65: 8B 75 08           mov         esi,dword ptr [ebp+8]
  00403F68: 88 0C 33           mov         byte ptr [ebx+esi],cl
  00403F6B: 90                 nop
  00403F6C: 43                 inc         ebx
  00403F6D: 89 7D FC           mov         dword ptr [ebp-4],edi
  00403F70: 83 7D 14 FF        cmp         dword ptr [ebp+14h],0FFFFFFFFh
  00403F74: 75 12              jne         00403F88
  00403F76: 8B 7D 10           mov         edi,dword ptr [ebp+10h]
  00403F79: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  00403F7C: 80 3C 38 00        cmp         byte ptr [eax+edi],0
  00403F80: 0F 85 DA F9 FF FF  jne         00403960
  00403F86: EB 0C              jmp         00403F94
  00403F88: 8B 55 14           mov         edx,dword ptr [ebp+14h]
  00403F8B: 39 55 FC           cmp         dword ptr [ebp-4],edx
  00403F8E: 0F 85 CC F9 FF FF  jne         00403960
  00403F94: 83 7D F8 00        cmp         dword ptr [ebp-8],0
  00403F98: 74 26              je          00403FC0
  00403F9A: 8B 4D F8           mov         ecx,dword ptr [ebp-8]
  00403F9D: 80 39 00           cmp         byte ptr [ecx],0
  00403FA0: 74 1E              je          00403FC0
  00403FA2: 89 F6              mov         esi,esi
  00403FA4: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403FA7: 73 0B              jae         00403FB4
  00403FA9: 8B 75 F8           mov         esi,dword ptr [ebp-8]
  00403FAC: 8A 06              mov         al,byte ptr [esi]
  00403FAE: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00403FB1: 88 04 3B           mov         byte ptr [ebx+edi],al
  00403FB4: 43                 inc         ebx
  00403FB5: FF 45 F8           inc         dword ptr [ebp-8]
  00403FB8: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  00403FBB: 80 38 00           cmp         byte ptr [eax],0
  00403FBE: 75 E4              jne         00403FA4
  00403FC0: 3B 5D 0C           cmp         ebx,dword ptr [ebp+0Ch]
  00403FC3: 73 07              jae         00403FCC
  00403FC5: 8B 55 08           mov         edx,dword ptr [ebp+8]
  00403FC8: C6 04 13 00        mov         byte ptr [ebx+edx],0
  00403FCC: 89 D8              mov         eax,ebx
  00403FCE: EB 0C              jmp         00403FDC
  00403FD0: C7 45 18 02 00 00  mov         dword ptr [ebp+18h],2
            00
  00403FD7: E9 75 F8 FF FF     jmp         00403851
  00403FDC: 8D 65 B8           lea         esp,[ebp-48h]
  00403FDF: 5B                 pop         ebx
  00403FE0: 5E                 pop         esi
  00403FE1: 5F                 pop         edi
  00403FE2: C9                 leave
  00403FE3: C3                 ret
  00403FE4: 55                 push        ebp
  00403FE5: 89 E5              mov         ebp,esp
  00403FE7: 83 EC 08           sub         esp,8
  00403FEA: 8B 45 18           mov         eax,dword ptr [ebp+18h]
  00403FED: 85 C0              test        eax,eax
  00403FEF: 75 05              jne         00403FF6
  00403FF1: B8 90 71 40 00     mov         eax,407190h
  00403FF6: 83 C4 F8           add         esp,0FFFFFFF8h
  00403FF9: 50                 push        eax
  00403FFA: FF 30              push        dword ptr [eax]
  00403FFC: FF 75 14           push        dword ptr [ebp+14h]
  00403FFF: FF 75 10           push        dword ptr [ebp+10h]
  00404002: FF 75 0C           push        dword ptr [ebp+0Ch]
  00404005: FF 75 08           push        dword ptr [ebp+8]
  00404008: E8 3B F8 FF FF     call        00403848
  0040400D: C9                 leave
  0040400E: C3                 ret
  0040400F: 90                 nop
  00404010: 55                 push        ebp
  00404011: 89 E5              mov         ebp,esp
  00404013: 83 EC 0C           sub         esp,0Ch
  00404016: 57                 push        edi
  00404017: 56                 push        esi
  00404018: 53                 push        ebx
  00404019: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  0040401C: 85 FF              test        edi,edi
  0040401E: 7D 08              jge         00404028
  00404020: E8 F3 11 00 00     call        00405218
  00404025: 8D 76 00           lea         esi,[esi]
  00404028: 39 3D 1C 60 40 00  cmp         dword ptr ds:[0040601Ch],edi
  0040402E: 0F 87 85 00 00 00  ja          004040B9
  00404034: 8D 5F 01           lea         ebx,[edi+1]
  00404037: 8D 34 DD 00 00 00  lea         esi,[ebx*8+00000000h]
            00
  0040403E: 89 F0              mov         eax,esi
  00404040: C1 E8 03           shr         eax,3
  00404043: 39 C3              cmp         ebx,eax
  00404045: 74 05              je          0040404C
  00404047: E8 44 09 00 00     call        00404990
  0040404C: 81 3D 28 60 40 00  cmp         dword ptr ds:[00406028h],406020h
            20 60 40 00
  00404056: 75 25              jne         0040407D
  00404058: 83 C4 F4           add         esp,0FFFFFFF4h
  0040405B: 6A 08              push        8
  0040405D: E8 62 09 00 00     call        004049C4
  00404062: 89 C1              mov         ecx,eax
  00404064: 89 0D 28 60 40 00  mov         dword ptr ds:[00406028h],ecx
  0040406A: A1 20 60 40 00     mov         eax,dword ptr ds:[00406020h]
  0040406F: 8B 15 24 60 40 00  mov         edx,dword ptr ds:[00406024h]
  00404075: 89 01              mov         dword ptr [ecx],eax
  00404077: 89 51 04           mov         dword ptr [ecx+4],edx
  0040407A: 83 C4 10           add         esp,10h
  0040407D: 83 C4 F8           add         esp,0FFFFFFF8h
  00404080: 56                 push        esi
  00404081: FF 35 28 60 40 00  push        dword ptr ds:[00406028h]
  00404087: E8 5C 09 00 00     call        004049E8
  0040408C: 89 C1              mov         ecx,eax
  0040408E: 89 0D 28 60 40 00  mov         dword ptr ds:[00406028h],ecx
  00404094: 8B 15 1C 60 40 00  mov         edx,dword ptr ds:[0040601Ch]
  0040409A: 89 D8              mov         eax,ebx
  0040409C: 29 D0              sub         eax,edx
  0040409E: 83 C4 FC           add         esp,0FFFFFFFCh
  004040A1: C1 E0 03           shl         eax,3
  004040A4: 50                 push        eax
  004040A5: 6A 00              push        0
  004040A7: 8D 14 D1           lea         edx,[ecx+edx*8]
  004040AA: 52                 push        edx
  004040AB: E8 98 11 00 00     call        00405248
  004040B0: 89 1D 1C 60 40 00  mov         dword ptr ds:[0040601Ch],ebx
  004040B6: 83 C4 20           add         esp,20h
  004040B9: A1 28 60 40 00     mov         eax,dword ptr ds:[00406028h]
  004040BE: 8B 34 F8           mov         esi,dword ptr [eax+edi*8]
  004040C1: 8B 5C F8 04        mov         ebx,dword ptr [eax+edi*8+4]
  004040C5: 83 C4 F4           add         esp,0FFFFFFF4h
  004040C8: 8B 45 14           mov         eax,dword ptr [ebp+14h]
  004040CB: 50                 push        eax
  004040CC: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  004040CF: 50                 push        eax
  004040D0: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  004040D3: 50                 push        eax
  004040D4: 56                 push        esi
  004040D5: 53                 push        ebx
  004040D6: E8 09 FF FF FF     call        00403FE4
  004040DB: 89 C2              mov         edx,eax
  004040DD: 83 C4 20           add         esp,20h
  004040E0: 39 D6              cmp         esi,edx
  004040E2: 77 44              ja          00404128
  004040E4: A1 28 60 40 00     mov         eax,dword ptr ds:[00406028h]
  004040E9: 8D 72 01           lea         esi,[edx+1]
  004040EC: 89 34 F8           mov         dword ptr [eax+edi*8],esi
  004040EF: 83 C4 F8           add         esp,0FFFFFFF8h
  004040F2: 56                 push        esi
  004040F3: 31 C0              xor         eax,eax
  004040F5: 81 FB 90 70 40 00  cmp         ebx,407090h
  004040FB: 74 02              je          004040FF
  004040FD: 89 D8              mov         eax,ebx
  004040FF: 50                 push        eax
  00404100: E8 E3 08 00 00     call        004049E8
  00404105: 89 C2              mov         edx,eax
  00404107: A1 28 60 40 00     mov         eax,dword ptr ds:[00406028h]
  0040410C: 89 D3              mov         ebx,edx
  0040410E: 89 5C F8 04        mov         dword ptr [eax+edi*8+4],ebx
  00404112: 83 C4 F4           add         esp,0FFFFFFF4h
  00404115: 8B 45 14           mov         eax,dword ptr [ebp+14h]
  00404118: 50                 push        eax
  00404119: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  0040411C: 50                 push        eax
  0040411D: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  00404120: 50                 push        eax
  00404121: 56                 push        esi
  00404122: 53                 push        ebx
  00404123: E8 BC FE FF FF     call        00403FE4
  00404128: 89 D8              mov         eax,ebx
  0040412A: 8D 65 E8           lea         esp,[ebp-18h]
  0040412D: 5B                 pop         ebx
  0040412E: 5E                 pop         esi
  0040412F: 5F                 pop         edi
  00404130: C9                 leave
  00404131: C3                 ret
  00404132: 89 F6              mov         esi,esi
  00404134: 55                 push        ebp
  00404135: 89 E5              mov         ebp,esp
  00404137: 83 EC 08           sub         esp,8
  0040413A: 68 90 71 40 00     push        407190h
  0040413F: 6A FF              push        0FFFFFFFFh
  00404141: FF 75 0C           push        dword ptr [ebp+0Ch]
  00404144: FF 75 08           push        dword ptr [ebp+8]
  00404147: E8 C4 FE FF FF     call        00404010
  0040414C: C9                 leave
  0040414D: C3                 ret
  0040414E: 89 F6              mov         esi,esi
  00404150: 55                 push        ebp
  00404151: 89 E5              mov         ebp,esp
  00404153: 83 EC 08           sub         esp,8
  00404156: 83 C4 F8           add         esp,0FFFFFFF8h
  00404159: FF 75 08           push        dword ptr [ebp+8]
  0040415C: 6A 00              push        0
  0040415E: E8 D1 FF FF FF     call        00404134
  00404163: C9                 leave
  00404164: C3                 ret
  00404165: 8D 76 00           lea         esi,[esi]
  00404168: 55                 push        ebp
  00404169: 89 E5              mov         ebp,esp
  0040416B: 83 EC 40           sub         esp,40h
  0040416E: 57                 push        edi
  0040416F: 56                 push        esi
  00404170: 8B 55 08           mov         edx,dword ptr [ebp+8]
  00404173: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  00404176: 89 45 D0           mov         dword ptr [ebp-30h],eax
  00404179: 8D 7D D4           lea         edi,[ebp-2Ch]
  0040417C: 31 C0              xor         eax,eax
  0040417E: FC                 cld
  0040417F: B9 08 00 00 00     mov         ecx,8
  00404184: F3 AB              rep stos    dword ptr es:[edi]
  00404186: 89 D7              mov         edi,edx
  00404188: 8D 75 D0           lea         esi,[ebp-30h]
  0040418B: FC                 cld
  0040418C: B9 09 00 00 00     mov         ecx,9
  00404191: F3 A5              rep movs    dword ptr es:[edi],dword ptr [esi]
  00404193: 89 D0              mov         eax,edx
  00404195: 5E                 pop         esi
  00404196: 5F                 pop         edi
  00404197: C9                 leave
  00404198: C2 04 00           ret         4
  0040419B: 90                 nop
  0040419C: 55                 push        ebp
  0040419D: 89 E5              mov         ebp,esp
  0040419F: 83 EC 3C           sub         esp,3Ch
  004041A2: 57                 push        edi
  004041A3: 56                 push        esi
  004041A4: 53                 push        ebx
  004041A5: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  004041A8: 8B 75 10           mov         esi,dword ptr [ebp+10h]
  004041AB: 8D 5D D0           lea         ebx,[ebp-30h]
  004041AE: 83 C4 F8           add         esp,0FFFFFFF8h
  004041B1: FF 75 0C           push        dword ptr [ebp+0Ch]
  004041B4: 53                 push        ebx
  004041B5: E8 AE FF FF FF     call        00404168
  004041BA: 83 C4 FC           add         esp,0FFFFFFFCh
  004041BD: 53                 push        ebx
  004041BE: 6A FF              push        0FFFFFFFFh
  004041C0: 56                 push        esi
  004041C1: 57                 push        edi
  004041C2: E8 49 FE FF FF     call        00404010
  004041C7: 8D 65 B8           lea         esp,[ebp-48h]
  004041CA: 5B                 pop         ebx
  004041CB: 5E                 pop         esi
  004041CC: 5F                 pop         edi
  004041CD: C9                 leave
  004041CE: C3                 ret
  004041CF: 90                 nop
  004041D0: 55                 push        ebp
  004041D1: 89 E5              mov         ebp,esp
  004041D3: 83 EC 3C           sub         esp,3Ch
  004041D6: 57                 push        edi
  004041D7: 56                 push        esi
  004041D8: 53                 push        ebx
  004041D9: 8B 7D 10           mov         edi,dword ptr [ebp+10h]
  004041DC: 8B 75 14           mov         esi,dword ptr [ebp+14h]
  004041DF: 8D 5D D0           lea         ebx,[ebp-30h]
  004041E2: 83 C4 F8           add         esp,0FFFFFFF8h
  004041E5: FF 75 0C           push        dword ptr [ebp+0Ch]
  004041E8: 53                 push        ebx
  004041E9: E8 7A FF FF FF     call        00404168
  004041EE: 83 C4 FC           add         esp,0FFFFFFFCh
  004041F1: 53                 push        ebx
  004041F2: 56                 push        esi
  004041F3: 57                 push        edi
  004041F4: 8B 45 08           mov         eax,dword ptr [ebp+8]
  004041F7: 50                 push        eax
  004041F8: E8 13 FE FF FF     call        00404010
  004041FD: 8D 65 B8           lea         esp,[ebp-48h]
  00404200: 5B                 pop         ebx
  00404201: 5E                 pop         esi
  00404202: 5F                 pop         edi
  00404203: C9                 leave
  00404204: C3                 ret
  00404205: 8D 76 00           lea         esi,[esi]
  00404208: 55                 push        ebp
  00404209: 89 E5              mov         ebp,esp
  0040420B: 83 EC 08           sub         esp,8
  0040420E: 83 C4 FC           add         esp,0FFFFFFFCh
  00404211: FF 75 0C           push        dword ptr [ebp+0Ch]
  00404214: FF 75 08           push        dword ptr [ebp+8]
  00404217: 6A 00              push        0
  00404219: E8 7E FF FF FF     call        0040419C
  0040421E: C9                 leave
  0040421F: C3                 ret
  00404220: 55                 push        ebp
  00404221: 89 E5              mov         ebp,esp
  00404223: 83 EC 3C           sub         esp,3Ch
  00404226: 57                 push        edi
  00404227: 56                 push        esi
  00404228: 53                 push        ebx
  00404229: 8B 5D 08           mov         ebx,dword ptr [ebp+8]
  0040422C: 0F BE 45 0C        movsx       eax,byte ptr [ebp+0Ch]
  00404230: 8D 7D D0           lea         edi,[ebp-30h]
  00404233: BE 90 71 40 00     mov         esi,407190h
  00404238: FC                 cld
  00404239: B9 09 00 00 00     mov         ecx,9
  0040423E: F3 A5              rep movs    dword ptr es:[edi],dword ptr [esi]
  00404240: 83 C4 FC           add         esp,0FFFFFFFCh
  00404243: 6A 01              push        1
  00404245: 50                 push        eax
  00404246: 8D 75 D0           lea         esi,[ebp-30h]
  00404249: 56                 push        esi
  0040424A: E8 91 F5 FF FF     call        004037E0
  0040424F: 56                 push        esi
  00404250: 6A FF              push        0FFFFFFFFh
  00404252: 53                 push        ebx
  00404253: 6A 00              push        0
  00404255: E8 B6 FD FF FF     call        00404010
  0040425A: 8D 65 B8           lea         esp,[ebp-48h]
  0040425D: 5B                 pop         ebx
  0040425E: 5E                 pop         esi
  0040425F: 5F                 pop         edi
  00404260: C9                 leave
  00404261: C3                 ret
  00404262: 89 F6              mov         esi,esi
  00404264: 55                 push        ebp
  00404265: 89 E5              mov         ebp,esp
  00404267: 83 EC 08           sub         esp,8
  0040426A: 83 C4 F8           add         esp,0FFFFFFF8h
  0040426D: 6A 3A              push        3Ah
  0040426F: FF 75 08           push        dword ptr [ebp+8]
  00404272: E8 A9 FF FF FF     call        00404220
  00404277: C9                 leave
  00404278: C3                 ret
  00404279: 8D 76 00           lea         esi,[esi]
  0040427C: 55                 push        ebp
  0040427D: 89 E5              mov         ebp,esp
  0040427F: 83 EC 1C           sub         esp,1Ch
  00404282: 57                 push        edi
  00404283: 56                 push        esi
  00404284: 53                 push        ebx
  00404285: 8B 5D 08           mov         ebx,dword ptr [ebp+8]
  00404288: 8B 75 0C           mov         esi,dword ptr [ebp+0Ch]
  0040428B: 8B 0B              mov         ecx,dword ptr [ebx]
  0040428D: 89 CF              mov         edi,ecx
  0040428F: 0F AF FE           imul        edi,esi
  00404292: 89 F8              mov         eax,edi
  00404294: 31 D2              xor         edx,edx
  00404296: F7 F6              div         eax,esi
  00404298: 39 C1              cmp         ecx,eax
  0040429A: 75 08              jne         004042A4
  0040429C: 89 3B              mov         dword ptr [ebx],edi
  0040429E: 31 C0              xor         eax,eax
  004042A0: EB 07              jmp         004042A9
  004042A2: 89 F6              mov         esi,esi
  004042A4: B8 01 00 00 00     mov         eax,1
  004042A9: 5B                 pop         ebx
  004042AA: 5E                 pop         esi
  004042AB: 5F                 pop         edi
  004042AC: C9                 leave
  004042AD: C3                 ret
  004042AE: 89 F6              mov         esi,esi
  004042B0: 55                 push        ebp
  004042B1: 89 E5              mov         ebp,esp
  004042B3: 83 EC 0C           sub         esp,0Ch
  004042B6: 57                 push        edi
  004042B7: 56                 push        esi
  004042B8: 53                 push        ebx
  004042B9: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  004042BC: 8B 75 0C           mov         esi,dword ptr [ebp+0Ch]
  004042BF: 8B 5D 10           mov         ebx,dword ptr [ebp+10h]
  004042C2: 4B                 dec         ebx
  004042C3: 83 FB FF           cmp         ebx,0FFFFFFFFh
  004042C6: 74 1D              je          004042E5
  004042C8: 83 C4 F8           add         esp,0FFFFFFF8h
  004042CB: 56                 push        esi
  004042CC: 57                 push        edi
  004042CD: E8 AA FF FF FF     call        0040427C
  004042D2: 83 C4 10           add         esp,10h
  004042D5: 85 C0              test        eax,eax
  004042D7: 74 07              je          004042E0
  004042D9: B8 01 00 00 00     mov         eax,1
  004042DE: EB 07              jmp         004042E7
  004042E0: 83 EB 01           sub         ebx,1
  004042E3: 73 E3              jae         004042C8
  004042E5: 31 C0              xor         eax,eax
  004042E7: 8D 65 E8           lea         esp,[ebp-18h]
  004042EA: 5B                 pop         ebx
  004042EB: 5E                 pop         esi
  004042EC: 5F                 pop         edi
  004042ED: C9                 leave
  004042EE: C3                 ret
  004042EF: 78 73              js          00404364
  004042F1: 74 72              je          00404365
  004042F3: 74 6F              je          00404364
  004042F5: 6C                 ins         byte ptr es:[edi],dx
  004042F6: 2E 63 00           arpl        word ptr cs:[eax],ax
  004042F9: 8D 76 00           lea         esi,[esi]
  004042FC: 30 20              xor         byte ptr [eax],ah
  004042FE: 3C 3D              cmp         al,3Dh
  00404300: 20 73 74           and         byte ptr [ebx+74h],dh
  00404303: 72 74              jb          00404379
  00404305: 6F                 outs        dx,dword ptr [esi]
  00404306: 6C                 ins         byte ptr es:[edi],dx
  00404307: 5F                 pop         edi
  00404308: 62 61 73           bound       esp,qword ptr [ecx+73h]
  0040430B: 65 20 26           and         byte ptr gs:[esi],ah
  0040430E: 26 20 73 74        and         byte ptr es:[ebx+74h],dh
  00404312: 72 74              jb          00404388
  00404314: 6F                 outs        dx,dword ptr [esi]
  00404315: 6C                 ins         byte ptr es:[edi],dx
  00404316: 5F                 pop         edi
  00404317: 62 61 73           bound       esp,qword ptr [ecx+73h]
  0040431A: 65 20 3C 3D 20 33  and         byte ptr gs:[edi+00363320h],bh
            36 00
  00404322: 89 F6              mov         esi,esi
  00404324: 55                 push        ebp
  00404325: 89 E5              mov         ebp,esp
  00404327: 83 EC 1C           sub         esp,1Ch
  0040432A: 57                 push        edi
  0040432B: 56                 push        esi
  0040432C: 53                 push        ebx
  0040432D: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  00404330: 83 7D 10 24        cmp         dword ptr [ebp+10h],24h
  00404334: 76 16              jbe         0040434C
  00404336: 83 C4 FC           add         esp,0FFFFFFFCh
  00404339: 6A 7F              push        7Fh
  0040433B: 68 EF 42 40 00     push        4042EFh
  00404340: 68 FC 42 40 00     push        4042FCh
  00404345: E8 26 0F 00 00     call        00405270
  0040434A: 89 F6              mov         esi,esi
  0040434C: 8B 75 0C           mov         esi,dword ptr [ebp+0Ch]
  0040434F: 85 F6              test        esi,esi
  00404351: 75 03              jne         00404356
  00404353: 8D 75 FC           lea         esi,[ebp-4]
  00404356: 89 FB              mov         ebx,edi
  00404358: EB 03              jmp         0040435D
  0040435A: 89 F6              mov         esi,esi
  0040435C: 43                 inc         ebx
  0040435D: 83 C4 F4           add         esp,0FFFFFFF4h
  00404360: 0F B6 03           movzx       eax,byte ptr [ebx]
  00404363: 50                 push        eax
  00404364: E8 FF 0E 00 00     call        00405268
  00404369: 83 C4 10           add         esp,10h
  0040436C: 85 C0              test        eax,eax
  0040436E: 75 EC              jne         0040435C
  00404370: 80 3B 2D           cmp         byte ptr [ebx],2Dh
  00404373: 75 0B              jne         00404380
  00404375: B8 01 00 00 00     mov         eax,1
  0040437A: E9 69 02 00 00     jmp         004045E8
  0040437F: 90                 nop
  00404380: E8 4B 0E 00 00     call        004051D0
  00404385: C7 00 00 00 00 00  mov         dword ptr [eax],0
  0040438B: 83 C4 FC           add         esp,0FFFFFFFCh
  0040438E: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  00404391: 50                 push        eax
  00404392: 56                 push        esi
  00404393: 57                 push        edi
  00404394: E8 C7 0E 00 00     call        00405260
  00404399: 89 45 F8           mov         dword ptr [ebp-8],eax
  0040439C: E8 2F 0E 00 00     call        004051D0
  004043A1: 83 C4 10           add         esp,10h
  004043A4: 83 38 00           cmp         dword ptr [eax],0
  004043A7: 0F 85 27 02 00 00  jne         004045D4
  004043AD: 8B 06              mov         eax,dword ptr [esi]
  004043AF: 39 F8              cmp         eax,edi
  004043B1: 75 29              jne         004043DC
  004043B3: 83 7D 18 00        cmp         dword ptr [ebp+18h],0
  004043B7: 74 BC              je          00404375
  004043B9: 80 38 00           cmp         byte ptr [eax],0
  004043BC: 74 B7              je          00404375
  004043BE: 83 C4 F8           add         esp,0FFFFFFF8h
  004043C1: 0F BE 00           movsx       eax,byte ptr [eax]
  004043C4: 50                 push        eax
  004043C5: 8B 55 18           mov         edx,dword ptr [ebp+18h]
  004043C8: 52                 push        edx
  004043C9: E8 8A 0E 00 00     call        00405258
  004043CE: 83 C4 10           add         esp,10h
  004043D1: 85 C0              test        eax,eax
  004043D3: 74 A0              je          00404375
  004043D5: C7 45 F8 01 00 00  mov         dword ptr [ebp-8],1
            00
  004043DC: 83 7D 18 00        cmp         dword ptr [ebp+18h],0
  004043E0: 0F 84 F8 01 00 00  je          004045DE
  004043E6: 8B 06              mov         eax,dword ptr [esi]
  004043E8: 80 38 00           cmp         byte ptr [eax],0
  004043EB: 0F 84 ED 01 00 00  je          004045DE
  004043F1: BB 00 04 00 00     mov         ebx,400h
  004043F6: BF 01 00 00 00     mov         edi,1
  004043FB: 83 C4 F8           add         esp,0FFFFFFF8h
  004043FE: 0F BE 00           movsx       eax,byte ptr [eax]
  00404401: 50                 push        eax
  00404402: 8B 45 18           mov         eax,dword ptr [ebp+18h]
  00404405: 50                 push        eax
  00404406: E8 4D 0E 00 00     call        00405258
  0040440B: 83 C4 10           add         esp,10h
  0040440E: 85 C0              test        eax,eax
  00404410: 0F 84 AA 01 00 00  je          004045C0
  00404416: 83 C4 F8           add         esp,0FFFFFFF8h
  00404419: 6A 30              push        30h
  0040441B: 8B 45 18           mov         eax,dword ptr [ebp+18h]
  0040441E: 50                 push        eax
  0040441F: E8 34 0E 00 00     call        00405258
  00404424: 83 C4 10           add         esp,10h
  00404427: 85 C0              test        eax,eax
  00404429: 74 2F              je          0040445A
  0040442B: 8B 16              mov         edx,dword ptr [esi]
  0040442D: 8A 42 01           mov         al,byte ptr [edx+1]
  00404430: 3C 44              cmp         al,44h
  00404432: 74 1C              je          00404450
  00404434: 7F 06              jg          0040443C
  00404436: 3C 42              cmp         al,42h
  00404438: 74 16              je          00404450
  0040443A: EB 1E              jmp         0040445A
  0040443C: 3C 69              cmp         al,69h
  0040443E: 75 1A              jne         0040445A
  00404440: 80 7A 02 42        cmp         byte ptr [edx+2],42h
  00404444: 75 14              jne         0040445A
  00404446: BF 03 00 00 00     mov         edi,3
  0040444B: EB 0D              jmp         0040445A
  0040444D: 8D 76 00           lea         esi,[esi]
  00404450: BB E8 03 00 00     mov         ebx,3E8h
  00404455: BF 02 00 00 00     mov         edi,2
  0040445A: 8B 06              mov         eax,dword ptr [esi]
  0040445C: 8A 00              mov         al,byte ptr [eax]
  0040445E: 04 BE              add         al,0BEh
  00404460: 0F BE C0           movsx       eax,al
  00404463: 83 F8 35           cmp         eax,35h
  00404466: 0F 87 54 01 00 00  ja          004045C0
  0040446C: FF 24 85 74 44 40  jmp         dword ptr [eax*4+00404474h]
            00
  00404473: 90                 nop
  00404474: 58                 pop         eax
  00404475: 45                 inc         ebp
  00404476: 40                 inc         eax
  00404477: 00 C0              add         al,al
  00404479: 45                 inc         ebp
  0040447A: 40                 inc         eax
  0040447B: 00 C0              add         al,al
  0040447D: 45                 inc         ebp
  0040447E: 40                 inc         eax
  0040447F: 00 64 45 40        add         byte ptr [ebp+eax*2+40h],ah
  00404483: 00 C0              add         al,al
  00404485: 45                 inc         ebp
  00404486: 40                 inc         eax
  00404487: 00 6C 45 40        add         byte ptr [ebp+eax*2+40h],ch
  0040448B: 00 C0              add         al,al
  0040448D: 45                 inc         ebp
  0040448E: 40                 inc         eax
  0040448F: 00 C0              add         al,al
  00404491: 45                 inc         ebp
  00404492: 40                 inc         eax
  00404493: 00 C0              add         al,al
  00404495: 45                 inc         ebp
  00404496: 40                 inc         eax
  00404497: 00 74 45 40        add         byte ptr [ebp+eax*2+40h],dh
  0040449B: 00 C0              add         al,al
  0040449D: 45                 inc         ebp
  0040449E: 40                 inc         eax
  0040449F: 00 7C 45 40        add         byte ptr [ebp+eax*2+40h],bh
  004044A3: 00 C0              add         al,al
  004044A5: 45                 inc         ebp
  004044A6: 40                 inc         eax
  004044A7: 00 C0              add         al,al
  004044A9: 45                 inc         ebp
  004044AA: 40                 inc         eax
  004044AB: 00 84 45 40 00 C0  add         byte ptr [ebp+eax*2+45C00040h],al
            45
  004044B2: 40                 inc         eax
  004044B3: 00 C0              add         al,al
  004044B5: 45                 inc         ebp
  004044B6: 40                 inc         eax
  004044B7: 00 C0              add         al,al
  004044B9: 45                 inc         ebp
  004044BA: 40                 inc         eax
  004044BB: 00 8C 45 40 00 C0  add         byte ptr [ebp+eax*2+45C00040h],cl
            45
  004044C2: 40                 inc         eax
  004044C3: 00 C0              add         al,al
  004044C5: 45                 inc         ebp
  004044C6: 40                 inc         eax
  004044C7: 00 C0              add         al,al
  004044C9: 45                 inc         ebp
  004044CA: 40                 inc         eax
  004044CB: 00 C0              add         al,al
  004044CD: 45                 inc         ebp
  004044CE: 40                 inc         eax
  004044CF: 00 A4 45 40 00 AC  add         byte ptr [ebp+eax*2+45AC0040h],ah
            45
  004044D6: 40                 inc         eax
  004044D7: 00 C0              add         al,al
  004044D9: 45                 inc         ebp
  004044DA: 40                 inc         eax
  004044DB: 00 C0              add         al,al
  004044DD: 45                 inc         ebp
  004044DE: 40                 inc         eax
  004044DF: 00 C0              add         al,al
  004044E1: 45                 inc         ebp
  004044E2: 40                 inc         eax
  004044E3: 00 C0              add         al,al
  004044E5: 45                 inc         ebp
  004044E6: 40                 inc         eax
  004044E7: 00 C0              add         al,al
  004044E9: 45                 inc         ebp
  004044EA: 40                 inc         eax
  004044EB: 00 C0              add         al,al
  004044ED: 45                 inc         ebp
  004044EE: 40                 inc         eax
  004044EF: 00 C0              add         al,al
  004044F1: 45                 inc         ebp
  004044F2: 40                 inc         eax
  004044F3: 00 4C 45 40        add         byte ptr [ebp+eax*2+40h],cl
  004044F7: 00 DC              add         ah,bl
  004044F9: 45                 inc         ebp
  004044FA: 40                 inc         eax
  004044FB: 00 C0              add         al,al
  004044FD: 45                 inc         ebp
  004044FE: 40                 inc         eax
  004044FF: 00 C0              add         al,al
  00404501: 45                 inc         ebp
  00404502: 40                 inc         eax
  00404503: 00 C0              add         al,al
  00404505: 45                 inc         ebp
  00404506: 40                 inc         eax
  00404507: 00 6C 45 40        add         byte ptr [ebp+eax*2+40h],ch
  0040450B: 00 C0              add         al,al
  0040450D: 45                 inc         ebp
  0040450E: 40                 inc         eax
  0040450F: 00 C0              add         al,al
  00404511: 45                 inc         ebp
  00404512: 40                 inc         eax
  00404513: 00 C0              add         al,al
  00404515: 45                 inc         ebp
  00404516: 40                 inc         eax
  00404517: 00 74 45 40        add         byte ptr [ebp+eax*2+40h],dh
  0040451B: 00 C0              add         al,al
  0040451D: 45                 inc         ebp
  0040451E: 40                 inc         eax
  0040451F: 00 7C 45 40        add         byte ptr [ebp+eax*2+40h],bh
  00404523: 00 C0              add         al,al
  00404525: 45                 inc         ebp
  00404526: 40                 inc         eax
  00404527: 00 C0              add         al,al
  00404529: 45                 inc         ebp
  0040452A: 40                 inc         eax
  0040452B: 00 C0              add         al,al
  0040452D: 45                 inc         ebp
  0040452E: 40                 inc         eax
  0040452F: 00 C0              add         al,al
  00404531: 45                 inc         ebp
  00404532: 40                 inc         eax
  00404533: 00 C0              add         al,al
  00404535: 45                 inc         ebp
  00404536: 40                 inc         eax
  00404537: 00 C0              add         al,al
  00404539: 45                 inc         ebp
  0040453A: 40                 inc         eax
  0040453B: 00 8C 45 40 00 C0  add         byte ptr [ebp+eax*2+45C00040h],cl
            45
  00404542: 40                 inc         eax
  00404543: 00 C0              add         al,al
  00404545: 45                 inc         ebp
  00404546: 40                 inc         eax
  00404547: 00 94 45 40 00 83  add         byte ptr [ebp+eax*2+C4830040h],dl
            C4
  0040454E: F8                 clc
  0040454F: 68 00 02 00 00     push        200h
  00404554: EB 43              jmp         00404599
  00404556: 89 F6              mov         esi,esi
  00404558: 83 C4 F8           add         esp,0FFFFFFF8h
  0040455B: 68 00 04 00 00     push        400h
  00404560: EB 37              jmp         00404599
  00404562: 89 F6              mov         esi,esi
  00404564: 83 C4 FC           add         esp,0FFFFFFFCh
  00404567: 6A 06              push        6
  00404569: EB 46              jmp         004045B1
  0040456B: 90                 nop
  0040456C: 83 C4 FC           add         esp,0FFFFFFFCh
  0040456F: 6A 03              push        3
  00404571: EB 3E              jmp         004045B1
  00404573: 90                 nop
  00404574: 83 C4 FC           add         esp,0FFFFFFFCh
  00404577: 6A 01              push        1
  00404579: EB 36              jmp         004045B1
  0040457B: 90                 nop
  0040457C: 83 C4 FC           add         esp,0FFFFFFFCh
  0040457F: 6A 02              push        2
  00404581: EB 2E              jmp         004045B1
  00404583: 90                 nop
  00404584: 83 C4 FC           add         esp,0FFFFFFFCh
  00404587: 6A 05              push        5
  00404589: EB 26              jmp         004045B1
  0040458B: 90                 nop
  0040458C: 83 C4 FC           add         esp,0FFFFFFFCh
  0040458F: 6A 04              push        4
  00404591: EB 1E              jmp         004045B1
  00404593: 90                 nop
  00404594: 83 C4 F8           add         esp,0FFFFFFF8h
  00404597: 6A 02              push        2
  00404599: 8D 45 F8           lea         eax,[ebp-8]
  0040459C: 50                 push        eax
  0040459D: E8 DA FC FF FF     call        0040427C
  004045A2: EB 2C              jmp         004045D0
  004045A4: 83 C4 FC           add         esp,0FFFFFFFCh
  004045A7: 6A 08              push        8
  004045A9: EB 06              jmp         004045B1
  004045AB: 90                 nop
  004045AC: 83 C4 FC           add         esp,0FFFFFFFCh
  004045AF: 6A 07              push        7
  004045B1: 53                 push        ebx
  004045B2: 8D 45 F8           lea         eax,[ebp-8]
  004045B5: 50                 push        eax
  004045B6: E8 F5 FC FF FF     call        004042B0
  004045BB: EB 13              jmp         004045D0
  004045BD: 8D 76 00           lea         esi,[esi]
  004045C0: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  004045C3: 8B 55 14           mov         edx,dword ptr [ebp+14h]
  004045C6: 89 02              mov         dword ptr [edx],eax
  004045C8: B8 02 00 00 00     mov         eax,2
  004045CD: EB 19              jmp         004045E8
  004045CF: 90                 nop
  004045D0: 85 C0              test        eax,eax
  004045D2: 74 08              je          004045DC
  004045D4: B8 03 00 00 00     mov         eax,3
  004045D9: EB 0D              jmp         004045E8
  004045DB: 90                 nop
  004045DC: 01 3E              add         dword ptr [esi],edi
  004045DE: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  004045E1: 8B 55 14           mov         edx,dword ptr [ebp+14h]
  004045E4: 89 02              mov         dword ptr [edx],eax
  004045E6: 31 C0              xor         eax,eax
  004045E8: 8D 65 D8           lea         esp,[ebp-28h]
  004045EB: 5B                 pop         ebx
  004045EC: 5E                 pop         esi
  004045ED: 5F                 pop         edi
  004045EE: C9                 leave
  004045EF: C3                 ret
  004045F0: 8D B6 00 00 00 00  lea         esi,[esi+00000000h]
  004045F6: 8D BF 00 00 00 00  lea         edi,[edi+00000000h]
  004045FC: 55                 push        ebp
  004045FD: 89 E5              mov         ebp,esp
  004045FF: 83 EC 08           sub         esp,8
  00404602: 83 C4 F4           add         esp,0FFFFFFF4h
  00404605: 6A 01              push        1
  00404607: E8 88 CE FF FF     call        00401494
  0040460C: C9                 leave
  0040460D: C3                 ret
  0040460E: 89 F6              mov         esi,esi
  00404610: 55                 push        ebp
  00404611: 89 E5              mov         ebp,esp
  00404613: 83 EC 1C           sub         esp,1Ch
  00404616: 57                 push        edi
  00404617: 56                 push        esi
  00404618: 53                 push        ebx
  00404619: C7 45 F8 FF FF FF  mov         dword ptr [ebp-8],0FFFFFFFFh
            FF
  00404620: C7 45 F4 00 00 00  mov         dword ptr [ebp-0Ch],0
            00
  00404627: 8B 7D 08           mov         edi,dword ptr [ebp+8]
  0040462A: B0 00              mov         al,0
  0040462C: FC                 cld
  0040462D: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  00404632: F2 AE              repne scas  byte ptr es:[edi]
  00404634: F7 D1              not         ecx
  00404636: 49                 dec         ecx
  00404637: 89 4D FC           mov         dword ptr [ebp-4],ecx
  0040463A: 31 DB              xor         ebx,ebx
  0040463C: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  0040463F: 83 38 00           cmp         dword ptr [eax],0
  00404642: 0F 84 A9 00 00 00  je          004046F1
  00404648: C7 45 F0 00 00 00  mov         dword ptr [ebp-10h],0
            00
  0040464F: 90                 nop
  00404650: 83 7D 18 00        cmp         dword ptr [ebp+18h],0
  00404654: 74 1A              je          00404670
  00404656: 83 C4 FC           add         esp,0FFFFFFFCh
  00404659: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  0040465C: 50                 push        eax
  0040465D: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00404660: 50                 push        eax
  00404661: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  00404664: FF 34 98           push        dword ptr [eax+ebx*4]
  00404667: E8 94 0B 00 00     call        00405200
  0040466C: EB 18              jmp         00404686
  0040466E: 89 F6              mov         esi,esi
  00404670: 83 C4 FC           add         esp,0FFFFFFFCh
  00404673: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  00404676: 50                 push        eax
  00404677: 8B 45 08           mov         eax,dword ptr [ebp+8]
  0040467A: 50                 push        eax
  0040467B: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  0040467E: FF 34 98           push        dword ptr [eax+ebx*4]
  00404681: E8 A6 0A 00 00     call        0040512C
  00404686: 83 C4 10           add         esp,10h
  00404689: 85 C0              test        eax,eax
  0040468B: 75 50              jne         004046DD
  0040468D: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  00404690: 8B 3C 98           mov         edi,dword ptr [eax+ebx*4]
  00404693: B0 00              mov         al,0
  00404695: FC                 cld
  00404696: B9 FF FF FF FF     mov         ecx,0FFFFFFFFh
  0040469B: F2 AE              repne scas  byte ptr es:[edi]
  0040469D: F7 D1              not         ecx
  0040469F: 8D 41 FF           lea         eax,[ecx-1]
  004046A2: 3B 45 FC           cmp         eax,dword ptr [ebp-4]
  004046A5: 74 55              je          004046FC
  004046A7: 83 7D F8 FF        cmp         dword ptr [ebp-8],0FFFFFFFFh
  004046AB: 75 07              jne         004046B4
  004046AD: 89 5D F8           mov         dword ptr [ebp-8],ebx
  004046B0: EB 2B              jmp         004046DD
  004046B2: 89 F6              mov         esi,esi
  004046B4: 83 7D 10 00        cmp         dword ptr [ebp+10h],0
  004046B8: 74 1C              je          004046D6
  004046BA: 8B 45 14           mov         eax,dword ptr [ebp+14h]
  004046BD: 0F AF 45 F8        imul        eax,dword ptr [ebp-8]
  004046C1: 8B 75 10           mov         esi,dword ptr [ebp+10h]
  004046C4: 01 C6              add         esi,eax
  004046C6: 8B 7D 10           mov         edi,dword ptr [ebp+10h]
  004046C9: 03 7D F0           add         edi,dword ptr [ebp-10h]
  004046CC: 8B 4D 14           mov         ecx,dword ptr [ebp+14h]
  004046CF: FC                 cld
  004046D0: A8 00              test        al,0
  004046D2: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  004046D4: 74 07              je          004046DD
  004046D6: C7 45 F4 01 00 00  mov         dword ptr [ebp-0Ch],1
            00
  004046DD: 8B 45 14           mov         eax,dword ptr [ebp+14h]
  004046E0: 01 45 F0           add         dword ptr [ebp-10h],eax
  004046E3: 43                 inc         ebx
  004046E4: 8B 45 0C           mov         eax,dword ptr [ebp+0Ch]
  004046E7: 83 3C 98 00        cmp         dword ptr [eax+ebx*4],0
  004046EB: 0F 85 5F FF FF FF  jne         00404650
  004046F1: 83 7D F4 00        cmp         dword ptr [ebp-0Ch],0
  004046F5: 75 09              jne         00404700
  004046F7: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  004046FA: EB 09              jmp         00404705
  004046FC: 89 D8              mov         eax,ebx
  004046FE: EB 05              jmp         00404705
  00404700: B8 FE FF FF FF     mov         eax,0FFFFFFFEh
  00404705: 8D 65 D8           lea         esp,[ebp-28h]
  00404708: 5B                 pop         ebx
  00404709: 5E                 pop         esi
  0040470A: 5F                 pop         edi
  0040470B: C9                 leave
  0040470C: C3                 ret
  0040470D: 8D 76 00           lea         esi,[esi]
  00404710: 55                 push        ebp
  00404711: 89 E5              mov         ebp,esp
  00404713: 83 EC 08           sub         esp,8
  00404716: 83 C4 F4           add         esp,0FFFFFFF4h
  00404719: 6A 01              push        1
  0040471B: FF 75 14           push        dword ptr [ebp+14h]
  0040471E: FF 75 10           push        dword ptr [ebp+10h]
  00404721: FF 75 0C           push        dword ptr [ebp+0Ch]
  00404724: FF 75 08           push        dword ptr [ebp+8]
  00404727: E8 E4 FE FF FF     call        00404610
  0040472C: C9                 leave
  0040472D: C3                 ret
  0040472E: 89 F6              mov         esi,esi
  00404730: 55                 push        ebp
  00404731: 89 E5              mov         ebp,esp
  00404733: 83 EC 08           sub         esp,8
  00404736: 83 C4 F4           add         esp,0FFFFFFF4h
  00404739: 6A 00              push        0
  0040473B: FF 75 14           push        dword ptr [ebp+14h]
  0040473E: FF 75 10           push        dword ptr [ebp+10h]
  00404741: FF 75 0C           push        dword ptr [ebp+0Ch]
  00404744: FF 75 08           push        dword ptr [ebp+8]
  00404747: E8 C4 FE FF FF     call        00404610
  0040474C: C9                 leave
  0040474D: C3                 ret
  0040474E: 69 6E 76 61 6C 69  imul        ebp,dword ptr [esi+76h],64696C61h
            64
  00404755: 20 61 72           and         byte ptr [ecx+72h],ah
  00404758: 67 75 6D           jne         004047C8
  0040475B: 65 6E              outs        dx,byte ptr gs:[esi]
  0040475D: 74 20              je          0040477F
  0040475F: 25 73 20 66 6F     and         eax,6F662073h
  00404764: 72 20              jb          00404786
  00404766: 25 73 00 61 6D     and         eax,6D610073h
  0040476B: 62 69 67           bound       ebp,qword ptr [ecx+67h]
  0040476E: 75 6F              jne         004047DF
  00404770: 75 73              jne         004047E5
  00404772: 20 61 72           and         byte ptr [ecx+72h],ah
  00404775: 67 75 6D           jne         004047E5
  00404778: 65 6E              outs        dx,byte ptr gs:[esi]
  0040477A: 74 20              je          0040479C
  0040477C: 25 73 20 66 6F     and         eax,6F662073h
  00404781: 72 20              jb          004047A3
  00404783: 25 73 00 89 F6     and         eax,0F6890073h
  00404788: 55                 push        ebp
  00404789: 89 E5              mov         ebp,esp
  0040478B: 83 EC 14           sub         esp,14h
  0040478E: 53                 push        ebx
  0040478F: BB 69 47 40 00     mov         ebx,404769h
  00404794: 83 7D 10 FF        cmp         dword ptr [ebp+10h],0FFFFFFFFh
  00404798: 75 05              jne         0040479F
  0040479A: BB 4E 47 40 00     mov         ebx,40474Eh
  0040479F: 83 C4 F4           add         esp,0FFFFFFF4h
  004047A2: 83 C4 F8           add         esp,0FFFFFFF8h
  004047A5: FF 75 08           push        dword ptr [ebp+8]
  004047A8: 6A 01              push        1
  004047AA: E8 81 02 00 00     call        00404A30
  004047AF: 50                 push        eax
  004047B0: 83 C4 FC           add         esp,0FFFFFFFCh
  004047B3: FF 75 0C           push        dword ptr [ebp+0Ch]
  004047B6: 6A 05              push        5
  004047B8: 6A 00              push        0
  004047BA: E8 DD F9 FF FF     call        0040419C
  004047BF: 83 C4 10           add         esp,10h
  004047C2: 50                 push        eax
  004047C3: 53                 push        ebx
  004047C4: 6A 00              push        0
  004047C6: 6A 00              push        0
  004047C8: E8 1B EE FF FF     call        004035E8
  004047CD: 8B 5D E8           mov         ebx,dword ptr [ebp-18h]
  004047D0: C9                 leave
  004047D1: C3                 ret
  004047D2: 56                 push        esi
  004047D3: 61                 popad
  004047D4: 6C                 ins         byte ptr es:[edi],dx
  004047D5: 69 64 20 61 72 67  imul        esp,dword ptr [eax+61h],6D756772h
            75 6D
  004047DD: 65 6E              outs        dx,byte ptr gs:[esi]
  004047DF: 74 73              je          00404854
  004047E1: 20 61 72           and         byte ptr [ecx+72h],ah
  004047E4: 65 3A 00           cmp         al,byte ptr gs:[eax]
  004047E7: 0A 20              or          ah,byte ptr [eax]
  004047E9: 20 2D 20 60 25 73  and         byte ptr ds:[73256020h],ch
  004047EF: 27                 daa
  004047F0: 00 2C 20           add         byte ptr [eax],ch
  004047F3: 60                 pushad
  004047F4: 25 73 27 00 55     and         eax,55002773h
  004047F9: 89 E5              mov         ebp,esp
  004047FB: 83 EC 1C           sub         esp,1Ch
  004047FE: 57                 push        edi
  004047FF: 56                 push        esi
  00404800: 53                 push        ebx
  00404801: C7 45 F8 00 00 00  mov         dword ptr [ebp-8],0
            00
  00404808: 83 C4 F8           add         esp,0FFFFFFF8h
  0040480B: 68 D2 47 40 00     push        4047D2h
  00404810: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00404815: 83 C0 40           add         eax,40h
  00404818: 50                 push        eax
  00404819: E8 DA 09 00 00     call        004051F8
  0040481E: C7 45 FC 00 00 00  mov         dword ptr [ebp-4],0
            00
  00404825: 83 C4 10           add         esp,10h
  00404828: 8B 45 08           mov         eax,dword ptr [ebp+8]
  0040482B: 83 38 00           cmp         dword ptr [eax],0
  0040482E: 0F 84 87 00 00 00  je          004048BB
  00404834: C7 45 F4 00 00 00  mov         dword ptr [ebp-0Ch],0
            00
  0040483B: 90                 nop
  0040483C: 8B 5D 10           mov         ebx,dword ptr [ebp+10h]
  0040483F: 0F AF 5D FC        imul        ebx,dword ptr [ebp-4]
  00404843: 83 7D FC 00        cmp         dword ptr [ebp-4],0
  00404847: 74 13              je          0040485C
  00404849: 8B 75 F8           mov         esi,dword ptr [ebp-8]
  0040484C: 8B 7D 0C           mov         edi,dword ptr [ebp+0Ch]
  0040484F: 03 7D F4           add         edi,dword ptr [ebp-0Ch]
  00404852: 8B 4D 10           mov         ecx,dword ptr [ebp+10h]
  00404855: FC                 cld
  00404856: A8 00              test        al,0
  00404858: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  0040485A: 74 28              je          00404884
  0040485C: 83 C4 FC           add         esp,0FFFFFFFCh
  0040485F: 8B 55 FC           mov         edx,dword ptr [ebp-4]
  00404862: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00404865: FF 34 90           push        dword ptr [eax+edx*4]
  00404868: 68 E7 47 40 00     push        4047E7h
  0040486D: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  00404872: 83 C0 40           add         eax,40h
  00404875: 50                 push        eax
  00404876: E8 7D 09 00 00     call        004051F8
  0040487B: 03 5D 0C           add         ebx,dword ptr [ebp+0Ch]
  0040487E: 89 5D F8           mov         dword ptr [ebp-8],ebx
  00404881: EB 20              jmp         004048A3
  00404883: 90                 nop
  00404884: 83 C4 FC           add         esp,0FFFFFFFCh
  00404887: 8B 55 FC           mov         edx,dword ptr [ebp-4]
  0040488A: 8B 45 08           mov         eax,dword ptr [ebp+8]
  0040488D: FF 34 90           push        dword ptr [eax+edx*4]
  00404890: 68 F1 47 40 00     push        4047F1h
  00404895: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  0040489A: 83 C0 40           add         eax,40h
  0040489D: 50                 push        eax
  0040489E: E8 55 09 00 00     call        004051F8
  004048A3: 83 C4 10           add         esp,10h
  004048A6: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  004048A9: 01 55 F4           add         dword ptr [ebp-0Ch],edx
  004048AC: FF 45 FC           inc         dword ptr [ebp-4]
  004048AF: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  004048B2: 8B 55 08           mov         edx,dword ptr [ebp+8]
  004048B5: 83 3C 82 00        cmp         dword ptr [edx+eax*4],0
  004048B9: 75 81              jne         0040483C
  004048BB: 83 C4 F8           add         esp,0FFFFFFF8h
  004048BE: A1 7C 81 40 00     mov         eax,dword ptr ds:[0040817Ch]
  004048C3: 83 C0 40           add         eax,40h
  004048C6: 50                 push        eax
  004048C7: 6A 0A              push        0Ah
  004048C9: E8 42 09 00 00     call        00405210
  004048CE: 8D 65 D8           lea         esp,[ebp-28h]
  004048D1: 5B                 pop         ebx
  004048D2: 5E                 pop         esi
  004048D3: 5F                 pop         edi
  004048D4: C9                 leave
  004048D5: C3                 ret
  004048D6: 89 F6              mov         esi,esi
  004048D8: 55                 push        ebp
  004048D9: 89 E5              mov         ebp,esp
  004048DB: 83 EC 0C           sub         esp,0Ch
  004048DE: 57                 push        edi
  004048DF: 56                 push        esi
  004048E0: 53                 push        ebx
  004048E1: 8B 5D 0C           mov         ebx,dword ptr [ebp+0Ch]
  004048E4: 8B 7D 14           mov         edi,dword ptr [ebp+14h]
  004048E7: 8B 75 18           mov         esi,dword ptr [ebp+18h]
  004048EA: 83 C4 F4           add         esp,0FFFFFFF4h
  004048ED: FF 75 1C           push        dword ptr [ebp+1Ch]
  004048F0: 56                 push        esi
  004048F1: 57                 push        edi
  004048F2: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  004048F5: 50                 push        eax
  004048F6: 53                 push        ebx
  004048F7: E8 14 FD FF FF     call        00404610
  004048FC: 83 C4 20           add         esp,20h
  004048FF: 85 C0              test        eax,eax
  00404901: 7D 28              jge         0040492B
  00404903: 83 C4 FC           add         esp,0FFFFFFFCh
  00404906: 50                 push        eax
  00404907: 53                 push        ebx
  00404908: FF 75 08           push        dword ptr [ebp+8]
  0040490B: E8 78 FE FF FF     call        00404788
  00404910: 83 C4 FC           add         esp,0FFFFFFFCh
  00404913: 56                 push        esi
  00404914: 57                 push        edi
  00404915: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  00404918: 50                 push        eax
  00404919: E8 DA FE FF FF     call        004047F8
  0040491E: 83 C4 20           add         esp,20h
  00404921: 8B 45 20           mov         eax,dword ptr [ebp+20h]
  00404924: FF D0              call        eax
  00404926: B8 FF FF FF FF     mov         eax,0FFFFFFFFh
  0040492B: 8D 65 E8           lea         esp,[ebp-18h]
  0040492E: 5B                 pop         ebx
  0040492F: 5E                 pop         esi
  00404930: 5F                 pop         edi
  00404931: C9                 leave
  00404932: C3                 ret
  00404933: 90                 nop
  00404934: 55                 push        ebp
  00404935: 89 E5              mov         ebp,esp
  00404937: 57                 push        edi
  00404938: 56                 push        esi
  00404939: 53                 push        ebx
  0040493A: 8B 55 14           mov         edx,dword ptr [ebp+14h]
  0040493D: 31 C0              xor         eax,eax
  0040493F: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  00404942: 83 39 00           cmp         dword ptr [ecx],0
  00404945: 74 2D              je          00404974
  00404947: 31 DB              xor         ebx,ebx
  00404949: 8D 76 00           lea         esi,[esi]
  0040494C: 8B 75 08           mov         esi,dword ptr [ebp+8]
  0040494F: 8B 7D 10           mov         edi,dword ptr [ebp+10h]
  00404952: 01 DF              add         edi,ebx
  00404954: 89 D1              mov         ecx,edx
  00404956: FC                 cld
  00404957: A8 00              test        al,0
  00404959: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  0040495B: 75 0B              jne         00404968
  0040495D: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00404960: 8B 04 82           mov         eax,dword ptr [edx+eax*4]
  00404963: EB 11              jmp         00404976
  00404965: 8D 76 00           lea         esi,[esi]
  00404968: 01 D3              add         ebx,edx
  0040496A: 40                 inc         eax
  0040496B: 8B 4D 0C           mov         ecx,dword ptr [ebp+0Ch]
  0040496E: 83 3C 81 00        cmp         dword ptr [ecx+eax*4],0
  00404972: 75 D8              jne         0040494C
  00404974: 31 C0              xor         eax,eax
  00404976: 5B                 pop         ebx
  00404977: 5E                 pop         esi
  00404978: 5F                 pop         edi
  00404979: C9                 leave
  0040497A: C3                 ret
  0040497B: 90                 nop
  0040497C: 6D                 ins         dword ptr es:[edi],dx
  0040497D: 65 6D              ins         dword ptr es:[edi],dx
  0040497F: 6F                 outs        dx,dword ptr [esi]
  00404980: 72 79              jb          004049FB
  00404982: 20 65 78           and         byte ptr [ebp+78h],ah
  00404985: 68 61 75 73 74     push        74737561h
  0040498A: 65
  0040498B: 64 00 25 73 00 55  add         byte ptr fs:[89550073h],ah
            89
  00404992: E5 83              in          eax,83h
  00404994: EC                 in          al,dx
  00404995: 08 A1 34 60 40 00  or          byte ptr [ecx+00406034h],ah
  0040499B: 85 C0              test        eax,eax
  0040499D: 74 02              je          004049A1
  0040499F: FF D0              call        eax
  004049A1: 68 7C 49 40 00     push        40497Ch
  004049A6: 68 8D 49 40 00     push        40498Dh
  004049AB: 6A 00              push        0
  004049AD: FF 35 30 60 40 00  push        dword ptr ds:[00406030h]
  004049B3: E8 30 EC FF FF     call        004035E8
  004049B8: 83 C4 F4           add         esp,0FFFFFFF4h
  004049BB: 6A FF              push        0FFFFFFFFh
  004049BD: E8 1E 08 00 00     call        004051E0
  004049C2: 89 F6              mov         esi,esi
  004049C4: 55                 push        ebp
  004049C5: 89 E5              mov         ebp,esp
  004049C7: 83 EC 08           sub         esp,8
  004049CA: 83 C4 F4           add         esp,0FFFFFFF4h
  004049CD: FF 75 08           push        dword ptr [ebp+8]
  004049D0: E8 B3 08 00 00     call        00405288
  004049D5: 83 C4 10           add         esp,10h
  004049D8: 85 C0              test        eax,eax
  004049DA: 75 08              jne         004049E4
  004049DC: E8 AF FF FF FF     call        00404990
  004049E1: 8D 76 00           lea         esi,[esi]
  004049E4: C9                 leave
  004049E5: C3                 ret
  004049E6: 89 F6              mov         esi,esi
  004049E8: 55                 push        ebp
  004049E9: 89 E5              mov         ebp,esp
  004049EB: 83 EC 08           sub         esp,8
  004049EE: 83 C4 F8           add         esp,0FFFFFFF8h
  004049F1: FF 75 0C           push        dword ptr [ebp+0Ch]
  004049F4: FF 75 08           push        dword ptr [ebp+8]
  004049F7: E8 84 08 00 00     call        00405280
  004049FC: 83 C4 10           add         esp,10h
  004049FF: 85 C0              test        eax,eax
  00404A01: 75 05              jne         00404A08
  00404A03: E8 88 FF FF FF     call        00404990
  00404A08: C9                 leave
  00404A09: C3                 ret
  00404A0A: 89 F6              mov         esi,esi
  00404A0C: 55                 push        ebp
  00404A0D: 89 E5              mov         ebp,esp
  00404A0F: 83 EC 08           sub         esp,8
  00404A12: 83 C4 F8           add         esp,0FFFFFFF8h
  00404A15: FF 75 0C           push        dword ptr [ebp+0Ch]
  00404A18: FF 75 08           push        dword ptr [ebp+8]
  00404A1B: E8 58 08 00 00     call        00405278
  00404A20: 83 C4 10           add         esp,10h
  00404A23: 85 C0              test        eax,eax
  00404A25: 75 05              jne         00404A2C
  00404A27: E8 64 FF FF FF     call        00404990
  00404A2C: C9                 leave
  00404A2D: C3                 ret
  00404A2E: 89 F6              mov         esi,esi
  00404A30: 55                 push        ebp
  00404A31: 89 E5              mov         ebp,esp
  00404A33: 83 EC 08           sub         esp,8
  00404A36: 83 C4 FC           add         esp,0FFFFFFFCh
  00404A39: FF 75 0C           push        dword ptr [ebp+0Ch]
  00404A3C: 6A 05              push        5
  00404A3E: FF 75 08           push        dword ptr [ebp+8]
  00404A41: E8 56 F7 FF FF     call        0040419C
  00404A46: C9                 leave
  00404A47: C3                 ret
  00404A48: 55                 push        ebp
  00404A49: 89 E5              mov         ebp,esp
  00404A4B: 83 EC 08           sub         esp,8
  00404A4E: 83 C4 F8           add         esp,0FFFFFFF8h
  00404A51: FF 75 08           push        dword ptr [ebp+8]
  00404A54: 6A 00              push        0
  00404A56: E8 D5 FF FF FF     call        00404A30
  00404A5B: C9                 leave
  00404A5C: C3                 ret
  00404A5D: 8D 76 00           lea         esi,[esi]
  00404A60: 55                 push        ebp
  00404A61: 89 E5              mov         ebp,esp
  00404A63: 83 EC 08           sub         esp,8
  00404A66: A1 40 60 40 00     mov         eax,dword ptr ds:[00406040h]
  00404A6B: 83 38 00           cmp         dword ptr [eax],0
  00404A6E: 74 1D              je          00404A8D
  00404A70: A1 40 60 40 00     mov         eax,dword ptr ds:[00406040h]
  00404A75: 8B 00              mov         eax,dword ptr [eax]
  00404A77: FF D0              call        eax
  00404A79: A1 40 60 40 00     mov         eax,dword ptr ds:[00406040h]
  00404A7E: 8D 50 04           lea         edx,[eax+4]
  00404A81: 89 15 40 60 40 00  mov         dword ptr ds:[00406040h],edx
  00404A87: 83 78 04 00        cmp         dword ptr [eax+4],0
  00404A8B: 75 E3              jne         00404A70
  00404A8D: C9                 leave
  00404A8E: C3                 ret
  00404A8F: 90                 nop
  00404A90: 55                 push        ebp
  00404A91: 89 E5              mov         ebp,esp
  00404A93: 83 EC 14           sub         esp,14h
  00404A96: 53                 push        ebx
  00404A97: A1 B8 52 40 00     mov         eax,dword ptr ds:[004052B8h]
  00404A9C: 83 F8 FF           cmp         eax,0FFFFFFFFh
  00404A9F: 75 1C              jne         00404ABD
  00404AA1: 31 C0              xor         eax,eax
  00404AA3: 83 3D BC 52 40 00  cmp         dword ptr ds:[004052BCh],0
            00
  00404AAA: 74 11              je          00404ABD
  00404AAC: BA BC 52 40 00     mov         edx,4052BCh
  00404AB1: 8D 76 00           lea         esi,[esi]
  00404AB4: 83 C2 04           add         edx,4
  00404AB7: 40                 inc         eax
  00404AB8: 83 3A 00           cmp         dword ptr [edx],0
  00404ABB: 75 F7              jne         00404AB4
  00404ABD: 89 C3              mov         ebx,eax
  00404ABF: 85 DB              test        ebx,ebx
  00404AC1: 74 0D              je          00404AD0
  00404AC3: 90                 nop
  00404AC4: 8B 04 9D B8 52 40  mov         eax,dword ptr [ebx*4+004052B8h]
            00
  00404ACB: FF D0              call        eax
  00404ACD: 4B                 dec         ebx
  00404ACE: 75 F4              jne         00404AC4
  00404AD0: 83 C4 F4           add         esp,0FFFFFFF4h
  00404AD3: 68 60 4A 40 00     push        404A60h
  00404AD8: E8 C3 06 00 00     call        004051A0
  00404ADD: 8B 5D E8           mov         ebx,dword ptr [ebp-18h]
  00404AE0: C9                 leave
  00404AE1: C3                 ret
  00404AE2: 89 F6              mov         esi,esi
  00404AE4: 55                 push        ebp
  00404AE5: 89 E5              mov         ebp,esp
  00404AE7: 83 EC 08           sub         esp,8
  00404AEA: 83 3D 44 60 40 00  cmp         dword ptr ds:[00406044h],0
            00
  00404AF1: 75 0F              jne         00404B02
  00404AF3: C7 05 44 60 40 00  mov         dword ptr ds:[00406044h],1
            01 00 00 00
  00404AFD: E8 8E FF FF FF     call        00404A90
  00404B02: C9                 leave
  00404B03: C3                 ret
  00404B04: 51                 push        ecx
  00404B05: 89 E1              mov         ecx,esp
  00404B07: 83 C1 08           add         ecx,8
  00404B0A: 3D 00 10 00 00     cmp         eax,1000h
  00404B0F: 72 10              jb          00404B21
  00404B11: 81 E9 00 10 00 00  sub         ecx,1000h
  00404B17: 83 09 00           or          dword ptr [ecx],0
  00404B1A: 2D 00 10 00 00     sub         eax,1000h
  00404B1F: EB E9              jmp         00404B0A
  00404B21: 29 C1              sub         ecx,eax
  00404B23: 83 09 00           or          dword ptr [ecx],0
  00404B26: 89 E0              mov         eax,esp
  00404B28: 89 CC              mov         esp,ecx
  00404B2A: 8B 08              mov         ecx,dword ptr [eax]
  00404B2C: 8B 40 04           mov         eax,dword ptr [eax+4]
  00404B2F: FF E0              jmp         eax
  00404B31: 8D 76 00           lea         esi,[esi]
  00404B34: 00 00              add         byte ptr [eax],al
  00404B36: 00 00              add         byte ptr [eax],al
  00404B38: 00 00              add         byte ptr [eax],al
  00404B3A: F0 3D 90 8D B4 26  lock cmp    eax,26B48D90h
  00404B40: 00 00              add         byte ptr [eax],al
  00404B42: 00 00              add         byte ptr [eax],al
  00404B44: 00 00              add         byte ptr [eax],al
  00404B46: 00 00              add         byte ptr [eax],al
  00404B48: 00 00              add         byte ptr [eax],al
  00404B4A: 00 80 3F 40 00 00  add         byte ptr [eax+0000403Fh],al
  00404B50: 55                 push        ebp
  00404B51: 89 E5              mov         ebp,esp
  00404B53: 83 EC 50           sub         esp,50h
  00404B56: 56                 push        esi
  00404B57: 53                 push        ebx
  00404B58: DD 45 08           fld         qword ptr [ebp+8]
  00404B5B: D9 EE              fldz
  00404B5D: D8 D9              fcomp       st(1)
  00404B5F: DF E0              fnstsw      ax
  00404B61: 80 E4 45           and         ah,45h
  00404B64: 75 0E              jne         00404B74
  00404B66: DD D8              fstp        st(0)
  00404B68: 31 C0              xor         eax,eax
  00404B6A: 31 D2              xor         edx,edx
  00404B6C: E9 CB 00 00 00     jmp         00404C3C
  00404B71: 8D 76 00           lea         esi,[esi]
  00404B74: D9 C0              fld         st(0)
  00404B76: DC 0D 34 4B 40 00  fmul        qword ptr ds:[00404B34h]
  00404B7C: D9 7D FE           fnstcw      word ptr [ebp-2]
  00404B7F: 66 8B 4D FE        mov         cx,word ptr [ebp-2]
  00404B83: 66 81 C9 00 0C     or          cx,0C00h
  00404B88: 66 89 4D FC        mov         word ptr [ebp-4],cx
  00404B8C: D9 6D FC           fldcw       word ptr [ebp-4]
  00404B8F: DF 7D F0           fistp       qword ptr [ebp-10h]
  00404B92: 8B 45 F0           mov         eax,dword ptr [ebp-10h]
  00404B95: 8B 55 F4           mov         edx,dword ptr [ebp-0Ch]
  00404B98: D9 6D FE           fldcw       word ptr [ebp-2]
  00404B9B: 89 C3              mov         ebx,eax
  00404B9D: 31 F6              xor         esi,esi
  00404B9F: 89 DE              mov         esi,ebx
  00404BA1: 31 DB              xor         ebx,ebx
  00404BA3: 89 5D F0           mov         dword ptr [ebp-10h],ebx
  00404BA6: 89 75 F4           mov         dword ptr [ebp-0Ch],esi
  00404BA9: DF 6D F0           fild        qword ptr [ebp-10h]
  00404BAC: DB 7D D0           fstp        tbyte ptr [ebp-30h]
  00404BAF: 6A 00              push        0
  00404BB1: 6A 00              push        0
  00404BB3: 56                 push        esi
  00404BB4: 53                 push        ebx
  00404BB5: DB 7D C0           fstp        tbyte ptr [ebp-40h]
  00404BB8: E8 87 00 00 00     call        00404C44
  00404BBD: DB 6D C0           fld         tbyte ptr [ebp-40h]
  00404BC0: 83 F8 01           cmp         eax,1
  00404BC3: 7D 0E              jge         00404BD3
  00404BC5: DB 2D 44 4B 40 00  fld         tbyte ptr ds:[00404B44h]
  00404BCB: DB 6D D0           fld         tbyte ptr [ebp-30h]
  00404BCE: DE C1              faddp       st(1),st
  00404BD0: DB 7D D0           fstp        tbyte ptr [ebp-30h]
  00404BD3: DB 6D D0           fld         tbyte ptr [ebp-30h]
  00404BD6: DD 5D E8           fstp        qword ptr [ebp-18h]
  00404BD9: DD 45 E8           fld         qword ptr [ebp-18h]
  00404BDC: DE E9              fsubp       st(1),st
  00404BDE: D9 EE              fldz
  00404BE0: D8 D9              fcomp       st(1)
  00404BE2: DF E0              fnstsw      ax
  00404BE4: 80 E4 45           and         ah,45h
  00404BE7: 75 2B              jne         00404C14
  00404BE9: D9 E0              fchs
  00404BEB: D9 7D FE           fnstcw      word ptr [ebp-2]
  00404BEE: 66 8B 4D FE        mov         cx,word ptr [ebp-2]
  00404BF2: 66 81 C9 00 0C     or          cx,0C00h
  00404BF7: 66 89 4D FC        mov         word ptr [ebp-4],cx
  00404BFB: D9 6D FC           fldcw       word ptr [ebp-4]
  00404BFE: DF 7D F0           fistp       qword ptr [ebp-10h]
  00404C01: 8B 45 F0           mov         eax,dword ptr [ebp-10h]
  00404C04: 8B 55 F4           mov         edx,dword ptr [ebp-0Ch]
  00404C07: D9 6D FE           fldcw       word ptr [ebp-2]
  00404C0A: 29 C3              sub         ebx,eax
  00404C0C: 83 DE 00           sbb         esi,0
  00404C0F: EB 27              jmp         00404C38
  00404C11: 8D 76 00           lea         esi,[esi]
  00404C14: D9 7D FE           fnstcw      word ptr [ebp-2]
  00404C17: 66 8B 4D FE        mov         cx,word ptr [ebp-2]
  00404C1B: 66 81 C9 00 0C     or          cx,0C00h
  00404C20: 66 89 4D FC        mov         word ptr [ebp-4],cx
  00404C24: D9 6D FC           fldcw       word ptr [ebp-4]
  00404C27: DF 7D F0           fistp       qword ptr [ebp-10h]
  00404C2A: 8B 45 F0           mov         eax,dword ptr [ebp-10h]
  00404C2D: 8B 55 F4           mov         edx,dword ptr [ebp-0Ch]
  00404C30: D9 6D FE           fldcw       word ptr [ebp-2]
  00404C33: 01 C3              add         ebx,eax
  00404C35: 83 D6 00           adc         esi,0
  00404C38: 89 D8              mov         eax,ebx
  00404C3A: 89 F2              mov         edx,esi
  00404C3C: 8D 65 A8           lea         esp,[ebp-58h]
  00404C3F: 5B                 pop         ebx
  00404C40: 5E                 pop         esi
  00404C41: C9                 leave
  00404C42: C3                 ret
  00404C43: 90                 nop
  00404C44: 55                 push        ebp
  00404C45: 89 E5              mov         ebp,esp
  00404C47: 53                 push        ebx
  00404C48: 8B 4D 08           mov         ecx,dword ptr [ebp+8]
  00404C4B: 8B 5D 0C           mov         ebx,dword ptr [ebp+0Ch]
  00404C4E: 8B 45 10           mov         eax,dword ptr [ebp+10h]
  00404C51: 8B 55 14           mov         edx,dword ptr [ebp+14h]
  00404C54: 39 D3              cmp         ebx,edx
  00404C56: 7C 06              jl          00404C5E
  00404C58: 7F 16              jg          00404C70
  00404C5A: 39 C1              cmp         ecx,eax
  00404C5C: 73 06              jae         00404C64
  00404C5E: 31 C0              xor         eax,eax
  00404C60: EB 13              jmp         00404C75
  00404C62: 89 F6              mov         esi,esi
  00404C64: 39 C1              cmp         ecx,eax
  00404C66: 77 08              ja          00404C70
  00404C68: B8 01 00 00 00     mov         eax,1
  00404C6D: EB 06              jmp         00404C75
  00404C6F: 90                 nop
  00404C70: B8 02 00 00 00     mov         eax,2
  00404C75: 5B                 pop         ebx
  00404C76: C9                 leave
  00404C77: C3                 ret
  00404C78: 00 01              add         byte ptr [ecx],al
  00404C7A: 02 02              add         al,byte ptr [edx]
  00404C7C: 03 03              add         eax,dword ptr [ebx]
  00404C7E: 03 03              add         eax,dword ptr [ebx]
  00404C80: 04 04              add         al,4
  00404C82: 04 04              add         al,4
  00404C84: 04 04              add         al,4
  00404C86: 04 04              add         al,4
  00404C88: 05 05 05 05 05     add         eax,5050505h
  00404C8D: 05 05 05 05 05     add         eax,5050505h
  00404C92: 05 05 05 05 05     add         eax,5050505h
  00404C97: 05 06 06 06 06     add         eax,6060606h
  00404C9C: 06                 push        es
  00404C9D: 06                 push        es
  00404C9E: 06                 push        es
  00404C9F: 06                 push        es
  00404CA0: 06                 push        es
  00404CA1: 06                 push        es
  00404CA2: 06                 push        es
  00404CA3: 06                 push        es
  00404CA4: 06                 push        es
  00404CA5: 06                 push        es
  00404CA6: 06                 push        es
  00404CA7: 06                 push        es
  00404CA8: 06                 push        es
  00404CA9: 06                 push        es
  00404CAA: 06                 push        es
  00404CAB: 06                 push        es
  00404CAC: 06                 push        es
  00404CAD: 06                 push        es
  00404CAE: 06                 push        es
  00404CAF: 06                 push        es
  00404CB0: 06                 push        es
  00404CB1: 06                 push        es
  00404CB2: 06                 push        es
  00404CB3: 06                 push        es
  00404CB4: 06                 push        es
  00404CB5: 06                 push        es
  00404CB6: 06                 push        es
  00404CB7: 06                 push        es
  00404CB8: 07                 pop         es
  00404CB9: 07                 pop         es
  00404CBA: 07                 pop         es
  00404CBB: 07                 pop         es
  00404CBC: 07                 pop         es
  00404CBD: 07                 pop         es
  00404CBE: 07                 pop         es
  00404CBF: 07                 pop         es
  00404CC0: 07                 pop         es
  00404CC1: 07                 pop         es
  00404CC2: 07                 pop         es
  00404CC3: 07                 pop         es
  00404CC4: 07                 pop         es
  00404CC5: 07                 pop         es
  00404CC6: 07                 pop         es
  00404CC7: 07                 pop         es
  00404CC8: 07                 pop         es
  00404CC9: 07                 pop         es
  00404CCA: 07                 pop         es
  00404CCB: 07                 pop         es
  00404CCC: 07                 pop         es
  00404CCD: 07                 pop         es
  00404CCE: 07                 pop         es
  00404CCF: 07                 pop         es
  00404CD0: 07                 pop         es
  00404CD1: 07                 pop         es
  00404CD2: 07                 pop         es
  00404CD3: 07                 pop         es
  00404CD4: 07                 pop         es
  00404CD5: 07                 pop         es
  00404CD6: 07                 pop         es
  00404CD7: 07                 pop         es
  00404CD8: 07                 pop         es
  00404CD9: 07                 pop         es
  00404CDA: 07                 pop         es
  00404CDB: 07                 pop         es
  00404CDC: 07                 pop         es
  00404CDD: 07                 pop         es
  00404CDE: 07                 pop         es
  00404CDF: 07                 pop         es
  00404CE0: 07                 pop         es
  00404CE1: 07                 pop         es
  00404CE2: 07                 pop         es
  00404CE3: 07                 pop         es
  00404CE4: 07                 pop         es
  00404CE5: 07                 pop         es
  00404CE6: 07                 pop         es
  00404CE7: 07                 pop         es
  00404CE8: 07                 pop         es
  00404CE9: 07                 pop         es
  00404CEA: 07                 pop         es
  00404CEB: 07                 pop         es
  00404CEC: 07                 pop         es
  00404CED: 07                 pop         es
  00404CEE: 07                 pop         es
  00404CEF: 07                 pop         es
  00404CF0: 07                 pop         es
  00404CF1: 07                 pop         es
  00404CF2: 07                 pop         es
  00404CF3: 07                 pop         es
  00404CF4: 07                 pop         es
  00404CF5: 07                 pop         es
  00404CF6: 07                 pop         es
  00404CF7: 07                 pop         es
  00404CF8: 08 08              or          byte ptr [eax],cl
  00404CFA: 08 08              or          byte ptr [eax],cl
  00404CFC: 08 08              or          byte ptr [eax],cl
  00404CFE: 08 08              or          byte ptr [eax],cl
  00404D00: 08 08              or          byte ptr [eax],cl
  00404D02: 08 08              or          byte ptr [eax],cl
  00404D04: 08 08              or          byte ptr [eax],cl
  00404D06: 08 08              or          byte ptr [eax],cl
  00404D08: 08 08              or          byte ptr [eax],cl
  00404D0A: 08 08              or          byte ptr [eax],cl
  00404D0C: 08 08              or          byte ptr [eax],cl
  00404D0E: 08 08              or          byte ptr [eax],cl
  00404D10: 08 08              or          byte ptr [eax],cl
  00404D12: 08 08              or          byte ptr [eax],cl
  00404D14: 08 08              or          byte ptr [eax],cl
  00404D16: 08 08              or          byte ptr [eax],cl
  00404D18: 08 08              or          byte ptr [eax],cl
  00404D1A: 08 08              or          byte ptr [eax],cl
  00404D1C: 08 08              or          byte ptr [eax],cl
  00404D1E: 08 08              or          byte ptr [eax],cl
  00404D20: 08 08              or          byte ptr [eax],cl
  00404D22: 08 08              or          byte ptr [eax],cl
  00404D24: 08 08              or          byte ptr [eax],cl
  00404D26: 08 08              or          byte ptr [eax],cl
  00404D28: 08 08              or          byte ptr [eax],cl
  00404D2A: 08 08              or          byte ptr [eax],cl
  00404D2C: 08 08              or          byte ptr [eax],cl
  00404D2E: 08 08              or          byte ptr [eax],cl
  00404D30: 08 08              or          byte ptr [eax],cl
  00404D32: 08 08              or          byte ptr [eax],cl
  00404D34: 08 08              or          byte ptr [eax],cl
  00404D36: 08 08              or          byte ptr [eax],cl
  00404D38: 08 08              or          byte ptr [eax],cl
  00404D3A: 08 08              or          byte ptr [eax],cl
  00404D3C: 08 08              or          byte ptr [eax],cl
  00404D3E: 08 08              or          byte ptr [eax],cl
  00404D40: 08 08              or          byte ptr [eax],cl
  00404D42: 08 08              or          byte ptr [eax],cl
  00404D44: 08 08              or          byte ptr [eax],cl
  00404D46: 08 08              or          byte ptr [eax],cl
  00404D48: 08 08              or          byte ptr [eax],cl
  00404D4A: 08 08              or          byte ptr [eax],cl
  00404D4C: 08 08              or          byte ptr [eax],cl
  00404D4E: 08 08              or          byte ptr [eax],cl
  00404D50: 08 08              or          byte ptr [eax],cl
  00404D52: 08 08              or          byte ptr [eax],cl
  00404D54: 08 08              or          byte ptr [eax],cl
  00404D56: 08 08              or          byte ptr [eax],cl
  00404D58: 08 08              or          byte ptr [eax],cl
  00404D5A: 08 08              or          byte ptr [eax],cl
  00404D5C: 08 08              or          byte ptr [eax],cl
  00404D5E: 08 08              or          byte ptr [eax],cl
  00404D60: 08 08              or          byte ptr [eax],cl
  00404D62: 08 08              or          byte ptr [eax],cl
  00404D64: 08 08              or          byte ptr [eax],cl
  00404D66: 08 08              or          byte ptr [eax],cl
  00404D68: 08 08              or          byte ptr [eax],cl
  00404D6A: 08 08              or          byte ptr [eax],cl
  00404D6C: 08 08              or          byte ptr [eax],cl
  00404D6E: 08 08              or          byte ptr [eax],cl
  00404D70: 08 08              or          byte ptr [eax],cl
  00404D72: 08 08              or          byte ptr [eax],cl
  00404D74: 08 08              or          byte ptr [eax],cl
  00404D76: 08 08              or          byte ptr [eax],cl
  00404D78: 55                 push        ebp
  00404D79: 89 E5              mov         ebp,esp
  00404D7B: 83 EC 2C           sub         esp,2Ch
  00404D7E: 57                 push        edi
  00404D7F: 56                 push        esi
  00404D80: 53                 push        ebx
  00404D81: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00404D84: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00404D87: 8B 4D 10           mov         ecx,dword ptr [ebp+10h]
  00404D8A: 8B 5D 14           mov         ebx,dword ptr [ebp+14h]
  00404D8D: 89 CE              mov         esi,ecx
  00404D8F: 89 DF              mov         edi,ebx
  00404D91: 89 45 FC           mov         dword ptr [ebp-4],eax
  00404D94: 89 55 EC           mov         dword ptr [ebp-14h],edx
  00404D97: 85 FF              test        edi,edi
  00404D99: 75 39              jne         00404DD4
  00404D9B: 39 D6              cmp         esi,edx
  00404D9D: 76 09              jbe         00404DA8
  00404D9F: F7 F6              div         eax,esi
  00404DA1: 89 C7              mov         edi,eax
  00404DA3: E9 AD 00 00 00     jmp         00404E55
  00404DA8: 85 C9              test        ecx,ecx
  00404DAA: 75 0D              jne         00404DB9
  00404DAC: B9 01 00 00 00     mov         ecx,1
  00404DB1: 89 C8              mov         eax,ecx
  00404DB3: 31 D2              xor         edx,edx
  00404DB5: F7 F6              div         eax,esi
  00404DB7: 89 C6              mov         esi,eax
  00404DB9: 8B 45 EC           mov         eax,dword ptr [ebp-14h]
  00404DBC: 89 FA              mov         edx,edi
  00404DBE: F7 F6              div         eax,esi
  00404DC0: 89 C1              mov         ecx,eax
  00404DC2: 89 55 EC           mov         dword ptr [ebp-14h],edx
  00404DC5: 8B 45 FC           mov         eax,dword ptr [ebp-4]
  00404DC8: F7 F6              div         eax,esi
  00404DCA: 89 C7              mov         edi,eax
  00404DCC: E9 86 00 00 00     jmp         00404E57
  00404DD1: 8D 76 00           lea         esi,[esi]
  00404DD4: 3B 7D EC           cmp         edi,dword ptr [ebp-14h]
  00404DD7: 76 07              jbe         00404DE0
  00404DD9: 31 FF              xor         edi,edi
  00404DDB: EB 78              jmp         00404E55
  00404DDD: 8D 76 00           lea         esi,[esi]
  00404DE0: 0F BD DF           bsr         ebx,edi
  00404DE3: 83 F3 1F           xor         ebx,1Fh
  00404DE6: 75 14              jne         00404DFC
  00404DE8: 39 7D EC           cmp         dword ptr [ebp-14h],edi
  00404DEB: 77 07              ja          00404DF4
  00404DED: 39 75 FC           cmp         dword ptr [ebp-4],esi
  00404DF0: 72 E7              jb          00404DD9
  00404DF2: 89 F6              mov         esi,esi
  00404DF4: BF 01 00 00 00     mov         edi,1
  00404DF9: EB 5A              jmp         00404E55
  00404DFB: 90                 nop
  00404DFC: C7 45 F8 20 00 00  mov         dword ptr [ebp-8],20h
            00
  00404E03: 29 5D F8           sub         dword ptr [ebp-8],ebx
  00404E06: 89 D9              mov         ecx,ebx
  00404E08: D3 E7              shl         edi,cl
  00404E0A: 89 7D E8           mov         dword ptr [ebp-18h],edi
  00404E0D: 89 F7              mov         edi,esi
  00404E0F: 8B 4D F8           mov         ecx,dword ptr [ebp-8]
  00404E12: D3 EF              shr         edi,cl
  00404E14: 09 7D E8           or          dword ptr [ebp-18h],edi
  00404E17: 89 D9              mov         ecx,ebx
  00404E19: D3 E6              shl         esi,cl
  00404E1B: 8B 7D EC           mov         edi,dword ptr [ebp-14h]
  00404E1E: 8B 4D F8           mov         ecx,dword ptr [ebp-8]
  00404E21: D3 EF              shr         edi,cl
  00404E23: 8B 45 EC           mov         eax,dword ptr [ebp-14h]
  00404E26: 89 D9              mov         ecx,ebx
  00404E28: D3 E0              shl         eax,cl
  00404E2A: 8B 55 FC           mov         edx,dword ptr [ebp-4]
  00404E2D: 8B 4D F8           mov         ecx,dword ptr [ebp-8]
  00404E30: D3 EA              shr         edx,cl
  00404E32: 09 D0              or          eax,edx
  00404E34: 89 45 E4           mov         dword ptr [ebp-1Ch],eax
  00404E37: 89 D9              mov         ecx,ebx
  00404E39: D3 65 FC           shl         dword ptr [ebp-4],cl
  00404E3C: 89 FA              mov         edx,edi
  00404E3E: F7 75 E8           div         eax,dword ptr [ebp-18h]
  00404E41: 89 C7              mov         edi,eax
  00404E43: 89 D1              mov         ecx,edx
  00404E45: F7 E6              mul         eax,esi
  00404E47: 89 C3              mov         ebx,eax
  00404E49: 39 CA              cmp         edx,ecx
  00404E4B: 77 07              ja          00404E54
  00404E4D: 75 06              jne         00404E55
  00404E4F: 3B 5D FC           cmp         ebx,dword ptr [ebp-4]
  00404E52: 76 01              jbe         00404E55
  00404E54: 4F                 dec         edi
  00404E55: 31 C9              xor         ecx,ecx
  00404E57: 89 7D F0           mov         dword ptr [ebp-10h],edi
  00404E5A: 89 4D F4           mov         dword ptr [ebp-0Ch],ecx
  00404E5D: 8B 45 F0           mov         eax,dword ptr [ebp-10h]
  00404E60: 8B 55 F4           mov         edx,dword ptr [ebp-0Ch]
  00404E63: 5B                 pop         ebx
  00404E64: 5E                 pop         esi
  00404E65: 5F                 pop         edi
  00404E66: C9                 leave
  00404E67: C3                 ret
  00404E68: 00 01              add         byte ptr [ecx],al
  00404E6A: 02 02              add         al,byte ptr [edx]
  00404E6C: 03 03              add         eax,dword ptr [ebx]
  00404E6E: 03 03              add         eax,dword ptr [ebx]
  00404E70: 04 04              add         al,4
  00404E72: 04 04              add         al,4
  00404E74: 04 04              add         al,4
  00404E76: 04 04              add         al,4
  00404E78: 05 05 05 05 05     add         eax,5050505h
  00404E7D: 05 05 05 05 05     add         eax,5050505h
  00404E82: 05 05 05 05 05     add         eax,5050505h
  00404E87: 05 06 06 06 06     add         eax,6060606h
  00404E8C: 06                 push        es
  00404E8D: 06                 push        es
  00404E8E: 06                 push        es
  00404E8F: 06                 push        es
  00404E90: 06                 push        es
  00404E91: 06                 push        es
  00404E92: 06                 push        es
  00404E93: 06                 push        es
  00404E94: 06                 push        es
  00404E95: 06                 push        es
  00404E96: 06                 push        es
  00404E97: 06                 push        es
  00404E98: 06                 push        es
  00404E99: 06                 push        es
  00404E9A: 06                 push        es
  00404E9B: 06                 push        es
  00404E9C: 06                 push        es
  00404E9D: 06                 push        es
  00404E9E: 06                 push        es
  00404E9F: 06                 push        es
  00404EA0: 06                 push        es
  00404EA1: 06                 push        es
  00404EA2: 06                 push        es
  00404EA3: 06                 push        es
  00404EA4: 06                 push        es
  00404EA5: 06                 push        es
  00404EA6: 06                 push        es
  00404EA7: 06                 push        es
  00404EA8: 07                 pop         es
  00404EA9: 07                 pop         es
  00404EAA: 07                 pop         es
  00404EAB: 07                 pop         es
  00404EAC: 07                 pop         es
  00404EAD: 07                 pop         es
  00404EAE: 07                 pop         es
  00404EAF: 07                 pop         es
  00404EB0: 07                 pop         es
  00404EB1: 07                 pop         es
  00404EB2: 07                 pop         es
  00404EB3: 07                 pop         es
  00404EB4: 07                 pop         es
  00404EB5: 07                 pop         es
  00404EB6: 07                 pop         es
  00404EB7: 07                 pop         es
  00404EB8: 07                 pop         es
  00404EB9: 07                 pop         es
  00404EBA: 07                 pop         es
  00404EBB: 07                 pop         es
  00404EBC: 07                 pop         es
  00404EBD: 07                 pop         es
  00404EBE: 07                 pop         es
  00404EBF: 07                 pop         es
  00404EC0: 07                 pop         es
  00404EC1: 07                 pop         es
  00404EC2: 07                 pop         es
  00404EC3: 07                 pop         es
  00404EC4: 07                 pop         es
  00404EC5: 07                 pop         es
  00404EC6: 07                 pop         es
  00404EC7: 07                 pop         es
  00404EC8: 07                 pop         es
  00404EC9: 07                 pop         es
  00404ECA: 07                 pop         es
  00404ECB: 07                 pop         es
  00404ECC: 07                 pop         es
  00404ECD: 07                 pop         es
  00404ECE: 07                 pop         es
  00404ECF: 07                 pop         es
  00404ED0: 07                 pop         es
  00404ED1: 07                 pop         es
  00404ED2: 07                 pop         es
  00404ED3: 07                 pop         es
  00404ED4: 07                 pop         es
  00404ED5: 07                 pop         es
  00404ED6: 07                 pop         es
  00404ED7: 07                 pop         es
  00404ED8: 07                 pop         es
  00404ED9: 07                 pop         es
  00404EDA: 07                 pop         es
  00404EDB: 07                 pop         es
  00404EDC: 07                 pop         es
  00404EDD: 07                 pop         es
  00404EDE: 07                 pop         es
  00404EDF: 07                 pop         es
  00404EE0: 07                 pop         es
  00404EE1: 07                 pop         es
  00404EE2: 07                 pop         es
  00404EE3: 07                 pop         es
  00404EE4: 07                 pop         es
  00404EE5: 07                 pop         es
  00404EE6: 07                 pop         es
  00404EE7: 07                 pop         es
  00404EE8: 08 08              or          byte ptr [eax],cl
  00404EEA: 08 08              or          byte ptr [eax],cl
  00404EEC: 08 08              or          byte ptr [eax],cl
  00404EEE: 08 08              or          byte ptr [eax],cl
  00404EF0: 08 08              or          byte ptr [eax],cl
  00404EF2: 08 08              or          byte ptr [eax],cl
  00404EF4: 08 08              or          byte ptr [eax],cl
  00404EF6: 08 08              or          byte ptr [eax],cl
  00404EF8: 08 08              or          byte ptr [eax],cl
  00404EFA: 08 08              or          byte ptr [eax],cl
  00404EFC: 08 08              or          byte ptr [eax],cl
  00404EFE: 08 08              or          byte ptr [eax],cl
  00404F00: 08 08              or          byte ptr [eax],cl
  00404F02: 08 08              or          byte ptr [eax],cl
  00404F04: 08 08              or          byte ptr [eax],cl
  00404F06: 08 08              or          byte ptr [eax],cl
  00404F08: 08 08              or          byte ptr [eax],cl
  00404F0A: 08 08              or          byte ptr [eax],cl
  00404F0C: 08 08              or          byte ptr [eax],cl
  00404F0E: 08 08              or          byte ptr [eax],cl
  00404F10: 08 08              or          byte ptr [eax],cl
  00404F12: 08 08              or          byte ptr [eax],cl
  00404F14: 08 08              or          byte ptr [eax],cl
  00404F16: 08 08              or          byte ptr [eax],cl
  00404F18: 08 08              or          byte ptr [eax],cl
  00404F1A: 08 08              or          byte ptr [eax],cl
  00404F1C: 08 08              or          byte ptr [eax],cl
  00404F1E: 08 08              or          byte ptr [eax],cl
  00404F20: 08 08              or          byte ptr [eax],cl
  00404F22: 08 08              or          byte ptr [eax],cl
  00404F24: 08 08              or          byte ptr [eax],cl
  00404F26: 08 08              or          byte ptr [eax],cl
  00404F28: 08 08              or          byte ptr [eax],cl
  00404F2A: 08 08              or          byte ptr [eax],cl
  00404F2C: 08 08              or          byte ptr [eax],cl
  00404F2E: 08 08              or          byte ptr [eax],cl
  00404F30: 08 08              or          byte ptr [eax],cl
  00404F32: 08 08              or          byte ptr [eax],cl
  00404F34: 08 08              or          byte ptr [eax],cl
  00404F36: 08 08              or          byte ptr [eax],cl
  00404F38: 08 08              or          byte ptr [eax],cl
  00404F3A: 08 08              or          byte ptr [eax],cl
  00404F3C: 08 08              or          byte ptr [eax],cl
  00404F3E: 08 08              or          byte ptr [eax],cl
  00404F40: 08 08              or          byte ptr [eax],cl
  00404F42: 08 08              or          byte ptr [eax],cl
  00404F44: 08 08              or          byte ptr [eax],cl
  00404F46: 08 08              or          byte ptr [eax],cl
  00404F48: 08 08              or          byte ptr [eax],cl
  00404F4A: 08 08              or          byte ptr [eax],cl
  00404F4C: 08 08              or          byte ptr [eax],cl
  00404F4E: 08 08              or          byte ptr [eax],cl
  00404F50: 08 08              or          byte ptr [eax],cl
  00404F52: 08 08              or          byte ptr [eax],cl
  00404F54: 08 08              or          byte ptr [eax],cl
  00404F56: 08 08              or          byte ptr [eax],cl
  00404F58: 08 08              or          byte ptr [eax],cl
  00404F5A: 08 08              or          byte ptr [eax],cl
  00404F5C: 08 08              or          byte ptr [eax],cl
  00404F5E: 08 08              or          byte ptr [eax],cl
  00404F60: 08 08              or          byte ptr [eax],cl
  00404F62: 08 08              or          byte ptr [eax],cl
  00404F64: 08 08              or          byte ptr [eax],cl
  00404F66: 08 08              or          byte ptr [eax],cl
  00404F68: 55                 push        ebp
  00404F69: 89 E5              mov         ebp,esp
  00404F6B: 83 EC 4C           sub         esp,4Ch
  00404F6E: 57                 push        edi
  00404F6F: 56                 push        esi
  00404F70: 53                 push        ebx
  00404F71: 8B 45 08           mov         eax,dword ptr [ebp+8]
  00404F74: 8B 55 0C           mov         edx,dword ptr [ebp+0Ch]
  00404F77: 89 45 F0           mov         dword ptr [ebp-10h],eax
  00404F7A: 89 55 F4           mov         dword ptr [ebp-0Ch],edx
  00404F7D: 8B 55 10           mov         edx,dword ptr [ebp+10h]
  00404F80: 8B 4D 14           mov         ecx,dword ptr [ebp+14h]
  00404F83: 89 55 C8           mov         dword ptr [ebp-38h],edx
  00404F86: 89 4D CC           mov         dword ptr [ebp-34h],ecx
  00404F89: 8D 4D F8           lea         ecx,[ebp-8]
  00404F8C: 89 4D EC           mov         dword ptr [ebp-14h],ecx
  00404F8F: 8B 7D C8           mov         edi,dword ptr [ebp-38h]
  00404F92: 8B 45 CC           mov         eax,dword ptr [ebp-34h]
  00404F95: 89 45 E8           mov         dword ptr [ebp-18h],eax
  00404F98: 8B 55 F0           mov         edx,dword ptr [ebp-10h]
  00404F9B: 89 55 E4           mov         dword ptr [ebp-1Ch],edx
  00404F9E: 8B 4D F4           mov         ecx,dword ptr [ebp-0Ch]
  00404FA1: 89 4D C4           mov         dword ptr [ebp-3Ch],ecx
  00404FA4: 85 C0              test        eax,eax
  00404FA6: 75 44              jne         00404FEC
  00404FA8: 39 CF              cmp         edi,ecx
  00404FAA: 76 08              jbe         00404FB4
  00404FAC: 89 D0              mov         eax,edx
  00404FAE: 89 CA              mov         edx,ecx
  00404FB0: F7 F7              div         eax,edi
  00404FB2: EB 21              jmp         00404FD5
  00404FB4: 83 7D C8 00        cmp         dword ptr [ebp-38h],0
  00404FB8: 75 0B              jne         00404FC5
  00404FBA: B8 01 00 00 00     mov         eax,1
  00404FBF: 31 D2              xor         edx,edx
  00404FC1: F7 F7              div         eax,edi
  00404FC3: 89 C7              mov         edi,eax
  00404FC5: 8B 45 C4           mov         eax,dword ptr [ebp-3Ch]
  00404FC8: 8B 55 E8           mov         edx,dword ptr [ebp-18h]
  00404FCB: F7 F7              div         eax,edi
  00404FCD: 89 55 C4           mov         dword ptr [ebp-3Ch],edx
  00404FD0: 8B 45 E4           mov         eax,dword ptr [ebp-1Ch]
  00404FD3: F7 F7              div         eax,edi
  00404FD5: 89 55 E4           mov         dword ptr [ebp-1Ch],edx
  00404FD8: 83 7D EC 00        cmp         dword ptr [ebp-14h],0
  00404FDC: 0F 84 07 01 00 00  je          004050E9
  00404FE2: 8B 5D E4           mov         ebx,dword ptr [ebp-1Ch]
  00404FE5: 31 F6              xor         esi,esi
  00404FE7: EB 58              jmp         00405041
  00404FE9: 8D 76 00           lea         esi,[esi]
  00404FEC: 8B 45 C4           mov         eax,dword ptr [ebp-3Ch]
  00404FEF: 39 45 E8           cmp         dword ptr [ebp-18h],eax
  00404FF2: 76 10              jbe         00405004
  00404FF4: 8B 5D F0           mov         ebx,dword ptr [ebp-10h]
  00404FF7: 89 C6              mov         esi,eax
  00404FF9: 89 5D F8           mov         dword ptr [ebp-8],ebx
  00404FFC: 89 75 FC           mov         dword ptr [ebp-4],esi
  00404FFF: E9 E5 00 00 00     jmp         004050E9
  00405004: 0F BD 55 E8        bsr         edx,dword ptr [ebp-18h]
  00405008: 83 F2 1F           xor         edx,1Fh
  0040500B: 89 55 E0           mov         dword ptr [ebp-20h],edx
  0040500E: 75 40              jne         00405050
  00405010: 8B 4D E8           mov         ecx,dword ptr [ebp-18h]
  00405013: 39 4D C4           cmp         dword ptr [ebp-3Ch],ecx
  00405016: 77 08              ja          00405020
  00405018: 39 7D E4           cmp         dword ptr [ebp-1Ch],edi
  0040501B: 72 14              jb          00405031
  0040501D: 8D 76 00           lea         esi,[esi]
  00405020: 8B 55 C4           mov         edx,dword ptr [ebp-3Ch]
  00405023: 8B 45 E4           mov         eax,dword ptr [ebp-1Ch]
  00405026: 29 F8              sub         eax,edi
  00405028: 1B 55 E8           sbb         edx,dword ptr [ebp-18h]
  0040502B: 89 55 C4           mov         dword ptr [ebp-3Ch],edx
  0040502E: 89 45 E4           mov         dword ptr [ebp-1Ch],eax
  00405031: 83 7D EC 00        cmp         dword ptr [ebp-14h],0
  00405035: 0F 84 AE 00 00 00  je          004050E9
  0040503B: 8B 5D E4           mov         ebx,dword ptr [ebp-1Ch]
  0040503E: 8B 75 C4           mov         esi,dword ptr [ebp-3Ch]
  00405041: 8B 4D EC           mov         ecx,dword ptr [ebp-14h]
  00405044: 89 19              mov         dword ptr [ecx],ebx
  00405046: 89 71 04           mov         dword ptr [ecx+4],esi
  00405049: E9 9B 00 00 00     jmp         004050E9
  0040504E: 89 F6              mov         esi,esi
  00405050: C7 45 DC 20 00 00  mov         dword ptr [ebp-24h],20h
            00
  00405057: 8B 45 E0           mov         eax,dword ptr [ebp-20h]
  0040505A: 29 45 DC           sub         dword ptr [ebp-24h],eax
  0040505D: 89 C1              mov         ecx,eax
  0040505F: D3 65 E8           shl         dword ptr [ebp-18h],cl
  00405062: 89 F8              mov         eax,edi
  00405064: 8B 4D DC           mov         ecx,dword ptr [ebp-24h]
  00405067: D3 E8              shr         eax,cl
  00405069: 09 45 E8           or          dword ptr [ebp-18h],eax
  0040506C: 8B 4D E0           mov         ecx,dword ptr [ebp-20h]
  0040506F: D3 E7              shl         edi,cl
  00405071: 8B 55 C4           mov         edx,dword ptr [ebp-3Ch]
  00405074: 8B 4D DC           mov         ecx,dword ptr [ebp-24h]
  00405077: D3 EA              shr         edx,cl
  00405079: 8B 4D E0           mov         ecx,dword ptr [ebp-20h]
  0040507C: D3 65 C4           shl         dword ptr [ebp-3Ch],cl
  0040507F: 8B 45 E4           mov         eax,dword ptr [ebp-1Ch]
  00405082: 8B 4D DC           mov         ecx,dword ptr [ebp-24h]
  00405085: D3 E8              shr         eax,cl
  00405087: 09 45 C4           or          dword ptr [ebp-3Ch],eax
  0040508A: 8B 4D E0           mov         ecx,dword ptr [ebp-20h]
  0040508D: D3 65 E4           shl         dword ptr [ebp-1Ch],cl
  00405090: 8B 45 C4           mov         eax,dword ptr [ebp-3Ch]
  00405093: F7 75 E8           div         eax,dword ptr [ebp-18h]
  00405096: 89 55 C4           mov         dword ptr [ebp-3Ch],edx
  00405099: F7 E7              mul         eax,edi
  0040509B: 89 45 C8           mov         dword ptr [ebp-38h],eax
  0040509E: 3B 55 C4           cmp         edx,dword ptr [ebp-3Ch]
  004050A1: 77 0A              ja          004050AD
  004050A3: 75 13              jne         004050B8
  004050A5: 8B 45 E4           mov         eax,dword ptr [ebp-1Ch]
  004050A8: 39 45 C8           cmp         dword ptr [ebp-38h],eax
  004050AB: 76 0B              jbe         004050B8
  004050AD: 8B 4D C8           mov         ecx,dword ptr [ebp-38h]
  004050B0: 29 F9              sub         ecx,edi
  004050B2: 1B 55 E8           sbb         edx,dword ptr [ebp-18h]
  004050B5: 89 4D C8           mov         dword ptr [ebp-38h],ecx
  004050B8: 83 7D EC 00        cmp         dword ptr [ebp-14h],0
  004050BC: 74 2B              je          004050E9
  004050BE: 8B 4D C4           mov         ecx,dword ptr [ebp-3Ch]
  004050C1: 8B 45 E4           mov         eax,dword ptr [ebp-1Ch]
  004050C4: 2B 45 C8           sub         eax,dword ptr [ebp-38h]
  004050C7: 19 D1              sbb         ecx,edx
  004050C9: 89 4D C4           mov         dword ptr [ebp-3Ch],ecx
  004050CC: 89 CA              mov         edx,ecx
  004050CE: 8B 4D DC           mov         ecx,dword ptr [ebp-24h]
  004050D1: D3 E2              shl         edx,cl
  004050D3: 8B 4D E0           mov         ecx,dword ptr [ebp-20h]
  004050D6: D3 E8              shr         eax,cl
  004050D8: 89 C3              mov         ebx,eax
  004050DA: 09 D3              or          ebx,edx
  004050DC: 8B 75 C4           mov         esi,dword ptr [ebp-3Ch]
  004050DF: D3 EE              shr         esi,cl
  004050E1: 8B 45 EC           mov         eax,dword ptr [ebp-14h]
  004050E4: 89 18              mov         dword ptr [eax],ebx
  004050E6: 89 70 04           mov         dword ptr [eax+4],esi
  004050E9: 8B 45 F8           mov         eax,dword ptr [ebp-8]
  004050EC: 8B 55 FC           mov         edx,dword ptr [ebp-4]
  004050EF: 5B                 pop         ebx
  004050F0: 5E                 pop         esi
  004050F1: 5F                 pop         edi
  004050F2: C9                 leave
  004050F3: C3                 ret
  004050F4: FF 25 40 81 40 00  jmp         dword ptr ds:[00408140h]
  004050FA: 90                 nop
  004050FB: 90                 nop
  004050FC: FF 25 48 81 40 00  jmp         dword ptr ds:[00408148h]
  00405102: 90                 nop
  00405103: 90                 nop
  00405104: FF 25 44 81 40 00  jmp         dword ptr ds:[00408144h]
  0040510A: 90                 nop
  0040510B: 90                 nop
  0040510C: FF 25 4C 81 40 00  jmp         dword ptr ds:[0040814Ch]
  00405112: 90                 nop
  00405113: 90                 nop
  00405114: 55                 push        ebp
  00405115: 89 E5              mov         ebp,esp
  00405117: 83 EC 08           sub         esp,8
  0040511A: 83 C4 F8           add         esp,0FFFFFFF8h
  0040511D: FF 75 0C           push        dword ptr [ebp+0Ch]
  00405120: FF 75 08           push        dword ptr [ebp+8]
  00405123: E8 78 01 00 00     call        004052A0
  00405128: C9                 leave
  00405129: C3                 ret
  0040512A: 89 F6              mov         esi,esi
  0040512C: 55                 push        ebp
  0040512D: 89 E5              mov         ebp,esp
  0040512F: 83 EC 08           sub         esp,8
  00405132: 83 C4 FC           add         esp,0FFFFFFFCh
  00405135: FF 75 10           push        dword ptr [ebp+10h]
  00405138: FF 75 0C           push        dword ptr [ebp+0Ch]
  0040513B: FF 75 08           push        dword ptr [ebp+8]
  0040513E: E8 55 01 00 00     call        00405298
  00405143: C9                 leave
  00405144: C3                 ret
  00405145: 8D 76 00           lea         esi,[esi]
  00405148: 55                 push        ebp
  00405149: 89 E5              mov         ebp,esp
  0040514B: 83 EC 08           sub         esp,8
  0040514E: 83 C4 F8           add         esp,0FFFFFFF8h
  00405151: FF 75 0C           push        dword ptr [ebp+0Ch]
  00405154: FF 75 08           push        dword ptr [ebp+8]
  00405157: E8 34 01 00 00     call        00405290
  0040515C: C9                 leave
  0040515D: C3                 ret
  0040515E: 89 F6              mov         esi,esi
  00405160: FF 25 60 81 40 00  jmp         dword ptr ds:[00408160h]
  00405166: 90                 nop
  00405167: 90                 nop
  00405168: FF 25 68 81 40 00  jmp         dword ptr ds:[00408168h]
  0040516E: 90                 nop
  0040516F: 90                 nop
  00405170: FF 25 5C 81 40 00  jmp         dword ptr ds:[0040815Ch]
  00405176: 90                 nop
  00405177: 90                 nop
  00405178: FF 25 78 81 40 00  jmp         dword ptr ds:[00408178h]
  0040517E: 90                 nop
  0040517F: 90                 nop
  00405180: FF 25 E4 81 40 00  jmp         dword ptr ds:[004081E4h]
  00405186: 90                 nop
  00405187: 90                 nop
  00405188: FF 25 70 81 40 00  jmp         dword ptr ds:[00408170h]
  0040518E: 90                 nop
  0040518F: 90                 nop
  00405190: FF 25 80 81 40 00  jmp         dword ptr ds:[00408180h]
  00405196: 90                 nop
  00405197: 90                 nop
  00405198: FF 25 58 81 40 00  jmp         dword ptr ds:[00408158h]
  0040519E: 90                 nop
  0040519F: 90                 nop
  004051A0: FF 25 94 81 40 00  jmp         dword ptr ds:[00408194h]
  004051A6: 90                 nop
  004051A7: 90                 nop
  004051A8: FF 25 E0 81 40 00  jmp         dword ptr ds:[004081E0h]
  004051AE: 90                 nop
  004051AF: 90                 nop
  004051B0: FF 25 D8 81 40 00  jmp         dword ptr ds:[004081D8h]
  004051B6: 90                 nop
  004051B7: 90                 nop
  004051B8: FF 25 A0 81 40 00  jmp         dword ptr ds:[004081A0h]
  004051BE: 90                 nop
  004051BF: 90                 nop
  004051C0: FF 25 A4 81 40 00  jmp         dword ptr ds:[004081A4h]
  004051C6: 90                 nop
  004051C7: 90                 nop
  004051C8: FF 25 B8 81 40 00  jmp         dword ptr ds:[004081B8h]
  004051CE: 90                 nop
  004051CF: 90                 nop
  004051D0: FF 25 6C 81 40 00  jmp         dword ptr ds:[0040816Ch]
  004051D6: 90                 nop
  004051D7: 90                 nop
  004051D8: FF 25 AC 81 40 00  jmp         dword ptr ds:[004081ACh]
  004051DE: 90                 nop
  004051DF: 90                 nop
  004051E0: FF 25 9C 81 40 00  jmp         dword ptr ds:[0040819Ch]
  004051E6: 90                 nop
  004051E7: 90                 nop
  004051E8: FF 25 B4 81 40 00  jmp         dword ptr ds:[004081B4h]
  004051EE: 90                 nop
  004051EF: 90                 nop
  004051F0: FF 25 D0 81 40 00  jmp         dword ptr ds:[004081D0h]
  004051F6: 90                 nop
  004051F7: 90                 nop
  004051F8: FF 25 B0 81 40 00  jmp         dword ptr ds:[004081B0h]
  004051FE: 90                 nop
  004051FF: 90                 nop
  00405200: FF 25 F8 81 40 00  jmp         dword ptr ds:[004081F8h]
  00405206: 90                 nop
  00405207: 90                 nop
  00405208: FF 25 BC 81 40 00  jmp         dword ptr ds:[004081BCh]
  0040520E: 90                 nop
  0040520F: 90                 nop
  00405210: FF 25 D4 81 40 00  jmp         dword ptr ds:[004081D4h]
  00405216: 90                 nop
  00405217: 90                 nop
  00405218: FF 25 90 81 40 00  jmp         dword ptr ds:[00408190h]
  0040521E: 90                 nop
  0040521F: 90                 nop
  00405220: FF 25 E8 81 40 00  jmp         dword ptr ds:[004081E8h]
  00405226: 90                 nop
  00405227: 90                 nop
  00405228: FF 25 F0 81 40 00  jmp         dword ptr ds:[004081F0h]
  0040522E: 90                 nop
  0040522F: 90                 nop
  00405230: FF 25 A8 81 40 00  jmp         dword ptr ds:[004081A8h]
  00405236: 90                 nop
  00405237: 90                 nop
  00405238: FF 25 00 82 40 00  jmp         dword ptr ds:[00408200h]
  0040523E: 90                 nop
  0040523F: 90                 nop
  00405240: FF 25 F4 81 40 00  jmp         dword ptr ds:[004081F4h]
  00405246: 90                 nop
  00405247: 90                 nop
  00405248: FF 25 CC 81 40 00  jmp         dword ptr ds:[004081CCh]
  0040524E: 90                 nop
  0040524F: 90                 nop
  00405250: FF 25 C0 81 40 00  jmp         dword ptr ds:[004081C0h]
  00405256: 90                 nop
  00405257: 90                 nop
  00405258: FF 25 EC 81 40 00  jmp         dword ptr ds:[004081ECh]
  0040525E: 90                 nop
  0040525F: 90                 nop
  00405260: FF 25 FC 81 40 00  jmp         dword ptr ds:[004081FCh]
  00405266: 90                 nop
  00405267: 90                 nop
  00405268: FF 25 C4 81 40 00  jmp         dword ptr ds:[004081C4h]
  0040526E: 90                 nop
  0040526F: 90                 nop
  00405270: FF 25 64 81 40 00  jmp         dword ptr ds:[00408164h]
  00405276: 90                 nop
  00405277: 90                 nop
  00405278: FF 25 98 81 40 00  jmp         dword ptr ds:[00408198h]
  0040527E: 90                 nop
  0040527F: 90                 nop
  00405280: FF 25 DC 81 40 00  jmp         dword ptr ds:[004081DCh]
  00405286: 90                 nop
  00405287: 90                 nop
  00405288: FF 25 C8 81 40 00  jmp         dword ptr ds:[004081C8h]
  0040528E: 90                 nop
  0040528F: 90                 nop
  00405290: FF 25 8C 81 40 00  jmp         dword ptr ds:[0040818Ch]
  00405296: 90                 nop
  00405297: 90                 nop
  00405298: FF 25 88 81 40 00  jmp         dword ptr ds:[00408188h]
  0040529E: 90                 nop
  0040529F: 90                 nop
  004052A0: FF 25 84 81 40 00  jmp         dword ptr ds:[00408184h]
  004052A6: 90                 nop
  004052A7: 90                 nop
  004052A8: FF 25 34 81 40 00  jmp         dword ptr ds:[00408134h]
  004052AE: 90                 nop
  004052AF: 90                 nop
  004052B0: FF 25 30 81 40 00  jmp         dword ptr ds:[00408130h]
  004052B6: 90                 nop
  004052B7: 90                 nop
  004052B8: FF
  004052B9: FF
  004052BA: FF
  004052BB: FF 00              inc         dword ptr [eax]
  004052BD: 00 00              add         byte ptr [eax],al
  004052BF: 00 FF              add         bh,bh
  004052C1: FF
  004052C2: FF
  004052C3: FF 00              inc         dword ptr [eax]
  004052C5: 00 00              add         byte ptr [eax],al
  004052C7: 00

  Summary

        1000 .bss
        1000 .data
        1000 .idata
        5000 .text
