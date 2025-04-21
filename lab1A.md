## 1. 문제 확인
- ID : lab1A
- Target : /level/lab01/lab1A
- flag : /home/lab1end/.pass
```
	lab1A@warzone:/levels/lab01$ ./lab1A
	.---------------------------.
	|---------  RPISEC  --------|
	|+ SECURE LOGIN SYS v. 3.0 +|
	|---------------------------|
	|~- Enter your Username:  ~-|
	'---------------------------'
	g4nzzi
	.---------------------------.
	| !! NEW ACCOUNT DETECTED !!|
	|---------------------------|
	|~- Input your serial:    ~-|
	'---------------------------'
	a12345678
	lab1A@warzone:/levels/lab01$
```

<br/><br/>
## 2. 코드 분석
### 2.1 main()

-  main()에는 StackGuard(Canary)가 적용되어 있음
```
   0x08048b4d <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048b50 <+12>:    mov    DWORD PTR [esp+0xc],eax
   0x08048b54 <+16>:    mov    eax,gs:0x14
   0x08048b5a <+22>:    mov    DWORD PTR [esp+0x3c],eax
   0x08048b5e <+26>:    xor    eax,eax
   0x08048b60 <+28>:    push   eax
   ...
   0x08048c5a <+278>:   mov    edx,DWORD PTR [esp+0x3c]
   0x08048c5e <+282>:   xor    edx,DWORD PTR gs:0x14
   0x08048c65 <+289>:   je     0x8048c6c <main+296>
   0x08048c67 <+291>:   call   0x8048800 <__stack_chk_fail@plt>
```
- fgets()로 Username을 입력받고 scanf()로 serial을 입력 받은 후, 입력받은 값으로 auth()를 호출
- auth() 리턴값이 0이면 쉘 획득
```
   0x08048bb1 <+109>:   mov    eax,ds:0x804b060
   0x08048bb6 <+114>:   mov    DWORD PTR [esp+0x8],eax
   0x08048bba <+118>:   mov    DWORD PTR [esp+0x4],0x20 
   0x08048bc2 <+126>:   lea    eax,[esp+0x1c]
   0x08048bc6 <+130>:   mov    DWORD PTR [esp],eax
   0x08048bc9 <+133>:   call   0x80487d0 <fgets@plt>
   ...
   0x08048c0a <+198>:   lea    eax,[esp+0x18]
   0x08048c0e <+202>:   mov    DWORD PTR [esp+0x4],eax
   0x08048c12 <+206>:   mov    DWORD PTR [esp],0x8048d00
   0x08048c19 <+213>:   call   0x8048860 <__isoc99_scanf@plt>	
   0x08048c1e <+218>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048c22 <+222>:   mov    DWORD PTR [esp+0x4],eax
   0x08048c26 <+226>:   lea    eax,[esp+0x1c]
   0x08048c2a <+230>:   mov    DWORD PTR [esp],eax
   0x08048c2d <+233>:   call   0x8048a0f <auth>
   0x08048c32 <+238>:   test   eax,eax
   0x08048c34 <+240>:   jne    0x8048c55 <main+273>
   0x08048c36 <+242>:   mov    DWORD PTR [esp],0x8048e63
   0x08048c3d <+249>:   call   0x8048810 <puts@plt>
   0x08048c42 <+254>:   mov    DWORD PTR [esp],0x8048e72
   0x08048c49 <+261>:   call   0x8048820 <system@plt>
```
```c
	fgets(Username, 0x20, stdin)
    ...
    scanf("%u", serial)
    if(auth(Username, serial) == 0)
    	puts("Authenticated!")
        system("/bin/sh")
```
### 2.2 auth()
- strnlen()으로 Username 입력값 길이(0x5)를 체크하고, ptrace()로 디버깅 여부를 체크하여 
  강제 종료 시킴
```
   0x08048a30 <+33>:    mov    DWORD PTR [esp+0x4],0x20
   0x08048a38 <+41>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048a3b <+44>:    mov    DWORD PTR [esp],eax
   0x08048a3e <+47>:    call   0x8048850 <strnlen@plt>
   0x08048a43 <+52>:    mov    DWORD PTR [ebp-0xc],eax
   ...
   0x08048a4f <+64>:    cmp    DWORD PTR [ebp-0xc],0x5
   0x08048a53 <+68>:    jg     0x8048a5f <auth+80>
   0x08048a55 <+70>:    mov    eax,0x1
   0x08048a5a <+75>:    jmp    0x8048b42 <auth+307>
   0x08048a5f <+80>:    mov    DWORD PTR [esp+0xc],0x0
   0x08048a67 <+88>:    mov    DWORD PTR [esp+0x8],0x1
   0x08048a6f <+96>:    mov    DWORD PTR [esp+0x4],0x0
   0x08048a77 <+104>:   mov    DWORD PTR [esp],0x0
   0x08048a7e <+111>:   call   0x8048870 <ptrace@plt>
   0x08048a83 <+116>:   cmp    eax,0xffffffff
   0x08048a86 <+119>:   jne    0x8048ab6 <auth+167>
   0x08048a88 <+121>:   mov    DWORD PTR [esp],0x8048d08
   0x08048a8f <+128>:   call   0x8048810 <puts@plt>
   0x08048a94 <+133>:   mov    DWORD PTR [esp],0x8048d2c
   0x08048a9b <+140>:   call   0x8048810 <puts@plt>
   0x08048aa0 <+145>:   mov    DWORD PTR [esp],0x8048d50
   0x08048aa7 <+152>:   call   0x8048810 <puts@plt>
   0x08048aac <+157>:   mov    eax,0x1
   0x08048ab1 <+162>:   jmp    0x8048b42 <auth+307>
```
```
	gdb-peda$ x/s 0x8048d08
	0x8048d08:      "\033[32m.", '-' <repeats 27 times>, "."
	gdb-peda$ x/s 0x8048d2c
	0x8048d2c:      "\033[31m| !! TAMPERING DETECTED !!  |"
	gdb-peda$ x/s 0x8048d50
	0x8048d50:      "\033[32m'", '-' <repeats 27 times>, "'"
   
```
```c
	...
    if(strnlen(Username, 0x20) > 5)
    	if(ptrace(0, 0, 1, 0) == -1)
    		puts("!! TAMPERING DETECTED !!")
        	return 1
    ...
    else
    	return 1
```
- Username 입력값의 네번째 값을 연산하여 임시(temp) 저장
```
   0x08048ab6 <+167>:   mov    eax,DWORD PTR [ebp+0x8]
   0x08048ab9 <+170>:   add    eax,0x3
   0x08048abc <+173>:   movzx  eax,BYTE PTR [eax]
   0x08048abf <+176>:   movsx  eax,al
   0x08048ac2 <+179>:   xor    eax,0x1337
   0x08048ac7 <+184>:   add    eax,0x5eeded
   0x08048acc <+189>:   mov    DWORD PTR [ebp-0x10],eax
   0x08048acf <+192>:   mov    DWORD PTR [ebp-0x14],0x0
```
```c
	temp = (Username[3] ^ 0x1337) + 0x5eeded
```
- Username 입력값을 하나씩 체크(0x1f와 비교)하여 만족할 경우, 이후 연산을 반복 진행
```
   0x08048ad8 <+201>:   mov    edx,DWORD PTR [ebp-0x14]
   0x08048adb <+204>:   mov    eax,DWORD PTR [ebp+0x8]
   0x08048ade <+207>:   add    eax,edx
   0x08048ae0 <+209>:   movzx  eax,BYTE PTR [eax]
   0x08048ae3 <+212>:   cmp    al,0x1f
   0x08048ae5 <+214>:   jg     0x8048aee <auth+223>
   0x08048ae7 <+216>:   mov    eax,0x1
   0x08048aec <+221>:   jmp    0x8048b42 <auth+307>
   0x08048aee <+223>:   mov    edx,DWORD PTR [ebp-0x14]
   0x08048af1 <+226>:   mov    eax,DWORD PTR [ebp+0x8]
   0x08048af4 <+229>:   add    eax,edx
   0x08048af6 <+231>:   movzx  eax,BYTE PTR [eax]
   0x08048af9 <+234>:   movsx  eax,al
   0x08048afc <+237>:   xor    eax,DWORD PTR [ebp-0x10]
   0x08048aff <+240>:   mov    ecx,eax
   0x08048b01 <+242>:   mov    edx,0x88233b2b
   0x08048b06 <+247>:   mov    eax,ecx
   0x08048b08 <+249>:   mul    edx
   0x08048b0a <+251>:   mov    eax,ecx
   0x08048b0c <+253>:   sub    eax,edx
   0x08048b0e <+255>:   shr    eax,1
   0x08048b10 <+257>:   add    eax,edx
   0x08048b12 <+259>:   shr    eax,0xa
   0x08048b15 <+262>:   imul   eax,eax,0x539
   0x08048b1b <+268>:   sub    ecx,eax
   0x08048b1d <+270>:   mov    eax,ecx
   0x08048b1f <+272>:   add    DWORD PTR [ebp-0x10],eax
   0x08048b22 <+275>:   add    DWORD PTR [ebp-0x14],0x1
   0x08048b26 <+279>:   mov    eax,DWORD PTR [ebp-0x14]
   0x08048b29 <+282>:   cmp    eax,DWORD PTR [ebp-0xc]
   0x08048b2c <+285>:   jl     0x8048ad8 <auth+201>
```
```c
	for(i=0; i < strlen(Username); i++)
    	if(Username[i] > 0x1f)
        	v1 = Username[i] ^ temp
        	v2 = (v1 * 0x88233b2b) >> 32
            v3 = (v1 - v2) >> 1
            v3 = (v3 + v2) >> 0xa
            v3 = v2 - (v3 * 0x539)
            temp += v3
        else
			return 1
```
- 연산이 끝난 임시(temp)값과 serial 입력값을 비교하여 일치할 경우에만 0x0을 리턴
```
   0x08048b2e <+287>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048b31 <+290>:   cmp    eax,DWORD PTR [ebp-0x10]
   0x08048b34 <+293>:   je     0x8048b3d <auth+302>
   0x08048b36 <+295>:   mov    eax,0x1
   0x08048b3b <+300>:   jmp    0x8048b42 <auth+307>
   0x08048b3d <+302>:   mov    eax,0x0
   0x08048b42 <+307>:   leave
   0x08048b43 <+308>:   ret
```
```c
	if(temp == serial)
    	return 0
    else
    	return 1
```

<br/><br/>
## 3. exploit
- Username 입력값에 따른 serial 생성 코드를 분석 했으니, 동일한 로직의 코드를 작성하여 
serial 획득 가능
```python
	Username = input("Username : ")

	if len(Username) > 5 :
    	temp = ((ord(Username[3])) ^ int('0x1337', 16)) + int('0x5eeded', 16)
    
    	for i in range(0, len(Username)) :
        	if (ord(Username[i])) > int('0x1f', 16) :
            	v1 = (ord(Username[i])) ^ temp
            	v2 = (v1 * int('0x88233b2b', 16)) >> 32
            	v3 = (v1 - v2) >> 1
            	v3 = (v3 + v2) >> int('0xa', 16)
            	v3 = v1 - (v3 * int('0x539', 16))
            	temp += v3
        	else:
            	exit()
	else:
    	exit()
    
	print('serial : ', temp)
```
```
	C:\Users\g4nzzi\Desktop>exploit.py
	username : g4nzzi
	serial :  6232833
	
	C:\Users\g4nzzi\Desktop>
```
- Username에 맞는 serial을 입력하면 쉘 획득
```
	lab1A@warzone:/levels/lab01$ ./lab1A
	.---------------------------.
	|---------  RPISEC  --------|
	|+ SECURE LOGIN SYS v. 3.0 +|
	|---------------------------|
	|~- Enter your Username:  ~-|
	'---------------------------'
	g4nzzi
	.---------------------------.
	| !! NEW ACCOUNT DETECTED !!|
	|---------------------------|
	|~- Input your serial:    ~-|
	'---------------------------'
	6232833
	Authenticated!
	$
```
