## 1. 문제 확인
- ID : lab1B
- Target : /level/lab01/lab1B
- flag : /home/lab1A/.pass
```
	lab1B@warzone:/levels/lab01$ ./lab1B
	.---------------------------.
	|-- RPISEC - CrackMe v2.0 --|
	'---------------------------'
	
	Password: a12345678
	
	Invalid Password!
	lab1B@warzone:/levels/lab01$
```

<br/><br/>
## 2. 코드 분석
### 2.1 main()
- scanf()로 입력받은 값(input)과 "0x1337d00d"으로 test() 호출
```
   0x08048c3a <+86>:    lea    eax,[esp+0x1c]
   0x08048c3e <+90>:    mov    DWORD PTR [esp+0x4],eax
   0x08048c42 <+94>:    mov    DWORD PTR [esp],0x8048dee
   0x08048c49 <+101>:   call   0x8048840 <__isoc99_scanf@plt>
   0x08048c4e <+106>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048c52 <+110>:   mov    DWORD PTR [esp+0x4],0x1337d00d
   0x08048c5a <+118>:   mov    DWORD PTR [esp],eax
   0x08048c5d <+121>:   call   0x8048a74 <test>
```
```c
	...
	scanf("%d", input)
    test(input, 0x1337d00d)
    ...
```
### 2.2 test()
- (0x1337d00d - input)의 결과가 0x15보다 클 경우, rand()값으로 decrypt() 호출
- 그렇지 않을 경우, case문을 통해 (0x1337d00d - input)으로 decrypt() 호출
```
   0x08048a7a <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x08048a7d <+9>:     mov    edx,DWORD PTR [ebp+0xc]
   0x08048a80 <+12>:    sub    edx,eax
   0x08048a82 <+14>:    mov    eax,edx
   0x08048a84 <+16>:    mov    DWORD PTR [ebp-0xc],eax
   0x08048a87 <+19>:    cmp    DWORD PTR [ebp-0xc],0x15
   0x08048a8b <+23>:    ja     0x8048bd5 <test+353>
   0x08048a91 <+29>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08048a94 <+32>:    shl    eax,0x2
   0x08048a97 <+35>:    add    eax,0x8048d30
   0x08048a9c <+40>:    mov    eax,DWORD PTR [eax]
   0x08048a9e <+42>:    jmp    eax
   0x08048aa0 <+44>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08048aa3 <+47>:    mov    DWORD PTR [esp],eax
   0x08048aa6 <+50>:    call   0x80489b7 <decrypt>
   ...
   0x08048bd5 <+353>:   call   0x8048830 <rand@plt>
   0x08048bda <+358>:   mov    DWORD PTR [esp],eax
   0x08048bdd <+361>:   call   0x80489b7 <decrypt>
   ...
```
```c
    ...
	key = 0x1337d00d - input
    if(key > 0x15)
    	decrypt(rand())
    else
    	switch(&((key << 2) + 0x8048d30))
        ...
        case:
        	decrypt(key)
    ...
```
### 2.3 decrypt()
- "Q}|u\`sfg~sf{}|a3" 문자열과 key(0x1337d00d - input)값으로 XOR 연산
- XOR 연산 결과와 "Congratulations!" 문자열이 일치하면 쉘 띄움
```
   0x080489c8 <+17>:    mov    DWORD PTR [ebp-0x1d],0x757c7d51
   0x080489cf <+24>:    mov    DWORD PTR [ebp-0x19],0x67667360
   0x080489d6 <+31>:    mov    DWORD PTR [ebp-0x15],0x7b66737e
   0x080489dd <+38>:    mov    DWORD PTR [ebp-0x11],0x33617c7d
   0x080489e4 <+45>:    mov    BYTE PTR [ebp-0xd],0x0
   0x080489e8 <+49>:    push   eax
   ...
   0x08048a08 <+81>:    lea    edx,[ebp-0x1d]
   0x08048a0b <+84>:    mov    eax,DWORD PTR [ebp-0x28]
   0x08048a0e <+87>:    add    eax,edx
   0x08048a10 <+89>:    movzx  eax,BYTE PTR [eax]
   0x08048a13 <+92>:    mov    edx,eax
   0x08048a15 <+94>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048a18 <+97>:    xor    eax,edx
   0x08048a1a <+99>:    lea    ecx,[ebp-0x1d]
   0x08048a1d <+102>:   mov    edx,DWORD PTR [ebp-0x28]
   0x08048a20 <+105>:   add    edx,ecx
   0x08048a22 <+107>:   mov    BYTE PTR [edx],al
   0x08048a24 <+109>:   add    DWORD PTR [ebp-0x28],0x1
   0x08048a28 <+113>:   mov    eax,DWORD PTR [ebp-0x28]
   0x08048a2b <+116>:   cmp    eax,DWORD PTR [ebp-0x24]
   0x08048a2e <+119>:   jb     0x8048a08 <decrypt+81>
   0x08048a30 <+121>:   mov    DWORD PTR [esp+0x4],0x8048d03
   0x08048a38 <+129>:   lea    eax,[ebp-0x1d]
   0x08048a3b <+132>:   mov    DWORD PTR [esp],eax
   0x08048a3e <+135>:   call   0x8048770 <strcmp@plt>
   0x08048a43 <+140>:   test   eax,eax
   0x08048a45 <+142>:   jne    0x8048a55 <decrypt+158>
   0x08048a47 <+144>:   mov    DWORD PTR [esp],0x8048d14
   0x08048a4e <+151>:   call   0x80487e0 <system@plt>
```
```c
    str = "Q}|u`sfg~sf{}|a3"
    ...
    for(i=0; i < strlen(str) ; i++)
    	str[i] = str[i] ^ key
    if(strcmp("Congratulations!", str) == 0)
    	system("/bin/sh")
    ...    
```
    ※ decrypt()에는 StackGuard(Canary) 코드가 존재(문제 풀이에 영향 없음)
```
   0x080489bd <+6>:     mov    eax,gs:0x14
   0x080489c3 <+12>:    mov    DWORD PTR [ebp-0xc],eax
   0x080489c6 <+15>:    xor    eax,eax
   ...
   0x08048a61 <+170>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08048a64 <+173>:   xor    eax,DWORD PTR gs:0x14
   0x08048a6b <+180>:   je     0x8048a72 <decrypt+187>
   0x08048a6d <+182>:   call   0x80487c0 <__stack_chk_fail@plt>
   0x08048a72 <+187>:   leave
```

<br/><br/>
## 3. exploit
- XOR 연산의 특성상 key값은 "Q}|u\`sfg~sf{}|a3"과 "Congratulations!"의 XOR 연산으로  역계산 가능
- 두 문자열의 문자를 1개씩 XOR 연산해보면 동일한 key값 확인
```python
	str1 = "517d7c75607366677e73667b7d7c613300"   # "Q}|u`sfg~sf{}|a3"
	str2 = "Congratulations!"
	
	s1 = [str1[x:x+2] for x in range(0, len(str1), 2)]
	s2 = [str2[x] for x in range(0, len(str2))]
	
	result = []
	for i, j in zip(s1, s2):
    	result.append(int(i, 16) ^ ord(j))
	
	print(result)
```
```
	[18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18]
```
- key값 18(0x12)은 (0x1337d00d - input) 값이므로 input은 (0x1337d00d - 0x12) 값
- Password로 322424827(0x1337cffb)를 입력하면 쉘 획득
```
	lab1B@warzone:/levels/lab01$ ./lab1B
	.---------------------------.
	|-- RPISEC - CrackMe v2.0 --|
	'---------------------------'
	
	Password: 322424827
	$
```
