## 1. 문제 확인
- ID : lab1C
- Target : /level/lab01/lab1C
- flag : /home/lab1B/.pass
```
	lab1C@warzone:/levels/lab01$ ls
	total 32
	-r-sr-x--- 1 lab1end lab1A 9672 Jun 21  2015 lab1A
	-r-sr-x--- 1 lab1A   lab1B 9672 Jun 21  2015 lab1B
	-r-sr-x--- 1 lab1B   lab1C 7414 Jun 21  2015 lab1C
	lab1C@warzone:/levels/lab01$ ./lab1C
	-----------------------------
	--- RPISEC - CrackMe v1.0 ---
	-----------------------------

	Password: a12345678
	
    Invalid Password!!!
	lab1C@warzone:/levels/lab01$
``` 

## 2. 코드 분석
- main() 코드를 확인해보면 scanf()로 입력받은 값과 비교 구문 존재
```
   0x080486da <+45>:    mov    DWORD PTR [esp],0x804880c
   0x080486e1 <+52>:    call   0x8048550 <printf@plt>
   0x080486e6 <+57>:    lea    eax,[esp+0x1c]
   0x080486ea <+61>:    mov    DWORD PTR [esp+0x4],eax
   0x080486ee <+65>:    mov    DWORD PTR [esp],0x8048818
   0x080486f5 <+72>:    call   0x80485a0 <__isoc99_scanf@plt>
   0x080486fa <+77>:    mov    eax,DWORD PTR [esp+0x1c]
   0x080486fe <+81>:    cmp    eax,0x149a
   0x08048703 <+86>:    jne    0x8048724 <main+119>
``` 
- 값이 일치할 경우, systme()로 "/bin/sh" 실행
```
   0x08048705 <+88>:    mov    DWORD PTR [esp],0x804881b
   0x0804870c <+95>:    call   0x8048560 <puts@plt>
   0x08048711 <+100>:   mov    DWORD PTR [esp],0x804882b
   0x08048718 <+107>:   call   0x8048570 <system@plt>
```
```
	gdb-peda$ x/s 0x804881b
	0x804881b:      "\nAuthenticated!"
	gdb-peda$ x/s 0x804882b
	0x804882b:      "/bin/sh"
```

## 3. Exploit
- "5274"(0x149a)를 입력하면 lab1B 권한의 쉘 획득
```
	lab1C@warzone:/levels/lab01$ ./lab1C
	-----------------------------
	--- RPISEC - CrackMe v1.0 ---
	-----------------------------

	Password: 5274

	Authenticated!
	$
```
