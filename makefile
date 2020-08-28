all: test.exe makefile
	test.exe 

test.exe: test.c aes.h aes.c makefile 
	gcc test.c aes.c -o test.exe -maes
	
