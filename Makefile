all: compress.so

compress.so: compress.c
	gcc compress.c -O3 -shared -o compress.so

clean:
	rm -rf compress.so *.pyc __pycache__

.PHONY: all
