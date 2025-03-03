build:
	cc src/*.c -O3 -o vpn -lcrypto

clean:
	rm vpn
