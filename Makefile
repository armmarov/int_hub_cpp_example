unit_test:
	g++ blockchain.cpp -I/usr/include/openssl -lcurl -lcrypto -DUNIT_TEST -o blockchain