// Protobuf Test Wrapper

#include <iostream>
#include <fstream>

#include <person.pb.h>

using namespace std;

static int proto_write()
{
	Person person;
	person.set_name("John Doe");
	person.set_id(1234);
	person.set_email("jdoe@example.com");

	fstream output("myfile", ios::out | ios::binary);
	person.SerializeToOstream(&output);

	return 0;
}

static int proto_read()
{
	Person person;
	fstream input("myfile", ios::in | ios::binary);
	person.ParseFromIstream(&input);
	cout << "Name: " << person.name() << endl;
	cout << "E-mail: " << person.email() << endl;
	
	return 0;
}

int proto_test()
{
	std::cout<< "Enter protobuf test case" << std::endl;

	proto_write();
	proto_read();
	
	return 0;
}