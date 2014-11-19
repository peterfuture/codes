// Protobuf Test Wrapper

#include <iostream>
#include <fstream>

using namespace std;

#include <person.pb.h>
using namespace proto;

static int proto_write()
{
	person p;
	p.set_name("John Doe");
	p.set_id(1234);
	p.set_email("jdoe@example.com");
	
	person_phone_number *phone;
	phone = p.add_phone();
	phone->set_number("13911111111");
	phone->set_type(proto::person_phone_type_MOBILE);

	phone = p.add_phone();
	phone->set_number("0211111111");
	phone->set_type(proto::person_phone_type_HOME);
	

	fstream output("myfile", ios::out | ios::binary);
	p.SerializeToOstream(&output);

	return 0;
}

static int proto_read()
{
	person p;
	fstream input("myfile", ios::in | ios::binary);
	p.ParseFromIstream(&input);
	cout << "Name: " << p.name() << endl;
	cout << "E-mail: " << p.email() << endl;
	
	int size = p.phone_size();
	for(int i = 0; i < size; i++)
	{
		person_phone_number phone = p.phone(i);
		cout<< "type:" << phone.type()<< " number:" << phone.number() << std::endl;
	}

	return 0;
}

int proto_test()
{
	std::cout<< "Enter protobuf test case" << std::endl;
	proto_write();
	proto_read();
	return 0;
}