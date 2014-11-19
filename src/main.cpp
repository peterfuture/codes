#include <iostream>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "codec_test.hpp"

using namespace std;

//global variables def
static int proto_enable = 0;
static int soci_enable = 0;
static int openssl_enable = 0;

po::options_description desc("Allowed options");
po::variables_map vm;
int program_options_usage(int argc, char **argv)
{
	desc.add_options()
	("help,h", "produce help message")
	("version,v", "print version string")
	("proto_test", po::value<int>(&proto_enable)->default_value(0), "exec proto test")
	("soci_test", po::value<int>(&soci_enable)->default_value(0), "exec soci-postgresql test")
	("openssl_test", po::value<int>(&openssl_enable)->default_value(0), "exec openssl test")
	;
	
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);
	
	if(argc == 1 || vm.count("help"))
	{
		std::cout<< desc<< std::endl;
		return 0;
	}
	
	if(vm.count("version"))
	{
		std::cout<< "Version:0.1" << std::endl;
		return 0;
	}
	
}

int main(int argc, char **argv)
{
	program_options_usage(argc, argv);
	
	std::cout<< "enter proto test:"<< proto_enable << std::endl;
	if(proto_enable == 1){
#ifdef ENABLE_PROTO_TEST
		proto_test();
#endif
	}
	
	if(soci_enable == 1){
		std::cout<< "enter soci-postgresql test" << std::endl;
#ifdef ENABLE_SOCI_TEST
		soci_test();
#endif
	}
	
	if(openssl_enable == 1){
		std::cout<< "enter openssl test" << std::endl;
#ifdef ENABLE_OPENSSL_TEST
		openssl_test();
#endif
	}
	
    return 0;
}
