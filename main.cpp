#include <iostream>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

//global variables def
static int proto_enable = 0;

po::options_description desc("Allowed options");
po::variables_map vm;
int program_options_usage(int argc, char **argv)
{
	desc.add_options()
	("help,h", "produce help message")
	("version,v", "print version string")
	("proto_enable", po::value<int>(&proto_enable)->default_value(0), "enable proto test")
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
    return 0;
}
