#include <iostream>
#include <fstream>

#include <boost/make_shared.hpp>
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

using namespace std;

static int pass_cb(char *buf, int size, int rwflag, char *u)
{
	int len;
	std::string tmp;
	/* We'd probably do something else if 'rwflag' is 1 */
	std::cout << "Enter pass phrase for " << u << " :";
	std::flush(std::cout);

	std::cin >> tmp;

	/* get pass phrase, length 'len' into 'tmp' */
	len = tmp.length();

	if (len <= 0) return 0;
	/* if too long, truncate */
	if (len > size) len = size;
	memcpy(buf, tmp.data(), len);
	return len;
}

int openssl_test()
{	
	OpenSSL_add_all_algorithms();
	std::string keyfilecontent, keyfilecontent_decrypted, certfilecontent;
	
	fs::path key("./test.key");
	fs::path cert("./test.crt");

	std::ifstream keyfile(key.string().c_str(), std::ios_base::binary | std::ios_base::in);
	std::ifstream certfile(cert.string().c_str(), std::ios_base::binary | std::ios_base::in);
	keyfilecontent.resize(fs::file_size(key));
	certfilecontent.resize(fs::file_size(cert));
	keyfile.read(&keyfilecontent[0], fs::file_size(key));
	certfile.read(&certfilecontent[0], fs::file_size(cert));
	
	// 这里通过读取然后写回的方式预先将私钥的密码去除
	boost::shared_ptr<BIO> shared_keyfile(BIO_new_mem_buf(&keyfilecontent[0], keyfilecontent.length()), BIO_free);
	boost::shared_ptr<RSA> rsa_key(
		PEM_read_bio_RSAPrivateKey(shared_keyfile.get(), 0, (pem_password_cb*)pass_cb,(void*) key.c_str()),
		RSA_free
	);

	shared_keyfile.reset(BIO_new(BIO_s_mem()), BIO_free);
	char *outbuf = 0;
	PEM_write_bio_RSAPrivateKey(shared_keyfile.get(),rsa_key.get(), 0, 0, 0, 0, 0);
	rsa_key.reset();
	auto l = BIO_get_mem_data(shared_keyfile.get(), &outbuf);
	keyfilecontent.assign(outbuf, l);
	shared_keyfile.reset();
	
	std::cout<< "openssl test end" << std::endl;
	return 0;
}