#include <iostream>
#include <fstream>

#include <boost/make_shared.hpp>
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

using namespace std;

//== DH
DH *dh_client;
DH *dh_server;
std::string random_g, random_p;
std::string server_pubkey, client_pubkey;
std::vector<uint8_t> client_shared_key;
std::vector<uint8_t> server_shared_key;

//== CA
boost::shared_ptr<RSA> rsa_key;
boost::shared_ptr<X509> x509_cert;

//step1 Client Generate HD P-G-PUBKEY
int dh_generate_clientkey()
{
	//Generate random g p pub_key
	unsigned char client_content[512] = {0};
	dh_client = DH_new();
	DH_generate_parameters_ex(dh_client,64,DH_GENERATOR_5,NULL);
	DH_generate_key(dh_client);

	random_g.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->g, client_content));
	random_p.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->p, client_content));
	client_pubkey.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->pub_key, client_content));

	return 0;
}

//step2 Server Generate shared Key with Client's P-G-KEY
//And send pub key to client
int dh_generate_serverkey()
{	
	unsigned char server_content[512] = { 0 };
	dh_server = DH_new();
	DH_generate_parameters_ex(dh_server, 64, DH_GENERATOR_5, NULL);

	dh_server->g = BN_bin2bn((const unsigned char *)random_g.data(), static_cast<long>(random_g.length()), dh_server->g);
	dh_server->p = BN_bin2bn((const unsigned char *)random_p.data(), static_cast<long>(random_p.length()), dh_server->p);
	DH_generate_key(dh_server);
	server_pubkey.assign(reinterpret_cast<const char*>(server_content), BN_bn2bin(dh_server->pub_key, server_content));
	
	// store client public key
	server_shared_key.resize(DH_size(dh_server));
	BIGNUM* server_client_pubkey = BN_bin2bn((const unsigned char *)client_pubkey.data(), static_cast<long>(client_pubkey.length()), NULL);
	DH_compute_key(&server_shared_key[0], server_client_pubkey, dh_server);
	BN_free(server_client_pubkey);
	DH_free(dh_server);
	
	std::string server_key;
	char buf[16] = { 0 };
	for (int i = 0; i < server_shared_key.size(); ++i)
	{
		sprintf(buf, "%x%x", (server_shared_key[i] >> 4) & 0xf, server_shared_key[i] & 0xf);
		server_key += buf;
	}
	
	std::cout << "Generate server shared key:" << server_key << std::endl;
	return 0;
}

//step3 client generate sharedkey with server pubkey
int dh_generate_client_shared_key()
{
	client_shared_key.resize(DH_size(dh_client));
	BIGNUM* client_server_pubkey = BN_bin2bn((const unsigned char *)server_pubkey.data(), static_cast<long>(server_pubkey.length()), NULL);
	DH_compute_key(&client_shared_key[0], client_server_pubkey, dh_client);
	BN_free(client_server_pubkey);
	DH_free(dh_client);

	std::string client_key;
	char buf[16] = { 0 };
    for (int i=0; i< client_shared_key.size(); ++i)
	{
		sprintf(buf, "%x%x", (client_shared_key[i] >> 4) & 0xf, client_shared_key[i] & 0xf);
		client_key += buf;
    }
    
	std::cout << "Generate client shared key:" << client_key << std::endl;
	return 0;
}

int dh_test()
{
	dh_generate_clientkey();
	dh_generate_serverkey();
	dh_generate_client_shared_key();
	return 0;
}

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

int dump_ca_info()
{
	unsigned char * CN = NULL;
	auto cert_name = X509_get_subject_name(x509_cert.get());
	auto cert_entry = X509_NAME_get_entry(cert_name, X509_NAME_get_index_by_NID(cert_name, NID_commonName, 0));
	ASN1_STRING *entryData = X509_NAME_ENTRY_get_data(cert_entry);
	auto strlengh = ASN1_STRING_to_UTF8(&CN, entryData);
	std::printf("%s\n",CN);
	OPENSSL_free(CN);
}

int ca_load()
{
	fs::path key("./test.key");
	fs::path cert("./test.crt");
	std::string keyfilecontent, certfilecontent;
	
	std::ifstream keyfile(key.string().c_str(), std::ios_base::binary | std::ios_base::in);
	std::ifstream certfile(cert.string().c_str(), std::ios_base::binary | std::ios_base::in);
	
	keyfilecontent.resize(fs::file_size(key));
	certfilecontent.resize(fs::file_size(cert));
	keyfile.read(&keyfilecontent[0], fs::file_size(key));
	certfile.read(&certfilecontent[0], fs::file_size(cert));
	
	boost::shared_ptr<BIO> shared_keyfile(BIO_new_mem_buf(&keyfilecontent[0], keyfilecontent.length()), BIO_free);
	boost::shared_ptr<BIO> shared_certfile(BIO_new_mem_buf(&certfilecontent[0], certfilecontent.length()), BIO_free);

	boost::shared_ptr<RSA> rsa_key_tmp(
		PEM_read_bio_RSAPrivateKey(shared_keyfile.get(), 0, (pem_password_cb*)pass_cb,(void*) key.c_str()),
		RSA_free
	);
	//shared_keyfile.reset(BIO_new(BIO_s_mem()), BIO_free);

	rsa_key = rsa_key_tmp;
	x509_cert.reset(PEM_read_bio_X509(shared_certfile.get(), 0, 0, 0), X509_free);

	//std::cout << "private_key:" << keyfilecontent << " cert_content:" << certfilecontent;
	dump_ca_info();
	std::cout << "load key cert ok." << std::endl;
}

std::string RSA_private_encrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize  - RSA_PKCS1_PADDING_SIZE;
	int inputlen = from.length();
	for(int i = 0 ; i < from.length(); i+= chunksize)
	{
		int flen = std::min<int>(chunksize, inputlen - i);

		std::fill(block.begin(),block.end(), 0);

		auto resultsize = RSA_private_encrypt(
			flen,
			(uint8_t*) &from[i],
			&block[0],
			rsa,
			RSA_PKCS1_PADDING
		);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

std::string RSA_public_encrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize  - RSA_PKCS1_PADDING_SIZE;
	int inputlen = from.length();

	for(int i = 0 ; i < inputlen; i+= chunksize)
	{
		auto resultsize = RSA_public_encrypt(std::min(chunksize, inputlen - i), (uint8_t*) &from[i],  &block[0], (RSA*) rsa, RSA_PKCS1_PADDING);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

std::string RSA_private_decrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);

	for(int i = 0 ; i < from.length(); i+= keysize)
	{
		auto resultsize = RSA_private_decrypt(std::min<int>(keysize, from.length() - i), (uint8_t*) &from[i],  &block[0], rsa, RSA_PKCS1_PADDING);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

std::string RSA_public_decrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	int inputlen = from.length();
	for(int i = 0 ; i < from.length(); i+= keysize)
	{
		int flen = std::min(keysize, inputlen - i);

		auto resultsize = RSA_public_decrypt(
			flen,
			(uint8_t*) &from[i],
			&block[0],
			rsa,
			RSA_PKCS1_PADDING
		);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

int ca_process()
{	
	auto key_tmp = X509_get_pubkey(x509_cert.get());
	auto user_rsa_pubkey = EVP_PKEY_get1_RSA(key_tmp);
	EVP_PKEY_free(key_tmp);
	
	
	std::string rawdata("codecs test for openssl");
	std::cout << "rawdata:" << rawdata<< std::endl;
	std::string encrypt_data = RSA_private_encrypt(rsa_key.get(), rawdata);
	//std::cout << "after private_key encrypt_data:" << encrypt_data << std::endl;
	std::string decrypt_data = RSA_public_decrypt(user_rsa_pubkey, encrypt_data);
	std::cout << "after pubkey decrypt_data:" << decrypt_data << std::endl;
	
	//encrypt by pubkey - decrypt by private_key
	encrypt_data.clear();
	decrypt_data.clear();
	encrypt_data += (RSA_public_encrypt(user_rsa_pubkey, rawdata));
	decrypt_data += (RSA_private_decrypt(rsa_key.get(), encrypt_data));
	std::cout << "after private_key decrypt_data:" << decrypt_data << std::endl;
	return 0;
}

int ca_test()
{
	ca_load();
	ca_process();
	return 0;
}

int openssl_test()
{	
	OpenSSL_add_all_algorithms();
	ca_test();
	dh_test();
	
	std::cout<< "openssl test end" << std::endl;
	return 0;
}