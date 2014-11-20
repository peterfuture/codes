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
	//std::cout << "private_key:" << keyfilecontent << " cert_content:" << certfilecontent;

	//Step1 - Client Generate random g p pub_key
	unsigned char client_content[512];
	DH *dh_client = DH_new();
	DH_generate_parameters_ex(dh_client,64,DH_GENERATOR_5,NULL);
	DH_generate_key(dh_client);

	// 把 g,p, pubkey 传过去
	std::string client_random_g, client_random_p, client_pub_key;
	client_random_g.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->g, client_content));
	client_random_p.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->p, client_content));
	client_pub_key.assign(reinterpret_cast<const char*>(client_content), BN_bn2bin(dh_client->pub_key, client_content));
	std::cout << "client public key:" << client_pub_key << std::endl;
	
	// Step 2 - Server Generate random number
	DH* dh_server = DH_new();
	unsigned char bin_key[512] = { 0 };
	std::string server_pubkey;

	// 生成随机数然后返回 m_dh->p ，让客户端去算共享密钥.
	DH_generate_parameters_ex(dh_server, 64, DH_GENERATOR_5, NULL);
	dh_server->g = BN_bin2bn((const unsigned char *)client_random_g.data(), static_cast<long>(client_random_g.length()), dh_server->g);
	dh_server->p = BN_bin2bn((const unsigned char *)client_random_p.data(), static_cast<long>(client_random_p.length()), dh_server->p);

	DH_generate_key(dh_server);
	server_pubkey.assign(reinterpret_cast<const char*>(bin_key), BN_bn2bin(dh_server->pub_key, bin_key));
	
	// store client public key
	std::vector<uint8_t> server_shared_key;
	server_shared_key.resize(DH_size(dh_server));
	BIGNUM* server_client_pubkey = BN_bin2bn((const unsigned char *)client_pub_key.data(), static_cast<long>(client_pub_key.length()), NULL);
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

	std::cout << "server_key: " << server_key << std::endl;
	
	//step3 - Client calc server key
	auto client_server_pubkey = BN_bin2bn((const unsigned char *) server_pubkey.data(), server_pubkey.length(), NULL);
	std::vector<unsigned char> client_shared_key;
	client_shared_key.resize(DH_size(dh_client));
	// 密钥就算出来啦！
	DH_compute_key(&client_shared_key[0], client_server_pubkey, dh_client);
	BN_free(client_server_pubkey);

    std::printf("key = 0x");
    for (int i=0; i<DH_size(dh_client); ++i)
	{
        std::printf("%x%x", (client_shared_key[i] >> 4) & 0xf, client_shared_key[i] & 0xf);
    }
    std::printf("\n");
	DH_free(dh_client);
	
	
	std::cout<< "openssl test end" << std::endl;
	return 0;
}