#include <iostream>

#include <soci.h>
#include <soci-config.h>
#include <session.h>
#include <postgresql/soci-postgresql.h>

int soci_test()
{
	const std::string connection_string = "hostaddr = '127.0.0.1' "
	"port = '5432' "
	"user = 'postgres' "
	"password = '666666' "
	"dbname = 'codecs' "
	"connect_timeout = '3' "
	"application_name = 'codecs'";
	
	soci::connection_pool db_pool(1);
	try{
	
		soci::session& sql = db_pool.at(0);
		sql.open(soci::postgresql, connection_string);
		
	}catch (soci::soci_error& ec)
	{
		std::cout<< "ERR:create database connection pool failed, error: " << ec.what();
	}
	
	soci::session ses(db_pool);
	std::string db_name("codecs");
	std::string db_user("user_info");
	try
	{
		// 检查数据库是否存在, 如果不存在, 则创建数据库.
		ses << "CREATE DATABASE " << db_name;
	}
	catch (soci::soci_error const& err)
	{
		std::cout<< err.what() << std::endl;
	}
	try
	{
		// 在这里创建数据表!
		ses << "CREATE TABLE " << db_user <<
			"(user_id text NOT NULL,"	// 用户id, 必填.
			"mail text,"				// mail, 可选.
			"phone text,"				// 电话, 可选.
			"cert bytea,"					// 证书信息, 可选.
			"public_key bytea NOT NULL,"	// 公钥信息, 必填.
			"private_key bytea,"		// 私钥, 可选.
			"allow boolean,"			// 是否允许登陆.
			"CONSTRAINT avim_user_pkey PRIMARY KEY(user_id)"
			")"
			"WITH("
			"OIDS = FALSE"
			");"
			"ALTER TABLE user_info "
			"OWNER TO postgres;";
	}
	catch (soci::soci_error const& err)
	{
		std::cout<< err.what() << std::endl;
	}
	
	std::cout<< "create db: " << db_user << "ok \n";
	
    return 0;
}
