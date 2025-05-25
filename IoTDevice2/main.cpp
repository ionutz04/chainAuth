#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <httplib.h>
#include <json/json.h>
#include <thread>
#include <random>
#include <iostream>
#include <fstream>
#include <chrono>
#include <cppcodec/base64_default_rfc4648.hpp>

using namespace cppcodec;

std::string sha256_to_hex(const unsigned char* hash) {
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return ss.str();
}

void generate_and_send_data(const std::string& sensor_type) {
    OpenSSL_add_all_algorithms();
    std::cout << "🚀 Starting " << sensor_type << " sensor thread\n";

    // Generate RSA keypair with error checking
    RSA* keypair = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    
    if(!RSA_generate_key_ex(keypair, 2048, bn, nullptr)) {
        std::cerr << "❌ RSA key generation failed: " 
                  << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        BN_free(bn);
        return;
    }
    BN_free(bn);

    // Save public key in PKCS#1 format
    std::string key_dir = "../BlockchainAuthentication/keys/";
    system(("mkdir -p " + key_dir).c_str());
    std::string pub_key_path = key_dir + sensor_type + "_public.pem";
    
    BIO* bio = BIO_new_file(pub_key_path.c_str(), "w");
    if(!PEM_write_bio_RSAPublicKey(bio, keypair)) {
        std::cerr << "❌ Failed to write public key: "
                  << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    }
    BIO_free(bio);

    // Initialize HTTP client
    httplib::Client cli("127.0.0.1", 5000);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    // Data generation setup
    std::random_device rd;
    std::mt19937 gen(rd());
    auto range = sensor_type == "temperature" ? std::make_pair(15, 40) : std::make_pair(30, 60);
    std::uniform_int_distribution<> distr(range.first, range.second);

    while(true) {
        // Generate and prepare data
        Json::Value data;
        data["username"] = sensor_type + "_sensor";
        data["sensor_type"] = sensor_type;
        data["value"] = distr(gen);
        data["timestamp"] = static_cast<Json::Int64>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );

        // Serialize with strict formatting
        Json::StreamWriterBuilder writer;
        writer["indentation"] = "";
        writer["sortKeys"] = true;
        std::string json_str = Json::writeString(writer, data);
        
        // Hash generation with debug output
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(json_str.c_str()), 
              json_str.length(), hash);
        std::cout << "🔏 Hashing data:\n" << json_str 
                  << "\nHash: " << sha256_to_hex(hash) << "\n";

        // Signature generation
        unsigned char* sig = new unsigned char[RSA_size(keypair)];
        unsigned int sig_len;
        if(!RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, &sig_len, keypair)) {
            std::cerr << "❌ Signing failed: "
                      << ERR_error_string(ERR_get_error(), nullptr) << "\n";
            delete[] sig;
            continue;
        }

        // Prepare payload with Base64 signature
        Json::Value payload;
        payload["data"] = data;
        payload["signature"] = base64_rfc4648::encode(sig, sig_len);
        std::string payload_str = Json::writeString(writer, payload);

        // Send request with debug output
        std::cout << "📤 Sending payload:\n" << payload_str << "\n";
        bool success = false;
        
        for(int i = 0; i < 3; ++i) {
            if(auto res = cli.Post("/data", payload_str, "application/json")) {
                std::cout << "✅ Server response: " << res->status 
                          << " - " << res->body << "\n";
                success = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        delete[] sig;
        if(!success) std::cerr << "💥 Failed after 3 attempts\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    
    RSA_free(keypair);
}

int main() {
    system("mkdir -p ../BlockchainAuthentication/keys");
    std::thread(generate_and_send_data, "humidity").detach();
    while(true) std::this_thread::sleep_for(std::chrono::seconds(60));
}
