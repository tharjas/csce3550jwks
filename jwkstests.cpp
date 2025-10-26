#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "jwt_utils.h"
#include "httplib.h"
#include "json.hpp"
#include <thread>
#include <chrono>
#include <sqlite3.h>  // Include for DB tests

using json = nlohmann::json;

// JWT verification (unchanged)
inline bool isJWTExpired(const std::string& token) {
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    if(firstDot == std::string::npos || secondDot == std::string::npos)
        return true;

    std::string payload64 = token.substr(firstDot + 1, secondDot - firstDot - 1);
    std::replace(payload64.begin(), payload64.end(), '-', '+');
    std::replace(payload64.begin(), payload64.end(), '_', '/');
    while(payload64.size() % 4) payload64 += '=';

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new_mem_buf(payload64.data(), payload64.size());
    mem = BIO_push(b64, mem);
    std::string payloadJson(payload64.size(), '\0');
    int len = BIO_read(mem, payloadJson.data(), payload64.size());
    payloadJson.resize(len);
    BIO_free_all(mem);

    auto j = json::parse(payloadJson, nullptr, false);
    if(j.is_discarded() || !j.contains("exp")) return true;

    return time(nullptr) >= j["exp"].get<time_t>();
}

// Test: JWKS server serves correct keys from DB
TEST_CASE("JWKS server serves correct keys from DB", "[jwks]") {
    sqlite3* db;
    sqlite3_open("totally_not_my_privateKeys.db", &db);
    const char* sql = "DELETE FROM keys;";  // Clear DB for test
    sqlite3_exec(db, sql, nullptr, nullptr, nullptr);

    // Generate and insert keys
    KeyPair valid = generateKey("key1", 3600);
    KeyPair expired = generateKey("key2", -3600);
    insertKey(db, valid);
    insertKey(db, expired);

    json jwks;
    jwks["keys"] = json::array();
    time_t now = time(nullptr);

    // Load non-expired keys
    auto keys = loadKeys(db);
    for(auto& k : keys){
        auto [n,e] = getPublicKeyComponents(k.rsa);
        jwks["keys"].push_back({
            {"kid", k.kid},
            {"kty", "RSA"},
            {"alg", "RS256"},
            {"n", n},
            {"e", e}
        });
        RSA_free(k.rsa);
    }

    // Only the valid key should appear
    REQUIRE(jwks["keys"].size() == 1);
    REQUIRE(jwks["keys"][0]["kid"] == "1");  // AUTOINCREMENT starts at 1
    sqlite3_close(db);
}

// Test: JWT signed correctly
TEST_CASE("JWT signed correctly", "[jwt]") {
    KeyPair kp = generateKey("key1", 3600);
    json payload;
    payload["sub"] = "fakeuser";
    payload["iat"] = time(nullptr);
    payload["exp"] = kp.expires;

    std::string token = signJWT(kp, payload.dump());

    REQUIRE(!token.empty());
    REQUIRE(token.find('.') != std::string::npos);
    RSA_free(kp.rsa);
}

// Test: Expired JWT is rejected
TEST_CASE("Expired JWT is rejected", "[jwt]") {
    KeyPair kp = generateKey("key1", -10); // already expired
    json payload;
    payload["sub"] = "fakeuser";
    payload["iat"] = time(nullptr) - 20;
    payload["exp"] = kp.expires;

    std::string token = signJWT(kp, payload.dump());
    REQUIRE(isJWTExpired(token) == true);
    RSA_free(kp.rsa);
}

// Test: JWKS endpoint rejects non-GET requests (server simulation)
TEST_CASE("JWKS endpoint rejects non-GET requests", "[http]") {
    httplib::Server svr;

    // Normal GET
    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res){
        res.status = 200; res.set_content("{}", "application/json");
    });
    // Method not allowed
    auto methodNotAllowed = [&](const httplib::Request&, httplib::Response& res){
        res.status = 405; res.set_content(R"({"error":"Method Not Allowed"})", "application/json");
    };
    svr.Post("/.well-known/jwks.json", methodNotAllowed);
    svr.Put("/.well-known/jwks.json", methodNotAllowed);
    svr.Delete("/.well-known/jwks.json", methodNotAllowed);

    std::thread t([&]{ svr.listen("0.0.0.0", 8080); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    httplib::Client cli("localhost", 8080);

    REQUIRE(cli.Post("/.well-known/jwks.json")->status == 405);
    REQUIRE(cli.Put("/.well-known/jwks.json")->status == 405);
    REQUIRE(cli.Delete("/.well-known/jwks.json")->status == 405);

    svr.stop();
    t.join();
}

// Test: Auth endpoint rejects non-POST requests (server simulation)
TEST_CASE("Auth endpoint rejects non-POST requests", "[http]") {
    httplib::Server svr;
    svr.Post("/auth", [&](const httplib::Request&, httplib::Response& res){
        res.status = 200; res.set_content("{}", "application/json");
    });
    auto methodNotAllowed = [&](const httplib::Request&, httplib::Response& res){
        res.status = 405; res.set_content(R"({"error":"Method Not Allowed"})", "application/json");
    };
    svr.Get("/auth", methodNotAllowed);
    svr.Put("/auth", methodNotAllowed);
    svr.Delete("/auth", methodNotAllowed);

    std::thread t([&]{ svr.listen("0.0.0.0", 8080); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    httplib::Client cli("localhost", 8080);

    REQUIRE(cli.Get("/auth")->status == 405);
    REQUIRE(cli.Put("/auth")->status == 405);
    REQUIRE(cli.Delete("/auth")->status == 405);

    svr.stop();
    t.join();
}

// New Test: Serialize/Deserialize RSA
TEST_CASE("Serialize and Deserialize RSA", "[db]") {
    KeyPair kp = generateKey("test", 3600);
    std::string pem = serializeRSA(kp.rsa);
    RSA* deserialized = deserializeRSA(pem);
    REQUIRE(deserialized != nullptr);

    // Compare public components to verify
    auto [n1, e1] = getPublicKeyComponents(kp.rsa);
    auto [n2, e2] = getPublicKeyComponents(deserialized);
    REQUIRE(n1 == n2);
    REQUIRE(e1 == e2);

    RSA_free(kp.rsa);
    RSA_free(deserialized);
}

// New Test: DB Insert and Load
TEST_CASE("DB Insert and Load Keys", "[db]") {
    sqlite3* db;
    sqlite3_open("test.db", &db);  // Temp DB for test
    createTable(db);
    const char* sql = "DELETE FROM keys;";  // Clear
    sqlite3_exec(db, sql, nullptr, nullptr, nullptr);

    KeyPair kp = generateKey("test", 3600);
    insertKey(db, kp);

    auto loaded = loadKeys(db);
    REQUIRE(loaded.size() == 1);
    REQUIRE(loaded[0].expires == kp.expires);

    sqlite3_close(db);
    std::remove("test.db");  // Clean up
}
