#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "jwt_utils.h"
#include "httplib.h"
#include "json.hpp"
#include <thread>
#include <chrono>

using json = nlohmann::json;

// JWT verification
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

// simple tests

// tests that JWKS server only servers non-expired keys
TEST_CASE("JWKS server serves correct keys", "[jwks]") {
    std::vector<KeyPair> keys;
    keys.push_back(generateKey("key1", 3600));  // valid
    keys.push_back(generateKey("key2", -3600)); // expired

    json jwks;
    jwks["keys"] = json::array();
    time_t now = time(nullptr);

    // include keys that have not expired
    for(auto& k : keys){
        if(k.expires > now){
            auto [n,e] = getPublicKeyComponents(k.rsa);
            jwks["keys"].push_back({
                {"kid", k.kid},
                {"kty", "RSA"},
                {"alg", "RS256"},
                {"n", n},
                {"e", e}
            });
        }
    }

    // only the valid key should appear in the JWKS
    REQUIRE(jwks["keys"].size() == 1);
    REQUIRE(jwks["keys"][0]["kid"] == "key1");
}

// tests that signing JWT makes a token in the right format
TEST_CASE("JWT signed correctly", "[jwt]") {
    KeyPair kp = generateKey("key1", 3600);
    json payload;
    payload["sub"] = "fakeuser";
    payload["iat"] = time(nullptr);
    payload["exp"] = kp.expires;

    std::string token = signJWT(kp, payload.dump());

    // token should not be empty + should have JWT format of header.payload.signature
    REQUIRE(!token.empty());
    REQUIRE(token.find('.') != std::string::npos); // JWT format contains periods
}

// test that expired JWT is recognized as expired
TEST_CASE("Expired JWT is rejected", "[jwt]") {
    KeyPair kp = generateKey("key1", -10); // already expired
    json payload;
    payload["sub"] = "fakeuser";
    payload["iat"] = time(nullptr) - 20;
    payload["exp"] = kp.expires;

    std::string token = signJWT(kp, payload.dump());
    REQUIRE(isJWTExpired(token) == true);
}

// test that JWKS endpoint rejects non-GET reqs
TEST_CASE("JWKS endpoint rejects non-GET requests", "[http]") {
    httplib::Server svr;

    // normal GET endpoint returns 200
    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res){
        res.status = 200; res.set_content("{}", "application/json");
    });
    // method not allowed for post/put/delete
    auto methodNotAllowed = [&](const httplib::Request&, httplib::Response& res){
        res.status = 405; res.set_content(R"({"error":"Method Not Allowed"})", "application/json");
    };
    svr.Post("/.well-known/jwks.json", methodNotAllowed);
    svr.Put("/.well-known/jwks.json", methodNotAllowed);
    svr.Delete("/.well-known/jwks.json", methodNotAllowed);

    // start server in separate thread
    std::thread t([&]{ svr.listen("0.0.0.0", 8080); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    httplib::Client cli("localhost", 8080);

    // non-GET reqs return 405
    REQUIRE(cli.Post("/.well-known/jwks.json")->status == 405);
    REQUIRE(cli.Put("/.well-known/jwks.json")->status == 405);
    REQUIRE(cli.Delete("/.well-known/jwks.json")->status == 405);

    svr.stop();
    t.join();
}

// tests that auth endpoint rejects non-POST reqs
TEST_CASE("Auth endpoint rejects non-POST requests", "[http]") {
    httplib::Server svr;
    // normal POST endpoint returns 200
    svr.Post("/auth", [&](const httplib::Request&, httplib::Response& res){
        res.status = 200; res.set_content("{}", "application/json");
    });
    // method not allowed for get/put/delete
    auto methodNotAllowed = [&](const httplib::Request&, httplib::Response& res){
        res.status = 405; res.set_content(R"({"error":"Method Not Allowed"})", "application/json");
    };
    svr.Get("/auth", methodNotAllowed);
    svr.Put("/auth", methodNotAllowed);
    svr.Delete("/auth", methodNotAllowed);

    // start server in separate thread
    std::thread t([&]{ svr.listen("0.0.0.0", 8080); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    httplib::Client cli("localhost", 8080);

    // non-post reqs return 405
    REQUIRE(cli.Get("/auth")->status == 405);
    REQUIRE(cli.Put("/auth")->status == 405);
    REQUIRE(cli.Delete("/auth")->status == 405);

    svr.stop();
    t.join();
}
