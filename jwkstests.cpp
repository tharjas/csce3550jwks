#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "../jwt_utils.h"
#include "../httplib.h"
#include "json.hpp"

using json = nlohmann::json;

TEST_CASE("JWKS server serves correct keys", "[jwks]") {
    std::vector<KeyPair> keys;
    keys.push_back(generateKey("key1", 3600));  // valid
    keys.push_back(generateKey("key2", -3600)); // expired

    json jwks;
    jwks["keys"] = json::array();
    time_t now = time(nullptr);
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

    REQUIRE(jwks["keys"].size() == 1);
    REQUIRE(jwks["keys"][0]["kid"] == "key1");
}

TEST_CASE("JWT signed correctly", "[jwt]") {
    KeyPair kp = generateKey("key1", 3600);
    json payload;
    payload["sub"] = "fakeuser";
    payload["iat"] = time(nullptr);
    payload["exp"] = kp.expires;

    std::string token = signJWT(kp, payload.dump());
    REQUIRE(!token.empty());
    REQUIRE(token.find('.') != std::string::npos); // JWT format contains periods
}

/*
next add tests like:

TEST_CASE("Expired JWT is rejected", "[jwt]")

TEST_CASE("JWKS endpoint rejects non-GET requests", "[http]")

TEST_CASE("Auth endpoint rejects non-POST requests", "[http]")
*/
