#include "jwt_utils.h"
#include "httplib.h"
#include <vector>
#include <iostream>
#include <ctime>
#include "json.hpp"

using json = nlohmann::json;

int main() {
    httplib::Server svr;

    // generate two keys: one valid, one expired
    std::vector<KeyPair> keys;
    keys.push_back(generateKey("key1", 3600));  // expires in 1 hour
    keys.push_back(generateKey("key2", -3600)); // already expired

    // JWKS endpoint: serve all keys so gradebot can verify signatures
    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res){
        json jwks; 
        jwks["keys"] = json::array();
        for(auto& k : keys){
            auto [n,e] = getPublicKeyComponents(k.rsa);
            jwks["keys"].push_back({
                {"kid", k.kid},
                {"kty", "RSA"},
                {"alg", "RS256"},
                {"n", n},
                {"e", e}
            });
        }
        res.set_content(jwks.dump(), "application/json");
    });

    // /auth endpoint: issue JWTs
    svr.Post("/auth", [&](const httplib::Request& req, httplib::Response& res){
        KeyPair* chosen = &keys[0]; // default: valid key

        // issue expired JWT if query parameter exists
        if(req.has_param("expired")){
            chosen = &keys[1]; // expired key
        }

        json payload;
        payload["sub"] = "fakeuser";
        payload["iat"] = time(nullptr);
        payload["exp"] = chosen->expires;

        std::string token = signJWT(*chosen, payload.dump());

        json out;
        out["token"] = token;
        out["kid"] = chosen->kid;
        out["expires_at"] = chosen->expires;

        res.set_content(out.dump(), "application/json");
    });

    std::cout << "Server starting on port 8080...\n";
    svr.listen("0.0.0.0", 8080);
}
