#include "jwt_utils.h"
#include "httplib.h"
#include <vector>
#include <iostream>
#include <ctime>
#include "json.hpp" // Include single-header JSON library

using json = nlohmann::json;

int main() {
    httplib::Server svr;

    // Generate two keys: one valid, one expired
    std::vector<KeyPair> keys;
    keys.push_back(generateKey("key1", 3600)); // expires in 1h
    keys.push_back(generateKey("key2", -3600)); // expired

    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res){
        json jwks; jwks["keys"] = json::array();
        for(auto& k : keys){
            auto [n,e] = getPublicKeyComponents(k.rsa);
            jwks["keys"].push_back({{"kid", k.kid},{"kty","RSA"},{"alg","RS256"},{"n",n},{"e",e}});
        }
        res.set_content(jwks.dump(), "application/json");
    });

    svr.Post("/auth", [&](const httplib::Request& req, httplib::Response& res){
        KeyPair* chosen = &keys[0]; // always pick the first key (unexpired)
        
        // if "expired" query is present, return the expired key
        if(req.has_param("expired")){
            chosen = &keys[1]; // second key is expired
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
