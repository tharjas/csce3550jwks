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

    // JWKS endpoint: serve only non-expired keys
    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res){
        json jwks; 
        jwks["keys"] = json::array();
        time_t now = time(nullptr); // Get current time
        for(auto& k : keys){
            if (k.expires > now) { // Only include non-expired keys
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
        res.status = 200; // Explicitly set status code
        res.set_content(jwks.dump(), "application/json");
    });

    // /auth endpoint: issue JWTs
    svr.Post("/auth", [&](const httplib::Request& req, httplib::Response& res){
        KeyPair* chosen = &keys[0]; // default: valid key

        // issue expired JWT if query parameter exists
        if(req.has_param("expired") && req.get_param_value("expired") == "true") {
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

        res.status = 200; // Explicitly set status code
        res.set_content(out.dump(), "application/json");
    });

    // handle non-POST requests to /auth !
    svr.Get("/auth", [&](const httplib::Request&, httplib::Response& res){
        res.status = 405; // method Not Allowed
        res.set_content(R"({"error":"Method Not Allowed"})", "application/json");
    });

    std::cout << "Server starting on port 8080...\n";
    svr.listen("0.0.0.0", 8080);
}
