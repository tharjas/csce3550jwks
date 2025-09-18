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
    std::cout << "Keys generated: key1 (expires: " << keys[0].expires 
              << "), key2 (expires: " << keys[1].expires << ")" << std::endl;

    // JWKS endpoint: serve only non-expired keys
    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res){
        std::cout << "Received GET /.well-known/jwks.json request" << std::endl;
        json jwks; 
        jwks["keys"] = json::array();
        time_t now = time(nullptr);
        for(auto& k : keys){
            if (k.expires > now) {
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
        std::cout << "JWKS response: " << jwks.dump() << std::endl;
        res.status = 200;
        res.set_header("Content-Type", "application/json");
        res.set_content(jwks.dump(), "application/json");
    });

    // handle non-GET requests to JWKS
    auto jwksMethodNotAllowed = [&](const httplib::Request& req, httplib::Response& res){
        std::cout << "Received invalid method " << req.method << " for /.well-known/jwks.json" << std::endl;
        res.status = 405;
        res.set_header("Content-Type", "text/plain");
        res.set_header("Allow", "GET");
    };
    svr.Post("/.well-known/jwks.json", jwksMethodNotAllowed);
    svr.Put("/.well-known/jwks.json", jwksMethodNotAllowed);
    svr.Delete("/.well-known/jwks.json", jwksMethodNotAllowed);
    svr.Patch("/.well-known/jwks.json", jwksMethodNotAllowed);
    svr.Options("/.well-known/jwks.json", jwksMethodNotAllowed);

    // auth endpoint: issue JWTs
    svr.Post("/auth", [&](const httplib::Request& req, httplib::Response& res){
        std::cout << "Received POST /auth request" << std::endl;
        KeyPair* chosen = &keys[0];
        if(req.has_param("expired") && req.get_param_value("expired") == "true") {
            std::cout << "Using expired key (key2)" << std::endl;
            chosen = &keys[1];
        } else {
            std::cout << "Using valid key (key1)" << std::endl;
        }

        json payload;
        payload["sub"] = "fakeuser";
        payload["iat"] = time(nullptr);
        payload["exp"] = chosen->expires;

        std::string token = signJWT(*chosen, payload.dump());
        std::cout << "Generated JWT: " << token << std::endl;

        json out;
        out["token"] = token;
        out["kid"] = chosen->kid;
        out["expires_at"] = chosen->expires;

        res.status = 200;
        res.set_header("Content-Type", "application/json");
        res.set_content(out.dump(), "application/json");
    });

    // handle non-POST requests to /auth
    auto authMethodNotAllowed = [&](const httplib::Request& req, httplib::Response& res){
        std::cout << "Received invalid method " << req.method << " for /auth" << std::endl;
        res.status = 405;
        res.set_header("Content-Type", "text/plain");
        res.set_header("Allow", "POST");
    };
    svr.Get("/auth", authMethodNotAllowed);
    svr.Put("/auth", authMethodNotAllowed);
    svr.Delete("/auth", authMethodNotAllowed);
    svr.Patch("/auth", authMethodNotAllowed);
    svr.Options("/auth", authMethodNotAllowed);

    // catch-all for unknown routes and unhandled methods (including HEAD!)
    //source for coding these parts: https://github.com/yhirose/cpp-httplib
    
    svr.set_error_handler([](const httplib::Request& req, httplib::Response& res){
        std::cout << "Received request for unknown route or method: " << req.method << " " << req.path << std::endl;
        if (req.path == "/.well-known/jwks.json") {
            res.status = 405;
            res.set_header("Content-Type", "text/plain");
            res.set_header("Allow", "GET");
        } else if (req.path == "/auth") {
            res.status = 405;
            res.set_header("Content-Type", "text/plain");
            res.set_header("Allow", "POST");
        } else {
            res.status = 404;
            res.set_header("Content-Type", "text/plain");
            res.set_content("Not Found", "text/plain");
        }
    });

    std::cout << "Server starting on port 8080...\n";
    svr.listen("0.0.0.0", 8080);
}
