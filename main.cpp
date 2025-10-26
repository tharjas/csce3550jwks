#include "jwt_utils.h"
#include "httplib.h"
#include <vector>
#include <iostream>
#include <ctime>
#include "json.hpp"
#include <sqlite3.h>  // Include SQLite

using json = nlohmann::json;

// DB file name as per requirements
const std::string DB_FILE = "totally_not_my_privateKeys.db";

// Helper: Open DB connection
sqlite3* openDB() {
    sqlite3* db;
    if (sqlite3_open(DB_FILE.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Error opening DB: " << sqlite3_errmsg(db) << std::endl;
        return nullptr;
    }
    return db;
}

// Helper: Create table if not exists
void createTable(sqlite3* db) {
    const char* sql = "CREATE TABLE IF NOT EXISTS keys("
                      "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "key BLOB NOT NULL,"
                      "exp INTEGER NOT NULL);";
    char* errMsg;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Error creating table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

// Helper: Insert key into DB (serialize RSA to PEM)
void insertKey(sqlite3* db, const KeyPair& kp) {
    std::string pem = serializeRSA(kp.rsa);
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO keys (key, exp) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, pem.c_str(), pem.size(), SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, kp.expires);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Error inserting key: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    }
}

// Helper: Load keys from DB (deserialize PEM to RSA)
std::vector<KeyPair> loadKeys(sqlite3* db, bool includeExpired = false) {
    std::vector<KeyPair> keys;
    sqlite3_stmt* stmt;
    const char* sql = includeExpired ? "SELECT kid, key, exp FROM keys;"
                                     : "SELECT kid, key, exp FROM keys WHERE exp > ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (!includeExpired) {
            time_t now = time(nullptr);
            sqlite3_bind_int64(stmt, 1, now);
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            KeyPair kp;
            kp.kid = std::to_string(sqlite3_column_int(stmt, 0));
            const void* blob = sqlite3_column_blob(stmt, 1);
            int blobSize = sqlite3_column_bytes(stmt, 1);
            std::string pem(static_cast<const char*>(blob), blobSize);
            kp.rsa = deserializeRSA(pem);
            kp.expires = sqlite3_column_int64(stmt, 2);
            if (kp.rsa) keys.push_back(kp);
        }
        sqlite3_finalize(stmt);
    }
    return keys;
}

// Helper: Load a specific key (valid or expired)
KeyPair loadKey(sqlite3* db, bool expired) {
    std::vector<KeyPair> keys = loadKeys(db, true);  // Load all to select
    time_t now = time(nullptr);
    for (const auto& kp : keys) {
        if ((expired && kp.expires <= now) || (!expired && kp.expires > now)) {
            return kp;
        }
    }
    // Fallback: Generate if none found (shouldn't happen)
    KeyPair fallback = generateKey("fallback", expired ? -3600 : 3600);
    insertKey(db, fallback);
    return fallback;
}

int main() {
    httplib::Server svr;

    // Open DB and create table
    sqlite3* db = openDB();
    if (!db) return 1;
    createTable(db);

    // Check if keys exist; if not, generate and insert
    std::vector<KeyPair> existingKeys = loadKeys(db, true);
    if (existingKeys.size() < 2) {
        // Generate valid key (expires in 1 hour)
        KeyPair valid = generateKey("", 3600);  // Empty kid for AUTOINCREMENT
        insertKey(db, valid);
        // Generate expired key (expired 1 hour ago)
        KeyPair expired = generateKey("", -3600);
        insertKey(db, expired);
        std::cout << "Generated and stored keys in DB." << std::endl;
    } else {
        std::cout << "Keys loaded from DB." << std::endl;
    }

    // JWKS endpoint: serve only non-expired keys from DB
    svr.Get("/.well-known/jwks.json", [&](const httplib::Request&, httplib::Response& res){
        std::cout << "Received GET /.well-known/jwks.json request" << std::endl;
        json jwks; 
        jwks["keys"] = json::array();
        auto keys = loadKeys(db);  // Non-expired only
        for(auto& k : keys){
            auto [n,e] = getPublicKeyComponents(k.rsa);
            jwks["keys"].push_back({
                {"kid", k.kid},
                {"kty", "RSA"},
                {"alg", "RS256"},
                {"n", n},
                {"e", e}
            });
            RSA_free(k.rsa);  // Clean up
        }
        std::cout << "JWKS response: " << jwks.dump() << std::endl;
        res.status = 200;
        res.set_header("Content-Type", "application/json");
        res.set_content(jwks.dump(), "application/json");
    });

    // Handle non-GET requests to JWKS
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

    // Auth endpoint: issue JWTs from DB keys
    svr.Post("/auth", [&](const httplib::Request& req, httplib::Response& res){
        std::cout << "Received POST /auth request" << std::endl;
        bool useExpired = req.has_param("expired") && req.get_param_value("expired") == "true";
        KeyPair chosen = loadKey(db, useExpired);
        std::cout << "Using " << (useExpired ? "expired" : "valid") << " key (kid: " << chosen.kid << ")" << std::endl;

        json payload;
        payload["sub"] = "fakeuser";
        payload["iat"] = time(nullptr);
        payload["exp"] = chosen.expires;

        std::string token = signJWT(chosen, payload.dump());
        std::cout << "Generated JWT: " << token << std::endl;

        json out;
        out["token"] = token;
        out["kid"] = chosen.kid;
        out["expires_at"] = chosen.expires;

        res.status = 200;
        res.set_header("Content-Type", "application/json");
        res.set_content(out.dump(), "application/json");

        RSA_free(chosen.rsa);  // Clean up
    });

    // Handle non-POST requests to /auth
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

    // Catch-all for unknown routes
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

    sqlite3_close(db);  // Close DB on exit (though server runs indefinitely)
    return 0;
}
