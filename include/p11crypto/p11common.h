//
// Created by Robert on 2023/11/26.
//

#pragma once
#include <memory>
#include <libp11.h>
#include <openssl/err.h>
#include <openssl/engine.h>

namespace p11crypto {

class P11Deleter {
public:
    P11Deleter() {}
    ~P11Deleter() {}

    void operator()(::PKCS11_CTX* ctx) { ::PKCS11_CTX_free(ctx); }
    void operator()(::ENGINE* engine) { ::ENGINE_free(engine); }
};

using PKCS11Ctx = std::unique_ptr<::PKCS11_CTX, P11Deleter>;
using P11Engine = std::unique_ptr<::ENGINE, P11Deleter>;

} // namespace p11crypto
