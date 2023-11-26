//
// Created by Kane on 2023/11/26.
//

#pragma once
#include <memory>
#include <libp11.h>
#include <openssl/err.h>

namespace p11crypto {

class P11Deleter {
public:
    P11Deleter() {}
    ~P11Deleter() {}

    void operator()(::PKCS11_CTX* ctx) {
      ::PKCS11_CTX_free(ctx);
    }
};

using PKCS11Ctx = std::unique_ptr<::PKCS11_CTX, P11Deleter>;

}
