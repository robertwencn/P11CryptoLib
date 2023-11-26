//
// Created by Robert on 2023/11/26.
//

#pragma once
#include <filesystem>
#include <libp11.h>

namespace p11crypto {

class P11Ctx {
public:
    P11Ctx(const std::filesystem::path& module);
    ~P11Ctx();

private:
    PKCS11Ctx ctx_;
};

class Crypto {
public:

};

}
