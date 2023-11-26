//
// Created by Robert on 2023/11/26.
//

#pragma once
#include <filesystem>
#include <p11crypto/p11common.h>

namespace p11crypto {

class P11Ctx {
public:
    P11Ctx(const std::filesystem::path& module);
    ~P11Ctx();

    ::PKCS11_CTX* Get() const {
        return ctx_.get();
    }

private:
    PKCS11Ctx ctx_;
};

class P11Slot {
public:
    P11Slot(const P11Ctx& ctx);
    ~P11Slot();

    ::PKCS11_SLOT* Slots() {
      return slots_;
    }

    unsigned int SlotNum() const {
      return slotNum_;
    }

private:
    const P11Ctx& ctx_;
    ::PKCS11_SLOT* slots_;
    unsigned int slotNum_;
};

//class Crypto {
//public:
//  Crypto(const std::filesystem::path& module, const std::filesystem::path& engine);
//  ~Crypto();
//
//};

}
