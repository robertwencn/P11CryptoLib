//
// Created by Robert on 2023/11/26.
//

#pragma once
#include <filesystem>
#include <string>
#include <p11crypto/p11common.h>

namespace p11crypto {

enum class RsaKeySize {
    RSA1024 = 1024,
    RSA2048 = 2048,
    RSA3072 = 3072,
    RSA4096 = 4096
};

enum class SecretKeySize {
    AES128 = 128
};

enum class EccCurve {

};

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

class Crypto {
public:
  Crypto(const std::filesystem::path& module) : ctx_(module), slot_(ctx_), engine_(nullptr), module_(module) {}
  ~Crypto();

  bool LoadEngine(const std::filesystem::path& engine, const std::string& pin);

  bool GenerateRsaKeyPair(const std::string& tokenLabel, const RsaKeySize size, const std::string& id,
                          const std::string& keyLabel);
  bool GenerateEccKeyPair(const std::string& tokenLabel, const EccCurve curve, const std::string& id,
                          const std::string& keyLabel);
  bool GenerateSecretKey(const std::string& tokenLabel, const SecretKeySize keySize, const std::string& id,
                         const std::string& keyLabel);

private:
    P11Ctx ctx_;
    P11Slot slot_;
    P11Engine engine_;
    std::filesystem::path module_;
};

}
