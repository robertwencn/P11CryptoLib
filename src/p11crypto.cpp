//
// Created by Robert on 2023/11/26.
//

#include <p11crypto/p11crypto.h>

namespace p11crypto {

P11Ctx::P11Ctx(const std::filesystem::path& module) : ctx_(::PKCS11_CTX_new()) {
    if (!std::filesystem::exists(module)) {
        throw std::runtime_error(module.string() + " not exists.");
    }

    int ret = ::PKCS11_CTX_load(Get(), module.c_str());
    if (ret != 0) {
        throw std::runtime_error("Load pkcs11 module failed.");
    }
}

P11Ctx::~P11Ctx() {
    if (ctx_ != nullptr) {
        ::PKCS11_CTX_unload(Get());
    }
}

P11Slot::P11Slot(const P11Ctx& ctx) : ctx_(ctx) {
    int ret = ::PKCS11_enumerate_slots(ctx_.Get(), &slots_, &slotNum_);
    if (ret != 0) {
        throw std::runtime_error("Can not enumerate slots");
    }
}

P11Slot::~P11Slot() {
    ::PKCS11_release_all_slots(ctx_.Get(), slots_, slotNum_);
}

Crypto::~Crypto() {
    if (ctx_ != nullptr) {
        ::PKCS11_CTX_unload(ctx_.get());
    }
}

bool Crypto::LoadEngine(const std::filesystem::path& engine, const std::string& pin) {
    if (!std::filesystem::exists(engine)) {
        return false;
    }

    ::ENGINE_load_builtin_engines();
    P11Engine eng { ENGINE_by_id("dynamic") };
    if (eng == nullptr) {
        return false;
    }

    if (::ENGINE_ctrl_cmd_string(eng.get(), "SO_PATH", module_.c_str(), 0) == 0) {
        return false;
    }

    if (::ENGINE_ctrl_cmd_string(eng.get(), "ID", "pkcs11", 0) == 0) {
        return false;
    }

    if (::ENGINE_ctrl_cmd_string(eng.get(), "LIST_ADD", "1", 0) == 0) {
        return false;
    }

    if (::ENGINE_ctrl_cmd_string(eng.get(), "LOAD", nullptr, 0) == 0) {
        return false;
    }

    if (::ENGINE_ctrl_cmd_string(eng.get(), "MODULE_PATH", engine.c_str(), 0) == 0) {
        return false;
    }

    if (::ENGINE_ctrl_cmd_string(eng.get(), "PIN", pin.c_str(), 0) == 0) {
        return false;
    }

    if (::ENGINE_init(eng.get()) == 0) {
        return false;
    }

    engine_ = std::move(eng);
    return true;
}

bool Crypto::GenerateRsaKeyPair(const std::string& tokenLabel, const RsaKeySize size, const std::string& id,
                        const std::string& keyLabel) {
    return true;
}

bool Crypto::GenerateEccKeyPair(const std::string& tokenLabel, const EccCurve curve, const std::string& id,
                        const std::string& keyLabel) {
    return true;
}

bool Crypto::GenerateSecretKey(const std::string& tokenLabel, const SecretKeySize keySize, const std::string& id,
                       const std::string& keyLabel) {
    return true;
}

} // namespace crypto
