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

} // namespace crypto
