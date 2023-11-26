//
// Created by Robert on 2023/11/26.
//

#include<gtest/gtest.h>

#include <p11crypto/p11crypto.h>

using namespace p11crypto;

TEST(P11CtxTest, ConstructorTest) {
    P11Ctx ctx ("/usr/lib/softhsm/libsofthsm2.so" );
    EXPECT_TRUE( ctx.Get() != nullptr );
}

TEST(P11SlotTest, ConstructorTest) {
    P11Ctx ctx ("/usr/lib/softhsm/libsofthsm2.so" );
    P11Slot slot(ctx);

    EXPECT_TRUE(slot.Slots() != nullptr);
    EXPECT_TRUE(slot.SlotNum() != 0);
}
