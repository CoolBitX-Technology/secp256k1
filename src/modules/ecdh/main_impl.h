/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_MAIN_H
#define SECP256K1_MODULE_ECDH_MAIN_H

#include "secp256k1_ecdh.h"
#include "../../ecmult_const_impl.h"

int secp256k1_ecdh(const secp256k1_context* ctx, const secp256k1_pubkey *point, const unsigned char *scalar) {
    int ret = 0;
    int overflow = 0;
    secp256k1_gej res;
    secp256k1_ge pt;
    secp256k1_scalar s;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    secp256k1_pubkey_load(ctx, &pt, point);
    secp256k1_scalar_set_b32(&s, scalar, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&s)) {
        ret = 0;
    } else {
        unsigned char x[32];
        unsigned char y[1];
        secp256k1_sha256 sha;

        secp256k1_ecmult_const(&res, &pt, &s, 256);
        secp256k1_ge_set_gej(&pt, &res);
				secp256k1_pubkey_save(point, &pt);
        ret = 1;
    }

    secp256k1_scalar_clear(&s);
    return ret;
}

#endif /* SECP256K1_MODULE_ECDH_MAIN_H */
