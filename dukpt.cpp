//
//  dukpt.cpp
//
//  Created by terukazu inoue on 2020/05/30.
//  Copyright © 2020 CODIANZ Inc. All rights reserved.
//

#include "dukpt.h"
#include <boost/algorithm/hex.hpp>
#include <openssl/evp.h>
#include <stdexcept>

static const auto KEY_MASK = dukpt::bytes_t{0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00};


/* static */
dukpt::string_t dukpt::decode(cstring_t sbdk, cstring_t sksn, cstring_t sdata)
{
  bytes_t bdk, ksn, data;
  boost::algorithm::unhex(sbdk.cbegin() , sbdk.cend() , std::back_inserter(bdk));
  boost::algorithm::unhex(sksn.cbegin() , sksn.cend() , std::back_inserter(ksn));
  boost::algorithm::unhex(sdata.cbegin(), sdata.cend(), std::back_inserter(data));
  const auto res = decode(bdk, ksn, data);
  string_t sres;
  boost::algorithm::hex(res.cbegin(), res.cend(), std::back_inserter(sres));
  return sres;
}

/* static */
dukpt::bytes_t dukpt::decode(cbytes_t bdk, cbytes_t ksn, cbytes_t data)
{
  if(bdk.size() != 16) throw new std::invalid_argument("bdk.size() != 16");
  if(ksn.size() != 10) throw new std::invalid_argument("ksn.size() != 10");
  if(data.size() == 0) throw new std::invalid_argument("data.size() == 0");

  auto ipek = calcIPEK(bdk, ksn);
  auto dkey = calcDataKey(ksn, ipek);
  return decryptoTripleDES_CBC(data, dkey);
}

/* static */
dukpt::bytes_t dukpt::calcDataKey(cbytes_t ksn, cbytes_t ipek)
{
  auto datakey = calcBaseKey(ksn, ipek);
  datakey[5] ^= 0xFF;
  datakey[13] ^= 0xFF;
  return encryptoTripleDES_ECB(datakey, datakey);
}

/* static */
dukpt::bytes_t dukpt::calcBaseKey(cbytes_t ksn, cbytes_t ipek)
{
  uint32_t ec=0;

  uint32_t sr;
  bytes_t r8(8), r8a(8), r8b(8);
  bytes_t tksn(10);

  std::copy(ksn.cbegin(), ksn.cend(), tksn.begin());

  //extract counter from serial
  //5+8+8
  ec |= tksn[10 - 3] & 0x1F;
  ec <<= 8;
  ec |= tksn[10 - 2];
  ec <<= 8;
  ec |= tksn[10 - 1];

  //zero out the counter bytes
  tksn[10 - 3] &= ~0x1F;
  tksn[10 - 2] = 0;
  tksn[10 - 1] = 0;

  bytes_t dukptKey(16);
  std::copy(ipek.cbegin(), ipek.cend(), dukptKey.begin());
  std::copy(tksn.cbegin() + 2, tksn.cend(), r8.begin());
  sr = 0x100000;

  while(sr != 0){
    if((sr & ec) != 0){
      r8[5] |= sr >> 16;
      r8[6] |= sr >> 8;
      r8[7] |= sr;
      r8a = vxor(r8, bytes_t(dukptKey.cbegin() + 8, dukptKey.end()));
      r8a = encryptoDES(r8a, dukptKey);
      r8a = vxor(r8a, bytes_t(dukptKey.cbegin() + 8, dukptKey.cend()));
      dukptKey = vxor(dukptKey, KEY_MASK);
      r8b = vxor(r8, bytes_t(dukptKey.cbegin() + 8, dukptKey.end()));
      r8b = encryptoDES(r8b, dukptKey);
      r8b = vxor(r8b, bytes_t(dukptKey.cbegin() + 8, dukptKey.end()));
      std::copy(r8a.cbegin(), r8a.cend(), dukptKey.begin() + 8);
      std::copy(r8b.cbegin(), r8b.cend(), dukptKey.begin());
    }
    sr >>= 1;
  }
  
  return dukptKey;
}

/* static */
dukpt::bytes_t dukpt::calcIPEK(cbytes_t bdk, cbytes_t ksn)
{
  bytes_t ipek1(8);
  std::copy_n(ksn.cbegin(), 8, ipek1.begin());
  ipek1[7] &= 0xE0;
  ipek1 = encryptoTripleDES_ECB(ipek1, bdk);
  
  bytes_t ipek2(8);
  std::copy_n(ksn.cbegin(), 8, ipek2.begin());
  ipek2[7] &= 0xE0;
  auto tmp = vxor(bdk, KEY_MASK);
  
  ipek2 = encryptoTripleDES_ECB(ipek2, tmp);
  
  ipek1.insert(ipek1.end(), ipek2.cbegin(), ipek2.cend());
  return ipek1;
}

/* static */
dukpt::bytes_t dukpt::decryptoTripleDES_CBC(cbytes_t src, cbytes_t key)
{
  std::unique_ptr<EVP_CIPHER_CTX>  ctx;
  ctx.reset(new EVP_CIPHER_CTX);
  ::EVP_CIPHER_CTX_init(ctx.get());
  ::EVP_DecryptInit(ctx.get(), ::EVP_des_ede_cbc(), key.data(), nullptr); /* 3DES CBC 2key */
  bytes_t res(src.size());
  int  processbytes = 0;
  ::EVP_DecryptUpdate(ctx.get(), res.data(), &processbytes, src.data(), static_cast<int>(src.size()));
  return res;
}

/* static */
dukpt::bytes_t dukpt::encryptoTripleDES_ECB(cbytes_t src, cbytes_t key)
{
  std::unique_ptr<EVP_CIPHER_CTX>  ctx;
  ctx.reset(new EVP_CIPHER_CTX);
  ::EVP_CIPHER_CTX_init(ctx.get());
  ::EVP_EncryptInit(ctx.get(), ::EVP_des_ede(), key.data(), nullptr); /* 3DES ECB 2key */
  bytes_t res(src.size());
  int  processbytes = 0;
  ::EVP_EncryptUpdate(ctx.get(), res.data(), &processbytes, src.data(), static_cast<int>(src.size()));
  return res;
}

/* static */
dukpt::bytes_t dukpt::encryptoDES(cbytes_t src, cbytes_t key)
{
  std::unique_ptr<EVP_CIPHER_CTX>  ctx;
  ctx.reset(new EVP_CIPHER_CTX);
  ::EVP_CIPHER_CTX_init(ctx.get());
  ::EVP_EncryptInit(ctx.get(), ::EVP_des_ecb(), key.data(), key.data());  /* DES ECB */
  bytes_t res(src.size());
  int  processbytes = 0;
  ::EVP_EncryptUpdate(ctx.get(), res.data(), &processbytes, src.data(), static_cast<int>(src.size()));
  return res;
}


/* static */
dukpt::bytes_t dukpt::vxor(cbytes_t a, cbytes_t b)
{
  bytes_t r;
  std::transform(a.begin(), a.end(), b.begin(), std::back_inserter(r), std::bit_xor<uint8_t>());
  return r;
}
