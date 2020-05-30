//
//  dukpt.h
//
//  Created by terukazu inoue on 2020/05/30.
//  Copyright © 2020 CODIANZ Inc. All rights reserved.
//

#if !defined(__h_dukpt__)
#define __h_dukpt__

#include <vector>
#include <string>

class dukpt
{
public:
  using bytes_t   = std::vector<uint8_t>;
  using cbytes_t  = const std::vector<uint8_t>;
  using string_t  = std::string;
  using cstring_t = const std::string;

private:
  static bytes_t calcIPEK(cbytes_t bdk, cbytes_t ksn);
  static bytes_t calcDataKey(cbytes_t ksn, cbytes_t ipek);
  static bytes_t calcBaseKey(cbytes_t ksn, cbytes_t ipek);
  
  static bytes_t decryptoTripleDES_CBC(cbytes_t src, cbytes_t key);
  static bytes_t encryptoTripleDES_ECB(cbytes_t src, cbytes_t key);
  static bytes_t encryptoDES(cbytes_t src, cbytes_t key);

  static bytes_t vxor(cbytes_t a, cbytes_t b);
  
protected:
  
public:
  
  static string_t decode(cstring_t sbdk, cstring_t sksn, cstring_t sdata);
  static bytes_t decode(cbytes_t bdk, cbytes_t ksn, cbytes_t data);
};
  
#endif /* !defined(__h_dukpt__) */
