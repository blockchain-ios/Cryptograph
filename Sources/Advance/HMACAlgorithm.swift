//
//  HMACAlgorithm.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation

/// `HMAC`
/// `HMAC`是密钥相关的哈希运算消息认证码（`Hash-based Message Authentication Code`）的缩写
/// `HMAC`算法是一种基于密钥的报文完整性的验证方法，可以用来作加密、数字签名、报文验证等
/// 其安全性是建立在`Hash`加密算法基础上的
/// 它要求通信双方共享密钥、约定算法、对报文进行`Hash`运算，形成固定长度的认证码
/// 通信双方通过认证码的校验来确定报文的合法性

extension HMACAlgorithm {
    
    func hmac<T>(message: String, key: T) -> String {
        let bytes = Array(message.utf8)
        let result = hmac(bytes: bytes, key: key)
        return Crypto.toHexadecimal(bytes: [UInt8](result))
    }
    
    func hmac<T>(data: Data, key: T) -> Data {
        hmac(bytes: [UInt8](data), key: key)
    }
    
    func hmac<T>(bytes: [UInt8], key: T) -> Data {
        var result: Data
        if let _key = key as? String {
            result = Crypto.HMAC.CCHmac(key: Array(_key.utf8), bytes: bytes, algorithmType: self)
        } else if let _key = key as? Array<UInt8> {
            result = Crypto.HMAC.CCHmac(key: _key, bytes: bytes, algorithmType: self)
        } else if let _key = key as? Data {
            result = Crypto.HMAC.CCHmac(key: [UInt8](_key), bytes: bytes, algorithmType: self)
        } else {
            fatalError("Key type only supports String and Data and [UInt8]")
        }
        return result
    }
}
