//
//  HMAC.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

///`HMAC
/// HMAC是密钥相关的哈希运算消息认证码（`Hash-based Message Authentication Code`）的缩写
/// 算法是一种基于密钥的报文完整性的验证方法，可以用来作加密、数字签名、报文验证等
/// 其安全性是建立在`Hash`加密算法基础上的
/// 它要求通信双方共享密钥、约定算法、对报文进行`Hash`运算，形成固定长度的认证码
/// 通信双方通过认证码的校验来确定报文的合法性

import Foundation
import CommonCrypto

extension Cryptograph.Crypto {
    public struct HMAC { }
}

extension Cryptograph.Crypto.HMAC {
    public enum Algorithm {
        case md5
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
    }
}

extension Cryptograph.Crypto.HMAC {
    /// HMAC
    /// HMAC是密钥相关的哈希运算消息认证码（`Hash-based Message Authentication Code`）的缩写
    /// 是一种基于密钥的报文完整性的验证方法，可以用来作加密、数字签名、报文验证等
    /// 其安全性是建立在`Hash`加密算法基础上的
    /// 它要求通信双方共享密钥、约定算法、对报文进行`Hash`运算，形成固定长度的认证码
    /// 通信双方通过认证码的校验来确定报文的合法性
    /// - Parameters:
    ///   - algorithmType: 算法类型
    ///   - data: 待加密数据
    ///   - key: 加密key
    /// - Returns: 加密数据
    public static func CCHmac(_ algorithmType: Crypto.HMAC.Algorithm, data: Data, key: Data) -> Data {
        let bytes = [UInt8](data)
        return CCHmac(algorithmType, bytes: bytes, key: [UInt8](key))
    }
    
    /// Hash-based Message Authentication Code加密算法
    /// - Parameters:
    ///   - algorithmType: 算法类型
    ///   - bytes: bytes字节数组
    ///   - key: Raw key bytes.
    /// - Returns: 加密数据
    public static func CCHmac(_ algorithmType: Crypto.HMAC.Algorithm, bytes: [UInt8], key: [UInt8]) -> Data {
        var key = key
        var bytes = bytes
        var result: [UInt8] = Array<UInt8>(repeating: 0x00, count: Int(algorithmType.digestLength))
        let algorithm = CCHmacAlgorithm(algorithmType.algorithmType)
        CommonCrypto.CCHmac(algorithm, &key, key.count, &bytes, bytes.count, &result)
        return Data(result)
    }
}

extension Cryptograph.Crypto.HMAC.Algorithm {
    var algorithmType: Int {
        switch self {
        case .md5:
            return kCCHmacAlgMD5
        case .sha1:
            return kCCHmacAlgSHA1
        case .sha224:
            return kCCHmacAlgSHA224
        case .sha256:
            return kCCHmacAlgSHA256
        case .sha384:
            return kCCHmacAlgSHA384
        case .sha512:
            return kCCHmacAlgSHA512
        }
    }
    
    var digestLength: Int32 {
        switch self {
        case .md5:
            return CC_MD5_DIGEST_LENGTH
        case .sha1:
            return CC_SHA1_DIGEST_LENGTH
        case .sha224:
            return CC_SHA224_DIGEST_LENGTH
        case .sha256:
            return CC_SHA256_DIGEST_LENGTH
        case .sha384:
            return CC_SHA384_DIGEST_LENGTH
        case .sha512:
            return CC_SHA512_DIGEST_LENGTH
        }
    }
}

extension Cryptograph.Crypto.HMAC.Algorithm {
    
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
            result = Crypto.HMAC.CCHmac(self, bytes: bytes, key: Array(_key.utf8))
        } else if let _key = key as? Array<UInt8> {
            result = Crypto.HMAC.CCHmac(self, bytes: bytes, key: _key)
        } else if let _key = key as? Data {
            result = Crypto.HMAC.CCHmac(self, bytes: bytes, key: [UInt8](_key))
        } else {
            fatalError("Key type only supports String and Data and [UInt8]")
        }
        return result
    }
}
