//
//  HMAC.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation
import CommonCrypto

/// 算法类型
public enum HMACAlgorithm {
    case md5
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512
}

extension Cryptograph.Crypto.HMAC {
    
    /// Hash-based Message Authentication Code加密算法
    /// - Parameters:
    ///   - key: Raw key bytes.
    ///   - data: bytes字节数组
    ///   - algorithmType: 算法类型
    /// - Returns: 加密数据
    public static func CCHmac(key: [UInt8], bytes: [UInt8], algorithmType: HMACAlgorithm) -> Data {
        var key = key
        var bytes = bytes
        var result: [UInt8] = Array<UInt8>(repeating: 0x00, count: Int(algorithmType.digestLength))
        let algorithm = CCHmacAlgorithm(algorithmType.algorithmType)
        CommonCrypto.CCHmac(algorithm, &key, key.count, &bytes, bytes.count, &result)
        return Data(result)
    }
}

extension HMACAlgorithm {
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
