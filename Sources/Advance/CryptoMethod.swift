//
//  CryptoMethod.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation
import ObjectiveC

public enum CryptoMethod {
    case MD5(lowercase: Bool)
    case SHA2(SHA2Variant)
    /// key支持`String`或者`[UInt8]`两种类型
    indirect case HMAC(HMACAlgorithm, key: Any)
}

extension CryptoMethod {
    
    public func data(_ data: Data) -> Data {
        switch self {
        case .MD5(let lowercase):
            return Cryptograph.Crypto.MD5.hash(data: data, lowercase: lowercase)
        case .SHA2(let sHA2Variant):
            return sHA2Variant.hash64Bit(data: data)
        case .HMAC(let algorithm, let key):
            return algorithm.hmac(data: data, key: key)
        }
    }
    
    public func bytes(_ bytes: [UInt8]) -> Data {
        switch self {
        case .MD5(let lowercase):
            return Cryptograph.Crypto.MD5.hash(bytes: bytes, lowercase: lowercase)
        case .SHA2(let sHA2Variant):
            return sHA2Variant.hash64Bit(bytes: bytes)
        case .HMAC(let algorithm, let key):
            return algorithm.hmac(bytes: bytes, key: key)
        }
    }
    
    public func message(_ message: String) -> String {
        switch self {
        case .MD5(let lowercase):
            return Cryptograph.Crypto.MD5.hash(message: message, lowercase: lowercase)
        case .SHA2(let sHA2Variant):
            return sHA2Variant.hash64Bit(message: message)
        case .HMAC(let algorithm, let key):
            return algorithm.hmac(message: message, key: key)
        }
    }
}
