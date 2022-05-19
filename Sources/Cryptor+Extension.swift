//
//  Cryptor+Ex.swift
//  Cryptograph
//
//  Created by Condy on 2022/5/18.
//

import Foundation

extension Cryptor: Encryptable {
    
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
