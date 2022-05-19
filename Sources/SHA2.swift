//
//  SHA2.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

/// 一般翻译做散列、杂凑，或音译为哈希
/// 是把任意长度的输入（又叫做预映射pre-image）通过散列算法变换成固定长度的输出，该输出就是散列值
/// 这种转换是一种压缩映射，也就是，散列值的空间通常远小于输入的空间，不同的输入可能会散列成相同的输出
/// 所以不可能从散列值来确定唯一的输入值
/// 简单的说就是一种将任意长度的消息压缩到某一固定长度的消息摘要的函数

import Foundation
import CommonCrypto

extension Cryptograph.Crypto {
    public struct SHA256 { }
    public struct SHA512 { }
}

extension Cryptograph.Crypto.SHA256 {
    
    public static func hash32Bit(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256([UInt8](data), CC_LONG(data.count), &hash)
        return Data(hash)
    }
    
    public static func hash32Bit(bytes: [UInt8]) -> Data {
        Cryptograph.Crypto.SHA256.hash32Bit(data: Data(bytes))
    }
    
    public static func hash32Bit(message: String) -> String {
        guard let data = message.data(using: String.Encoding.utf8) else {
            return message
        }
        let _data = Cryptograph.Crypto.SHA256.hash32Bit(data: data)
        return Crypto.toHexadecimal(bytes: [UInt8](_data))
    }
}

extension Cryptograph.Crypto.SHA512 {
    
    public static func hash64Bit(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA512($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
    
    public static func hash64Bit(bytes: [UInt8]) -> Data {
        Cryptograph.Crypto.SHA512.hash64Bit(data: Data(bytes))
    }
    
    public static func hash64Bit(message: String) -> String {
        guard var data = message.data(using: String.Encoding.utf8) else {
            return message
        }
        data = Cryptograph.Crypto.SHA512.hash64Bit(data: data)
        return Crypto.toHexadecimal(bytes: [UInt8](data))
    }
}

extension Cryptograph.Crypto {
    public struct SHA2 {
        public enum Algorithm {
            case SHA224
            case SHA256
            case SHA384
            case SHA512
            case SHA512SLASH224
            case SHA512SLASH256
        }
    }
}

extension Cryptograph.Crypto.SHA2.Algorithm {
    func hash64Bit(data: Data) -> Data {
        switch self {
        case .SHA256:
            return Cryptograph.Crypto.SHA256.hash32Bit(data: data)
        case .SHA512:
            return Cryptograph.Crypto.SHA512.hash64Bit(data: data)
        default:
            return data
        }
    }
    
    func hash64Bit(bytes: [UInt8]) -> Data {
        switch self {
        case .SHA256:
            return Cryptograph.Crypto.SHA256.hash32Bit(bytes: bytes)
        case .SHA512:
            return Cryptograph.Crypto.SHA512.hash64Bit(bytes: bytes)
        default:
            return Data(bytes)
        }
    }
    
    func hash64Bit(message: String) -> String {
        switch self {
        case .SHA256:
            return Cryptograph.Crypto.SHA256.hash32Bit(message: message)
        case .SHA512:
            return Cryptograph.Crypto.SHA512.hash64Bit(message: message)
        default:
            return message
        }
    }
}
