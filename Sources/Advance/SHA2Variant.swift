//
//  SHA2Variant.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation

/// HASH
/// 一般翻译做散列、杂凑，或音译为哈希
/// 是把任意长度的输入（又叫做预映射pre-image）通过散列算法变换成固定长度的输出，该输出就是散列值
/// 这种转换是一种压缩映射，也就是，散列值的空间通常远小于输入的空间，不同的输入可能会散列成相同的输出
/// 所以不可能从散列值来确定唯一的输入值
/// 简单的说就是一种将任意长度的消息压缩到某一固定长度的消息摘要的函数

public enum SHA2Variant {
    case SHA224
    case SHA256
    case SHA384
    case SHA512
    case SHA512SLASH224
    case SHA512SLASH256
}

extension SHA2Variant {
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
