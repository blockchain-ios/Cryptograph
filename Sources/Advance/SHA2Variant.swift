//
//  SHA2Variant.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation

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
