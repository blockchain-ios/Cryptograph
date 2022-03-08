//
//  SHA2.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation
import CommonCrypto

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
