//
//  MD5.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation
import CommonCrypto

extension Cryptograph.Crypto {
    public typealias MD5Lowercase = Bool
    public struct MD5 { }
}

extension Cryptograph.Crypto.MD5 {
    
    public static func hash(data: Data, lowercase: Crypto.MD5Lowercase) -> Data {
        guard let string = String(data: data, encoding: String.Encoding.utf8) else {
            return data
        }
        let message = Cryptograph.Crypto.MD5.hash(message: string, lowercase: lowercase)
        return message.data(using: String.Encoding.utf8) ?? data
    }
    
    public static func hash(bytes: [UInt8], lowercase: Crypto.MD5Lowercase) -> Data {
        return Cryptograph.Crypto.MD5.hash(data: Data(bytes), lowercase: lowercase)
    }
    
    public static func hash(message: String, lowercase: Crypto.MD5Lowercase) -> String {
        let ccharArray = message.cString(using: String.Encoding.utf8)
        var uint8Array = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5(ccharArray, CC_LONG(ccharArray!.count - 1), &uint8Array)
        return uint8Array.reduce("") { $0 + String(format: lowercase ? "%02x" : "%02X", $1) }
    }
}
