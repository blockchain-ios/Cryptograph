//
//  Crypto.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation

public struct Crypto {
    public struct MD5 { }
    public struct HMAC { }
    public struct SHA256 { }
    public struct SHA512 { }
    public struct Base58 { }
    public struct PBKDF2 { }
}

extension Crypto {
    
    /// 转成十六进制字符串
    /// - Parameter bytes: bytes字节数组
    /// - Returns: 十六进制字符串
    public static func toHexadecimal(bytes: [UInt8]) -> String {
        return bytes.reduce("") { $0 + String(format: "%02x", $1) }
    }
}
