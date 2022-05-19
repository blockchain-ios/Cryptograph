//
//  Crypto.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation

public struct Crypto {
    
    /// 转成十六进制字符串
    /// - Parameter bytes: bytes字节数组
    /// - Returns: 十六进制字符串
    public static func toHexadecimal(bytes: [UInt8]) -> String {
        return bytes.reduce("") { $0 + String(format: "%02x", $1) }
    }
    
    public static func dataToBytes(data: Data) -> [UInt8] {
        return [UInt8](data)
    }
    
    /// 指定长度随机`Data`
    /// - Parameter length: 指定长度
    public static func randomData(length: Int) -> Data? {
        for _ in 0...1024 {
            var data = Data(repeating: 0, count: length)
            let result = data.withUnsafeMutableBytes { (body: UnsafeMutableRawBufferPointer) -> Int32? in
                if let address = body.baseAddress, body.count > 0 {
                    let pointer = address.assumingMemoryBound(to: UInt8.self)
                    return SecRandomCopyBytes(kSecRandomDefault, length, pointer)
                } else {
                    return nil
                }
            }
            if let result = result, result == errSecSuccess {
                return data
            }
        }
        return nil
    }
}
