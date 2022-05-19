//
//  Cryptor.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation

public enum Cryptor {
    
    case MD5(Crypto.MD5Lowercase)
    
    /// 哈希加密
    case SHA2(Crypto.SHA2.Algorithm)
    
    /// key支持`String`或者`[UInt8]`两种类型
    indirect case HMAC(Crypto.HMAC.Algorithm, key: Any)
}

public protocol Encryptable {
    
    func data(_ data: Data) -> Data
    
    func bytes(_ bytes: [UInt8]) -> Data
    
    func message(_ message: String) -> String
}
