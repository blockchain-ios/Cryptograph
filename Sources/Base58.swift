//
//  Base58.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/9.
//

///`Base58
/// 是用于比特币中使用的一种独特的编码方式，主要用于产生比特币钱包地址
/// 相比`Base64`，`Base58`不使用数字"0"，字母大写"O"，字母大写"I"，和字母小写"l"，以及"+"和"/"符号
/// 本质其实就是58进制
/// https://www.cnblogs.com/yanglang/p/10147028.html
/// https://blog.csdn.net/bnbjin/article/details/81431686
/// https://blog.csdn.net/idwtwt/article/details/80740474
/// https://www.sohu.com/a/238347731_116580
/// https://www.liankexing.com/q/6455

/// `Base58 Check`
/// 1.首先对数据添加一个版本前缀，这个前缀用来识别编码的数据类型
/// 2.对数据连续进行两次`SHA256`哈希算法，checksum = SHA256(SHA256(prefix+data))
/// 3.在产生的长度为`32`个字节（两次哈希云算）的哈希值中，取其前`4`个字节作为检验和添加到数据第一步产生的数据之后
/// 4.将数据进行Base58编码处理
/// https://blog.csdn.net/luckydog612/article/details/81168276
/// https://www.jianshu.com/p/9644fe5a06bc
/// 地址前缀列表：https://en.bitcoin.it/wiki/List_of_address_prefixes

import Foundation

extension Cryptograph.Crypto {
    public struct Base58 { }
}

extension Cryptograph.Crypto.Base58 {
    private static let base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    // `Base 58`编码
    public static func base58Encoded(data: Data) -> String {
        var bytes = [UInt8](data)
        var zerosCount = 0
        var length = 0
        for b in bytes {
            if b != 0 { break }
            zerosCount += 1
        }
        bytes.removeFirst(zerosCount)
        let size = bytes.count * 138 / 100 + 1
        var base58: [UInt8] = Array(repeating: 0, count: size)
        for b in bytes {
            var carry = Int(b)
            var i = 0
            for j in 0...base58.count-1 where carry != 0 || i < length {
                carry += 256 * Int(base58[base58.count - j - 1])
                base58[base58.count - j - 1] = UInt8(carry % 58)
                carry /= 58
                i += 1
            }
            assert(carry == 0)
            length = i
        }
        // skip leading zeros
        var zerosToRemove = 0
        var str = ""
        for b in base58 {
            if b != 0 { break }
            zerosToRemove += 1
        }
        base58.removeFirst(zerosToRemove)
        while 0 < zerosCount {
            str = "\(str)1"
            zerosCount -= 1
        }
        for b in base58 {
            str = "\(str)\(base58Alphabet[String.Index(utf16Offset: Int(b), in: base58Alphabet)])"
        }
        return str
    }
    
    // `Base 58`解码
    public static func base58Decoded(base58String: String) -> [UInt8] {
        // remove leading and trailing whitespaces
        let string = base58String.trimmingCharacters(in: CharacterSet.whitespaces)
        guard !string.isEmpty else { return [] }
        var zerosCount = 0
        var length = 0
        for c in string {
            if c != "1" { break }
            zerosCount += 1
        }
        
        let size = string.lengthOfBytes(using: String.Encoding.utf8) * 733 / 1000 + 1 - zerosCount
        var base58: [UInt8] = Array(repeating: 0, count: size)
        for c in string where c != " " {
            // search for base58 character
            guard let base58Index = base58Alphabet.firstIndex(of: c) else { return [] }
            var carry = base58Index.utf16Offset(in: base58Alphabet)
            var i = 0
            for j in 0...base58.count where carry != 0 || i < length {
                carry += 58 * Int(base58[base58.count - j - 1])
                base58[base58.count - j - 1] = UInt8(carry % 256)
                carry /= 256
                i += 1
            }
            assert(carry == 0)
            length = i
        }
        // skip leading zeros
        var zerosToRemove = 0
        
        for b in base58 {
            if b != 0 { break }
            zerosToRemove += 1
        }
        base58.removeFirst(zerosToRemove)
        var result: [UInt8] = Array(repeating: 0, count: zerosCount)
        for b in base58 {
            result.append(b)
        }
        return result
    }
    
    /// `Base 58 Check`编码
    public static func base58CheckEncoded(data: Data?) -> String? {
        guard let data = data else { return nil }
        // 连续两次`SHA256`
        let sha256Data = Cryptograph.Crypto.SHA256.hash32Bit(data: data)
        let checksums = Cryptograph.Crypto.SHA256.hash32Bit(data: sha256Data)
        // 取前4位得到`checksum`
        let checksum = Array(checksums[0..<4])
        // 得到完整的`bytes`
        let resultData = data + checksum
        // Base58编码
        let base58String = Cryptograph.Crypto.Base58.base58Encoded(data: resultData)
        return base58String
    }
    
    /// `Base 58 Check`解码
    public static func base58CheckDecoded(base58Data: Data?) -> Data? {
        let base58Data = base58Data ?? Data()
        guard let base58String = String(data: base58Data, encoding: .utf8) else { return nil }
        // 先解码
        var bytes = Cryptograph.Crypto.Base58.base58Decoded(base58String: base58String)
        guard bytes.count > 4 else { return nil }
        let checksum = [UInt8](bytes.suffix(4))
        bytes = [UInt8](bytes.prefix(bytes.count - 4))
        let sha256Data = Cryptograph.Crypto.SHA256.hash32Bit(bytes: bytes)
        var calculatedChecksum = Cryptograph.Crypto.SHA256.hash32Bit(data: sha256Data)
        calculatedChecksum = calculatedChecksum[0..<4]
        if checksum != [UInt8](calculatedChecksum) { return nil }
        return Data(bytes)
    }
    
    /// `Base 58 Check`解码
    public static func base58CheckDecoded(base58String: String?) -> Data? {
        guard let base58String = base58String, let data = base58String.data(using: .utf8) else {
            return nil
        }
        return Cryptograph.Crypto.Base58.base58CheckDecoded(base58Data: data)
    }
}
