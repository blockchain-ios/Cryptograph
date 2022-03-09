//
//  PBKDF2.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/9.
//

/// `PBKDF2`
/// `Password-Based Key Derivation Function 2`
/// `PBKDF2`的基本原理是通过一个伪随机函数（例如`HMAC`函数），把明文和一个盐值作为输入参数，然后重复进行运算，并最终产生密钥
/// 如果重复的次数足够大，破解的成本就会变得很高，而盐值的添加也会增加“彩虹表”攻击的难度
/// https://en.wikipedia.org/wiki/PBKDF2
/// https://baike.baidu.com/item/PBKDF2/237696?fr=aladdin
/// https://blog.csdn.net/xy010902100449/article/details/52078767

/// 延伸：彩虹表
/// 彩虹表是一个用于加密散列函数逆运算的预先计算好的表，为破解密码的散列值（或称哈希值、微缩图、摘要、指纹、哈希密文）而准备
/// https://en.wikipedia.org/wiki/RainbowCrack
/// http://project-rainbowcrack.com/table.htm
/// https://baike.baidu.com/item/%E5%BD%A9%E8%99%B9%E8%A1%A8/689313?fr=aladdin
/// https://www.zhihu.com/question/19790488

import Foundation
import CommonCrypto

/// 算法类型
public enum PBKDF2Algorithm {
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512
}

extension Cryptograph.Crypto.PBKDF2 {
    
    /// PBKDF2
    /// Password-Based Key Derivation Function 2
    /// 基本原理是通过一个伪随机函数（例如`HMAC`函数），把明文和一个盐值作为输入参数，然后重复进行运算，并最终产生密钥
    /// 如果重复的次数足够大，破解的成本就会变得很高，而盐值的添加也会增加“彩虹表”攻击的难度
    ///
    /// - Parameters:
    ///   - algorithmType: 算法类型
    ///   - input: 输入
    ///   - salt: 盐
    ///   - iterationsCount: 迭代次数
    ///   - dkLen: 输出密文的长度
    /// - Returns: 输出的密文
    public static func PBKDF2(_ algorithmType: PBKDF2Algorithm,
                              input: String,
                              salt: String,
                              iterationsCount: UInt32,
                              dkLen: Int) -> Data? {
        guard var inputData = input.cString(using: .utf8) else { return nil }
        guard let saltData = salt.data(using: .utf8) else { return nil }
        var saltBytes = [UInt8](saltData)
        var result: [UInt8] = Array<UInt8>(repeating: 0, count: dkLen)
        // 使用网上的在线工具，会发现加密出来的和自己算得不一样，是因为网上的type是kCCPRFHmacAlgSHA1
        let error = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         &inputData,
                                         inputData.count,
                                         &saltBytes,
                                         saltBytes.count,
                                         algorithmType.algorithmType,
                                         iterationsCount,
                                         &result,
                                         result.count)
        if error == kCCSuccess {
            return Data(result)
        }
        return nil
    }
}

extension PBKDF2Algorithm {
    var algorithmType: UInt32 {
        switch self {
        case .sha1:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        case .sha224:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
        case .sha256:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .sha384:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case .sha512:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }
    }
}
