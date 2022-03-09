//
//  HMACAlgorithm.swift
//  Cryptograph
//
//  Created by Condy on 2022/3/8.
//

import Foundation

extension HMACAlgorithm {
    
    func hmac<T>(message: String, key: T) -> String {
        let bytes = Array(message.utf8)
        let result = hmac(bytes: bytes, key: key)
        return Crypto.toHexadecimal(bytes: [UInt8](result))
    }
    
    func hmac<T>(data: Data, key: T) -> Data {
        hmac(bytes: [UInt8](data), key: key)
    }
    
    func hmac<T>(bytes: [UInt8], key: T) -> Data {
        var result: Data
        if let _key = key as? String {
            result = Crypto.HMAC.CCHmac(self, bytes: bytes, key: Array(_key.utf8))
        } else if let _key = key as? Array<UInt8> {
            result = Crypto.HMAC.CCHmac(self, bytes: bytes, key: _key)
        } else if let _key = key as? Data {
            result = Crypto.HMAC.CCHmac(self, bytes: bytes, key: [UInt8](_key))
        } else {
            fatalError("Key type only supports String and Data and [UInt8]")
        }
        return result
    }
}
