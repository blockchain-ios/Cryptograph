//
//  CryptoDemoTests.swift
//  CryptoDemoTests
//
//  Created by Condy on 2022/3/8.
//

import XCTest
@testable import Cryptograph

class CryptoDemoTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        // Any test you write for XCTest can be annotated as throws and async.
        // Mark your test throws to produce an unexpected failure when your test encounters an uncaught error.
        // Mark your test async to allow awaiting for asynchronous code to complete. Check the results with assertions afterwards.
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
    func testMD5() {
        let result = CryptoMethod.MD5(lowercase: true).message("")
        XCTAssertEqual(result, "d41d8cd98f00b204e9800998ecf8427e")
    }
    
    func testSHA256() {
        let result = CryptoMethod.SHA2(SHA2Variant.SHA256).message("")
        XCTAssertEqual(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }
    
    func testSHA512() {
        let result = CryptoMethod.SHA2(SHA2Variant.SHA512).message("")
        XCTAssertEqual(result, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    }
    
    func testHMAC() {
        let result = CryptoMethod.HMAC(HMACAlgorithm.md5, key: "").message("")
        XCTAssertEqual(result, "74e6f7298a9c2d168935f58c001bad88")
    }
}
