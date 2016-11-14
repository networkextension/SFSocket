//
//  EncryptExtension.swift
//  Surf
//
//  Created by 孔祥波 on 7/14/16.
//  Copyright © 2016 yarshure. All rights reserved.
//

//
//  HMAC.swift
//
//  Created by Mihael Isaev on 21.04.15.
//  Copyright (c) 2014 Mihael Isaev inc. All rights reserved.
//
// ***********************************************************
//
// How to import CommonCrypto in Swift project without Obj-c briging header
//
// To work around this create a directory called CommonCrypto in the root of the project using Finder.
// In this directory create a file name module.map and copy the following into the file.
// You will need to alter the paths to ensure they point to the headers on your system.
//
// module CommonCrypto [system] {
//     header "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include/CommonCrypto/CommonCrypto.h"
//     export *
// }
// To make this module visible to Xcode, go to Build Settings, Swift Compiler – Search Paths
// and set Import Paths to point to the directory that contains the CommonCrypto directory.
//
// You should now be able to use import CommonCrypto in your Swift code.
//
// You have to set the Import Paths in every project that uses your framework so that Xcode can find it.
//
// ***********************************************************
//
// Move to Swift 3 by yarshure

import Foundation
import CommonCrypto

extension String {
    var md5x: String {
        return HMAC.hash(inp: self, algo: HMACAlgo.MD5)
    }
    
    var sha1: String {
        return HMAC.hash(inp: self, algo: HMACAlgo.SHA1)
    }
    
    var sha224: String {
        return HMAC.hash(inp: self, algo: HMACAlgo.SHA224)
    }
    
    var sha256: String {
        return HMAC.hash(inp: self, algo: HMACAlgo.SHA256)
    }
    
    var sha384: String {
        return HMAC.hash(inp: self, algo: HMACAlgo.SHA384)
    }
    
    var sha512: String {
        return HMAC.hash(inp: self, algo: HMACAlgo.SHA512)
    }
}
extension Data {
    var md5x: Data {
        return HMAC.hashData(inp: self, algo: HMACAlgo.MD5)
    }
    
    var sha1: Data {
        return HMAC.hashData(inp: self, algo: HMACAlgo.SHA1)
    }
    
    var sha224: Data {
        return HMAC.hashData(inp: self, algo: HMACAlgo.SHA224)
    }
    
    var sha256: Data {
        return HMAC.hashData(inp: self, algo: HMACAlgo.SHA256)
    }
    
    var sha384: Data {
        return HMAC.hashData(inp: self, algo: HMACAlgo.SHA384)
    }
    
    var sha512: Data {
        return HMAC.hashData(inp: self, algo: HMACAlgo.SHA512)
    }
}
extension Data {
//    func hmac(algorithm: HMACAlgo, cKey: NSData) -> NSData {
//        
//        
//        var result = [CUnsignedChar](count: Int(algorithm.digestLength()), repeatedValue: 0)
//        let length : Int = cKey.length
//        let data : Int = self.length
//        CCHmac(algorithm.toCCHmacAlgorithm(), cKey!,length , self, data, &result)
//        
//        let hmacData:NSData = NSData(bytes: result, length: (Int(algorithm.digestLength())))
//        
//        
//        
//        return hmacData
//    }
    
    
    func hmacsha1(keyData: Data) -> Data {
        let algorithm = HMACAlgo.SHA1
        let digestLen = algorithm.digestLength()
        let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
        
        let ptr = (keyData  as NSData).bytes
        let ptr2 = (self as NSData).bytes
        CCHmac(algorithm.toCCEnum(),ptr,  keyData.count, ptr2, Int(self.count), result)
        let data = Data.init(bytes:  result, count: digestLen)
        result.deallocate(capacity: digestLen)
        return data.subdata(in: Range(0 ..< 10))
        //.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding64CharacterLineLength)
    }

}

public struct HMAC {
    
    static func hash(inp: String, algo: HMACAlgo) -> String {
        if let stringData = inp.data(using: String.Encoding.utf8, allowLossyConversion: false) {
            return hexStringFromData(input: digest(input: stringData, algo: algo))
        }
        return ""
    }
    static func hashData(inp: Data, algo: HMACAlgo) -> Data {
        //if let stringData = inp.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) {
            return digest(input: inp , algo: algo)
        //}
        //return
    }
    private static func digest(input : Data, algo: HMACAlgo) -> Data {
        let digestLength = algo.digestLength()
        var hash = [UInt8](repeating: 0, count: digestLength)
        let x = (input as NSData).bytes
        switch algo {
        case .MD5:
            CC_MD5(x, UInt32(input.count), &hash)
            break
        case .SHA1:
            CC_SHA1(x, UInt32(input.count), &hash)
            break
        case .SHA224:
            CC_SHA224(x, UInt32(input.count), &hash)
            break
        case .SHA256:
            CC_SHA256(x, UInt32(input.count), &hash)
            break
        case .SHA384:
            CC_SHA384(x, UInt32(input.count), &hash)
            break
        case .SHA512:
            CC_SHA512(x, UInt32(input.count), &hash)
            break
        }
        return Data.init(bytes: hash, count: digestLength)
    }
    
    private static func hexStringFromData(input: Data) -> String {
        var bytes = [UInt8](repeating: 0, count: input.count)
        input.copyBytes(to: &bytes, count: input.count)
        
        var hexString = ""
        for byte in bytes {
            hexString += String(format:"%02x", UInt8(byte))
        }
        
        return hexString
    }
}

enum HMACAlgo {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    func digestLength() -> Int {
        var result: CInt = 0
        switch self {
        case .MD5:
            result = CC_MD5_DIGEST_LENGTH
        case .SHA1:
            result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:
            result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:
            result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:
            result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:
            result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
    func toCCEnum() -> CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:
            result = kCCHmacAlgMD5
        case .SHA1:
            result = kCCHmacAlgSHA1
        case .SHA224:
            result = kCCHmacAlgSHA224
        case .SHA256:
            result = kCCHmacAlgSHA256
        case .SHA384:
            result = kCCHmacAlgSHA384
        case .SHA512:
            result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
}
