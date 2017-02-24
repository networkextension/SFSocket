//
//  SFEncrypt.swift
//  SSencrypt
//
//  Created by 孔祥波 on 7/8/16.
//  Copyright © 2016 Kong XiangBo. All rights reserved.
//

import Foundation
import CommonCrypto
import AxLogger
import Sodium
//import Security

let  kCCAlgorithmInvalid =  UINT32_MAX
let  supported_ciphers_iv_size = [
    0, 0, 16, 16, 16, 16, 8, 16, 16, 16, 8, 8, 8, 8, 16, 8, 8, 12
];

let supported_ciphers_key_size = [
    0, 16, 16, 16, 24, 32, 16, 16, 24, 32, 16, 8, 16, 16, 16, 32, 32, 32
];
let SODIUM_BLOCK_SIZE:UInt64 = 64
public enum  CryptoMethod:Int,CustomStringConvertible{
    //case NONE       =         -1
    case TABLE     =          0
    case RC4         =        1
    case RC4_MD5      =       2
    case AES_128_CFB   =      3
    case AES_192_CFB    =     4
    case AES_256_CFB     =    5
    case BF_CFB           =   6
    case CAMELLIA_128_CFB  =  7
    case CAMELLIA_192_CFB   = 8
    case CAMELLIA_256_CFB    = 9
    case CAST5_CFB  =         10
    case DES_CFB     =        11
    case IDEA_CFB     =       12
    case RC2_CFB       =      13
    case SEED_CFB       =     14
    case SALSA20         =    15
    case CHACHA20         =   16
    case CHACHA20IETF      =  17
    public var description: String {
        switch self {
            
        //case NONE:      return         "NONE"
        case .TABLE:     return         "TABLE"
        case .RC4:         return        "RC4"
        case .RC4_MD5:      return       "RC4-MD5"
        case .AES_128_CFB:   return      "AES-128-CFB"
        case .AES_192_CFB:    return     "AES_192-CFB"
        case .AES_256_CFB:     return    "AES-256-CFB"
        case .BF_CFB:           return   "BF-CFB"
        case .CAMELLIA_128_CFB:  return  "CAMELLIA-128-CFB"
        case .CAMELLIA_192_CFB:   return "CAMELLIA-192-CFB"
        case .CAMELLIA_256_CFB:    return "CAMELLIA-256-CFB"
        case .CAST5_CFB:  return         "CAST5-CFB"
        case .DES_CFB:     return        "DES-CFB"
        case .IDEA_CFB:     return       "IDEA-CFB"
        case .RC2_CFB:       return      "RC2-CFB"
        case .SEED_CFB:       return     "SEED-CFB"
        case .SALSA20:         return    "SALSA20"
        case .CHACHA20:         return   "CHACHA20"
        case .CHACHA20IETF:      return  "CHACHA20IETF"
        }
    }
    public var support:Bool {
        switch self {
        //case NONE:      return         false
        case .TABLE:     return         false
        case .RC4:         return        false
        case .RC4_MD5:      return       false
        case .AES_128_CFB:   return      true
        case .AES_192_CFB:    return     true
        case .AES_256_CFB:     return    true
        case .BF_CFB:           return   false
        case .CAMELLIA_128_CFB:  return  false
        case .CAMELLIA_192_CFB:   return false
        case .CAMELLIA_256_CFB:    return false
        case .CAST5_CFB:  return         false
        case .DES_CFB:     return        false
        case .IDEA_CFB:     return       false
        case .RC2_CFB:       return      false
        case .SEED_CFB:       return     false
        case .SALSA20:         return    true
        case .CHACHA20:         return   true
        case .CHACHA20IETF:      return  true
        }
    }
    public var ccmode:CCMode {
        switch self {
            
        case .RC4:         return        9//4
        case .RC4_MD5:      return       9//4
        case .AES_128_CFB:   return      3
        case .AES_192_CFB:    return     3
        case .AES_256_CFB:     return    3
        case .BF_CFB:           return   3
            
        case .CAST5_CFB:  return         3
        case .DES_CFB:     return        3
        case .IDEA_CFB:     return       3
        case .RC2_CFB:       return      3
        case .SEED_CFB:       return     3
            
            
        default:
            return UInt32.max
        }
    }
    func supported_ciphers() ->CCAlgorithm {
        
        _ = 0
        switch self {
        //case NONE:      return         false
        case .TABLE:     return         kCCAlgorithmInvalid
        case .RC4:         return        UInt32(kCCAlgorithmRC4)
        case .RC4_MD5:      return       CCAlgorithm(kCCAlgorithmRC4)
        case .AES_128_CFB:   return      CCAlgorithm(kCCAlgorithmAES)
        case .AES_192_CFB:    return     CCAlgorithm(kCCAlgorithmAES)
        case .AES_256_CFB:     return    CCAlgorithm(kCCAlgorithmAES)
        case .BF_CFB:           return   CCAlgorithm(kCCAlgorithmBlowfish)
        case .CAMELLIA_128_CFB:  return  kCCAlgorithmInvalid
        case .CAMELLIA_192_CFB:   return kCCAlgorithmInvalid
        case .CAMELLIA_256_CFB:    return kCCAlgorithmInvalid
        case .CAST5_CFB:  return         CCAlgorithm(kCCAlgorithmCAST)
        case .DES_CFB:     return        CCAlgorithm(kCCAlgorithmDES)
        case .IDEA_CFB:     return       kCCAlgorithmInvalid
        case .RC2_CFB:       return      CCAlgorithm(kCCAlgorithmRC2)
        case .SEED_CFB:       return     kCCAlgorithmInvalid
        case .SALSA20:         return    kCCAlgorithmInvalid
        case .CHACHA20:         return   kCCAlgorithmInvalid
        case .CHACHA20IETF:      return  kCCAlgorithmInvalid
        }
        
        
        
    }
    public var iv_size:Int {
        return supported_ciphers_iv_size[self.rawValue]
    }
    public var key_size:Int {
        return supported_ciphers_key_size[self.rawValue]
    }
    init(cipher:String){
        let up = cipher.uppercased()
        var raw = 0
        switch up {
        //case "NONE":     raw = -1
        case "TABLE":     raw = 0
        case "RC4":         raw = 1
        case "RC4-MD5":      raw = 2
        case "AES-128-CFB":   raw = 3
        case "AES-192-CFB":    raw = 4
        case "AES-256-CFB":     raw = 5
        case "BF-CFB":           raw = 6
        case "CAMELLIA-128-CFB":  raw = 7
        case "CAMELLIA-192-CFB":   raw = 8
        case "CAMELLIA-256-CFB":    raw = 9
        case "CAST5-CFB":          raw = 10
        case "DES-CFB":     raw = 11
        case "IDEA-CFB":     raw = 12
        case "RC2-CFB":       raw = 13
        case "SEED-CFB":       raw = 14
        case "SALSA20":         raw = 15
        case "CHACHA20":         raw = 16
        case "CHACHA20IETF":      raw = 17
        default:
            raw = 0
        }
        self = CryptoMethod(rawValue:raw)!
    }
}





let  ONETIMEAUTH_BYTES = 10
let  MAX_KEY_LENGTH =  64
let  MAX_IV_LENGTH = 16
let CLEN_BYTES = 2

class enc_ctx {
    var m:CryptoMethod
    static var sodiumInited = false
    var counter:UInt64 = 0
    //let cryptor = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)
    var IV:Data
    
    var  ctx:CCCryptorRef?
    var cryptoInit:Bool = false
    func test (){
        let abcd = "aaaa"
        if abcd.hasPrefix("aa"){
            
        }
    }
    static func setupSodium() {
        if !enc_ctx.sodiumInited {
            if sodium_init() == -1 {
                //print("sodium_init failure")
                AxLogger.log("sodium_init failure todo fix",level: .Error)
            }
        }
    }
    static func create_enc(op:CCOperation,key:Data,iv:Data,m:CryptoMethod,cryptor: inout UnsafeMutablePointer<CCCryptorRef?>)   {//->CCCryptorRef?
        
        let algorithm:CCAlgorithm =  m.supported_ciphers() // findCCAlgorithm(Int32(m.rawValue))
        //var  cryptor :CCCryptorRef?
        
        let key_size = m.key_size
        
        let  createDecrypt:CCCryptorStatus = CCCryptorCreateWithMode(op, // operation
            m.ccmode, // mode CTR kCCModeRC4= 9
            algorithm,//CCAlgorithm(0),//kCCAlgorithmAES, // Algorithm
            CCPadding(0), // padding
            (iv as NSData).bytes, // can be NULL, because null is full of zeros
            (key  as NSData).bytes, // key
            key_size, // keylength
            nil, //const void *tweak
            0, //size_t tweakLength,
            0, //int numRounds,
            0, //CCModeOptions options,
            cryptor); //CCCryptorRef *cryptorRef
        if (createDecrypt == CCCryptorStatus(0)){
            //let ptr = cryptor.pointee
            //cryptor.deallocate(capacity: 1)
            //return ptr
        }else {
            AxLogger.log("create crypto ctx error",level: .Error)
            //return nil
        }
        
    }
    init(key:Data,iv:Data,encrypt:Bool,method:CryptoMethod){
        
        if method.iv_size != iv.count {
            fatalError()
        }
        
        //findCCAlgorithm(Int32(method.rawValue)) //m.supported_ciphers()
        var true_key:Data
        if method == .RC4_MD5 {
            var key_iv = Data()
            key_iv.append(key)
            key_iv.count = 16
            key_iv.append(iv)
            
            
            true_key = key_iv.md5x
            //iv_len   = 0;
        }else {
            true_key = key
            
            
        }
        
        m = method
        let c = m.supported_ciphers()
        if  c != UInt32.max {
            
            var opt:CCOperation = CCOperation(1)
            if encrypt {
                opt = CCOperation(0)
                
            }
            var temp:CCCryptorRef?
            let  createDecrypt:CCCryptorStatus = CCCryptorCreateWithMode(opt, // operation
                m.ccmode, // mode CTR kCCModeRC4= 9
                m.supported_ciphers(),//CCAlgorithm(0),//kCCAlgorithmAES, // Algorithm
                CCPadding(0), // padding
                (iv as NSData).bytes, // can be NULL, because null is full of zeros
                (true_key  as NSData).bytes, // key
                m.key_size, // keylength
                nil, //const void *tweak
                0, //size_t tweakLength,
                0, //int numRounds,
                0, //CCModeOptions options,
                &temp); //CCCryptorRef *cryptorRef
            if (createDecrypt == CCCryptorStatus(0)){
                cryptoInit = true
                ctx = temp
            }else {
                AxLogger.log("create crypto ctx error",level: .Error)
                
            }
            //CCCryptorRelease(temp)
            //ctx = cryptor.pointee
            //cryptor.deallocate(capacity: 1)
            
        }else {
            //ctx = nil
            if method == .SALSA20 || method == .CHACHA20 || method == .CHACHA20IETF {
                //let sIV = NSMutableData.init(data: iv)
                //sIV.length = 16
                
                enc_ctx.setupSodium()
            }
            //init
        }
        
        IV = iv
        
    }
    
    deinit {
        
        if ctx != nil {
            CCCryptorRelease(ctx)
        }

       
        print("enc deinit")
        
    }
}
public class SSEncrypt {
    
    var m:CryptoMethod
    var testenable:Bool = false
    var send_ctx:enc_ctx
    var recv_ctx:enc_ctx!
    //let block_size = 16
    public var ramdonKey:Data?
    var ivBuffer:Data = Data()
    static var iv_cache:[Data] = []
    static func have_iv(i:Data,m:CryptoMethod) ->Bool {
        let x = CryptoMethod.RC4_MD5
        if m.rawValue >= x.rawValue {
            for x in SSEncrypt.iv_cache {
                if x == i {
                    return true
                }
            }
        }
        SSEncrypt.iv_cache.append(i)
        return false
        
    }
    deinit {
        print("SFEncrypt deinit")
    }
    func dataWithHexString(hex: String) -> Data {
        var hex = hex
        let  data = SFData()
        while(hex.characters.count > 0) {
            let c: String = hex.to(index: 2)
            hex = hex.to(index: 2)
            var ch: UInt32 = 0
            Scanner(string: c).scanHexInt32(&ch)
            data.append(ch)
        }
        return data.data
    }
    public init(password:String,method:String) {
        
        m = CryptoMethod.init(cipher: method)
        //print("method:\(m.description)")
        ramdonKey  = SSEncrypt.evpBytesToKey(password: password,keyLen: m.key_size)
        
        let iv =  SSEncrypt.getSecureRandom(bytesCount: m.iv_size)
        
        send_ctx = enc_ctx.init(key: ramdonKey!, iv: iv, encrypt: true,method:m )
        
        
    }
    func recvCTX(iv:Data){
        //debugLog(message: "use iv create ctx \(iv)")
        if SSEncrypt.have_iv(i: iv,m:m)  && !testenable{
            AxLogger.log("cryto iv dup error",level: .Error)
            
        }else {
            recv_ctx = enc_ctx.init(key: ramdonKey!, iv: iv, encrypt: false,method:m)
            
        }
        
    }
    static func evpBytesToKey(password:String, keyLen:Int) ->Data {
        let  md5Len:Int = 16
        
        let cnt = (keyLen - 1)/md5Len + 1
        var m = Data.init(count: cnt*md5Len)
        let bytes = password.data(using: .utf8, allowLossyConversion: false)
        // memcpy((m?.mutableBytes)!, bytes.bytes , password.characters.count)
        let md5 = bytes?.md5x
        m = md5!
        
        
        // Repeatedly call md5 until bytes generated is enough.
        // Each call to md5 uses data: prev md5 sum + password.
        var d = Data()//.init(count:md5Len+(bytes?.count)!)
        //d := make([]byte, md5Len+len(password))
        var start = 0
        for _ in 0 ..< cnt {//最长32,算法还不支持>32 的情况
            start += md5Len
            d.append(m)
            d.append(bytes!)
            //            memcpy(d.mutableBytes,m.bytes , m.count)
            //            memcpy(d.mutableBytes+md5Len, bytes?.bytes, (bytes?.count)!)
            let md5 = d.md5x
            m.append(md5)
            if m.count >= keyLen {
                break;
            }
        }
        
        m.count = keyLen
        
        return m
    }
    func crypto_stream_xor_ic(_ cd:inout Data, md: Data,mlen: UInt64, nd:Data, ic:UInt64, kd:Data)  ->Int32{
        
        
        var ret:Int32 = -1
        
        var outptr:UnsafeMutablePointer<UInt8>?
        
        
        _ = cd.withUnsafeMutableBytes( { (ptr:UnsafeMutablePointer<UInt8>) in
            outptr = ptr
        })
        
        var inptr:UnsafePointer<UInt8>?
        
        _ = md.withUnsafeBytes({ (ptr:UnsafePointer<UInt8>)  in
            inptr = ptr
        })
        
        var kptr:UnsafePointer<UInt8>?
        _ = kd.withUnsafeBytes({ (ptr:UnsafePointer<UInt8>)  in
            kptr = ptr
        })
        
        var nptr:UnsafePointer<UInt8>?
        _ = nd.withUnsafeBytes({ (ptr:UnsafePointer<UInt8>)  in
            nptr = ptr
        })
        switch send_ctx.m{
        case .SALSA20:
            
            ret = crypto_stream_salsa20_xor_ic(outptr!, inptr, mlen, nptr!, ic, kptr!)
            
        case .CHACHA20:
            
            ret =  crypto_stream_chacha20_xor_ic(outptr!, inptr, mlen, nptr!, ic, kptr!)
        case .CHACHA20IETF:
            
            ret =  crypto_stream_chacha20_ietf_xor_ic(outptr!, inptr!, mlen, nptr!, UInt32(ic), kptr!)
        default:
            break
        }
        //print("sodium ret \(ret)")
//        if let o = outptr {
//            cd = Data.init(buffer: o)
//        }
        
        return ret
    }
    func genData(encrypt_bytes:Data) ->Data?{
        
        //Empty IV: initialization vector
        
        //self.iv = ivt
        let cipher:Data?
        if recv_ctx == nil {
            
            let iv_len = send_ctx.m.iv_size
            
            if encrypt_bytes.count + ivBuffer.count < iv_len {
                ivBuffer.append(encrypt_bytes)
                AxLogger.log("recv iv not finished,waiting recv iv",level: .Warning)
                return nil
            }else {
                let iv_need_len = iv_len - ivBuffer.count
                
                
                ivBuffer.append(encrypt_bytes.subdata(in: Range(0 ..< iv_need_len)))
                recvCTX(iv: ivBuffer) //
                //ivBuffer
                cipher = encrypt_bytes.subdata(in: Range(iv_need_len ..< encrypt_bytes.count ))
            }
            
        }else {
            cipher = encrypt_bytes
        }
        
        return cipher as Data?
        
    }
    public func decrypt(encrypt_bytes:Data) ->Data?{
        if (  encrypt_bytes.count == 0 ) {
            
            return nil;
            
        }
        if recv_ctx == nil && encrypt_bytes.count < send_ctx.m.iv_size {
            
            AxLogger.log("socket read less iv_len",level: .Error)
        }
        //leaks
        if let left = genData(encrypt_bytes: encrypt_bytes) {
            
            // Alloc Data Out
            guard let  ctx =  recv_ctx else {
                //print("ctx error")
                AxLogger.log("recv_ctx not init ",level: .Error)
                return nil }
            
            if ctx.m.rawValue >= CryptoMethod.SALSA20.rawValue {
                
                let padding = ctx.counter % SODIUM_BLOCK_SIZE;
                var cipher = Data.init(count:  left.count + Int(padding))
                
                //cipher.length += encrypt_bytes.length
                //            brealloc(cipher, iv_len + (padding + cipher->len) * 2, capacity);
                var  plain:Data
                if padding != 0 {
                    plain = Data.init(count: Int(padding))
                    plain.append(left)
                  
                }else {
                    plain = Data.init()
                    plain.append(left)
                }
                
                _ = crypto_stream_xor_ic(&cipher,
                                         md: plain,
                                         mlen: UInt64(plain.count),
                                         nd: ctx.IV,
                                         ic: ctx.counter / SODIUM_BLOCK_SIZE,
                                         kd: ramdonKey!)
                
                ctx.counter += UInt64(left.count)
                let result = cipher.subdata(in: Range(Int(padding) ..< cipher.count))
                return result
                
            }else {
                var cipherDataDecrypt:Data = Data(count: left.count)
                
                //alloc number of bytes written to data Out
                var  outLengthDecrypt:NSInteger = 0
                
                var ptr :UnsafeMutableRawPointer?
                
                _ = cipherDataDecrypt.withUnsafeMutableBytes {mutableBytes in
                    ptr = UnsafeMutableRawPointer.init(mutableBytes)
                }
                
                //Update Cryptor
                let updateDecrypt:CCCryptorStatus = CCCryptorUpdate(ctx.ctx,
                                                                    (left as NSData).bytes, //const void *dataIn,
                    left.count,  //size_t dataInLength,
                    ptr, //void *dataOut,
                    cipherDataDecrypt.count, // size_t dataOutAvailable,
                    &outLengthDecrypt); // size_t *dataOutMoved)
                
                if (updateDecrypt == CCCryptorStatus(0))
                {
                    //Cut Data Out with nedded length
                    cipherDataDecrypt.count = outLengthDecrypt;
                    
                    
                    var ptr :UnsafeMutableRawPointer?
                    
                    _ = cipherDataDecrypt.withUnsafeMutableBytes {mutableBytes in
                        ptr = UnsafeMutableRawPointer.init(mutableBytes)
                    }
                    
                    let final:CCCryptorStatus = CCCryptorFinal(ctx.ctx, //CCCryptorRef cryptorRef,
                        ptr, //void *dataOut,
                        cipherDataDecrypt.count, // size_t dataOutAvailable,
                        &outLengthDecrypt); // size_t *dataOutMoved)
                    
                    if (final != CCCryptorStatus( 0))
                    {
                        AxLogger.log("decrypt CCCryptorFinal failure",level: .Error)
                       
                    }
                    
                    return cipherDataDecrypt as Data ;//cipherFinalDecrypt;
                }else {
                    AxLogger.log("decrypt CCCryptorUpdate failure",level: .Error)
                }
                
            }
            
        }else {
            
            AxLogger.log("decrypt no Data",level: .Warning)
        }
        
        
        
        return nil
    }
    static func getSecureRandom(bytesCount:Int) ->Data {
        // Swift
        //import Security
        
        //let bytesCount = 4 // number of bytes
        //var randomNum: UInt32 = 0 // variable for random unsigned 32 bit integer
        var randomBytes = [UInt8](repeating: 0, count: bytesCount) // array to hold randoms bytes
        
        // Gen random bytes
        _ = SecRandomCopyBytes(kSecRandomDefault, bytesCount, &randomBytes)
        
        // Turn bytes into data and pass data bytes into int
    
        return Data(bytes: randomBytes, count: bytesCount) //getBytes(&randomNum, length: bytesCount)
    }
    //    func padding(d:NSData) ->NSData{
    //        let l = d.length % block_size
    //        if l != 0 {
    //            let x = NSMutableData.init(data: d)
    //            x.length += l
    //            return x
    //        }else {
    //            return d
    //        }
    //    }
    public func encrypt(encrypt_bytes:Data) ->Data?{
        
        
        let ctx = send_ctx
        //Update Cryptor
        if ctx.m.rawValue >= CryptoMethod.SALSA20.rawValue {
            //debugLog("111 encrypt")
            let padding = ctx.counter % SODIUM_BLOCK_SIZE;
            var cipher = Data.init(count:  1*(encrypt_bytes.count + Int(padding)))
            
            var  plain:Data
            if padding != 0 {
                plain = Data(count: Int(padding))
                plain.append(encrypt_bytes)
               
            }else {
                plain = Data()
                plain.append(encrypt_bytes)
            }
            var riv =  ctx.IV
            
            riv.count = 32
            
            _ =  crypto_stream_xor_ic(&cipher ,
                                      md: plain,
                                      mlen: UInt64(plain.count),
                                      nd: riv,//ctx.IV,
                ic: ctx.counter / SODIUM_BLOCK_SIZE,
                kd: ramdonKey!)
            var result:Data
            if ctx.counter == 0 {
                
                result =  ctx.IV
                result.count = m.iv_size
            }else {
                result = Data()
            }
            
            ctx.counter += UInt64(encrypt_bytes.count)
            
            //let end = Int(padding)+
            result.append(cipher.subdata(in: Range(Int(padding) ..< cipher.count
            )))
            //debugLog("000 encrypt")
            return result
        }else {
            var  outLength:NSInteger = 0 ;
            // Alloc Data Out
            
            var cipherData:Data = Data.init(count: encrypt_bytes.count)
            
            var ptr :UnsafeMutableRawPointer?
            
            _ = cipherData.withUnsafeMutableBytes {mutableBytes in
                ptr = UnsafeMutableRawPointer.init(mutableBytes)
            }
            
            let  update:CCCryptorStatus = CCCryptorUpdate(ctx.ctx,
                                                          (encrypt_bytes as NSData).bytes,
                                                          encrypt_bytes.count,
                                                          ptr,
                                                          cipherData.count,
                                                          &outLength);
            if (update == CCCryptorStatus(0))
            {
                //Cut Data Out with nedded length
                cipherData.count = outLength;
                
                //Final Cryptor
                let final:CCCryptorStatus = CCCryptorFinal(ctx.ctx, //CCCryptorRef cryptorRef,
                    ptr, //void *dataOut,
                    cipherData.count, // size_t dataOutAvailable,
                    &outLength); // size_t *dataOutMoved)
                
                if (final == CCCryptorStatus(0))
                {
                    if ctx.counter == 0 {
                        ctx.counter += 1
                        var d:Data = Data()
                        d.append(ctx.IV);
                        
                        d.append(cipherData)
                        return d
                    }else {
                        return cipherData
                    }
                    
                    
                }else {
                    AxLogger.log("CCCryptorFinal error \(final)",level:.Error)
                }
                
                //AxLogger.log("cipher length:\(d.length % 16)")
                
                
            }else {
                AxLogger.log("CCCryptorUpdate error \(update)",level:.Error)
            }
            
        }
        
        return nil
    }
    static func encryptErrorReason(r:Int32) {
        
        var message:String = "undefine error"
        switch  r{
        case -4300:
            message = "kCCParamError"
        case -4301:
            message = "kCCBufferTooSmall"
        case -4302:
            message = "kCCMemoryFailure"
        case -4303:
            message = "kCCAlignmentError"
        case -4304:
            message = "kCCDecodeError"
        case -4305:
            message = "kCCUnimplemented"
        case -4306:
            message = "kCCOverflow"
        case -4307:
            message = "kCCRNGFailure"
        default:
            break
        }
        AxLogger.log("\(message)",level: .Debug)
    }
    func ss_onetimeauth(buffer:Data) ->Data {
        
        var keyData = Data()
        keyData.append( send_ctx.IV)
        
        
        keyData.append(ramdonKey!)
        let hash = buffer.hmacsha1(keyData: keyData)
        AxLogger.log("ss_onetimeauth \(hash)",level: .Debug)
        return hash
    }
    func ss_gen_hash(buffer:Data,counter:Int32) ->Data {
        
        let blen = buffer.count
        let chunk_len:UInt16 = UInt16(blen).bigEndian
        let c =  UInt32(counter).bigEndian
        
        let keyData = SFData()
        keyData.append(send_ctx.IV)
        keyData.append(c)
        let hash = buffer.hmacsha1(keyData: keyData.data)
        let result = SFData()
        result.append(chunk_len)
        
        result.append(hash)
        
        return result.data
    }
    
}
