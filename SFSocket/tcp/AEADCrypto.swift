//
//  AEAD.swift
//  SFSocket
//
//  Created by 孔祥波 on 16/03/2017.
//  Copyright © 2017 Kong XiangBo. All rights reserved.
//

import Foundation
import CommonCrypto
import AxLogger
import Sodium
//需要对源代码的stream 部分兼容
typealias fCCCryptorGCMAddIV = @convention(c) (CCCryptorRef, UnsafeRawPointer,CInt) -> CInt
typealias fCCCryptorGCMaddAAD = @convention(c) (CCCryptorRef, UnsafeRawPointer,CInt) -> CInt
typealias fgcm_update = @convention(c) (CCCryptorRef, UnsafeRawPointer,CInt,UnsafeMutableRawPointer) -> CInt
typealias fCCCryptorGCMEncrypt = @convention(c) (CCCryptorRef, UnsafeRawPointer,CInt,UnsafeMutableRawPointer) -> CInt
typealias fCCCryptorGCMDecrypt = @convention(c) (CCCryptorRef, UnsafeRawPointer,CInt,UnsafeMutableRawPointer) -> CInt
typealias fCCCryptorGCMFinal = @convention(c) (CCCryptorRef, UnsafeMutableRawPointer,UnsafeMutablePointer<Int>) -> CInt
class loadSys {
    static var load = false
    static var CCCryptorGCMAddIV:fCCCryptorGCMAddIV!
    static var CCCryptorGCMaddAAD:fCCCryptorGCMaddAAD!
    static var gcm_update:fgcm_update!
    static var gcmen_update:fCCCryptorGCMEncrypt!
    static var gcmde_update:fCCCryptorGCMDecrypt!
    static var CCCryptorGCMFinal:fCCCryptorGCMFinal!
    static func loadFuncs() {
        if !load{
            let d = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOW);
            
            let x  = dlsym(d, "CCCryptorGCMAddIV");
            CCCryptorGCMAddIV = unsafeBitCast(x, to: fCCCryptorGCMAddIV.self)
            
            
            let y  = dlsym(d, "CCCryptorGCMaddAAD");
            CCCryptorGCMaddAAD = unsafeBitCast(y, to: fCCCryptorGCMaddAAD.self)
            let z  = dlsym(d, "gcm_update");
            let err = dlerror()
            //let xx = String.init(cString: err!, encoding: .utf8)
            gcm_update = unsafeBitCast(z, to: fgcm_update.self)
            
            let yy  = dlsym(d, "CCCryptorGCMEncrypt");
            gcmen_update = unsafeBitCast(yy, to: fCCCryptorGCMEncrypt.self)
            
            let zz  = dlsym(d, "CCCryptorGCMDecrypt");
            
            gcmde_update = unsafeBitCast(zz, to: fCCCryptorGCMDecrypt.self)
            
            
            
            let w  = dlsym(d, "CCCryptorGCMFinal");
            CCCryptorGCMFinal = unsafeBitCast(w, to: fCCCryptorGCMFinal.self)
            load = true
        }
    }
    static func addIV(ctx:CCCryptorRef,iv:Data) {
        let c = (iv as NSData).bytes
        let r = CCCryptorGCMAddIV(ctx,c,CInt(iv.count))
        AxLogger.log("CCCryptorGCMAddIV \(r)", level: .Debug)
    }
    static func addAAD(ctx:CCCryptorRef,aData:Data){
        let c = (aData as NSData).bytes
        let r = CCCryptorGCMaddAAD(ctx,c,CInt(aData.count))
        AxLogger.log("CCCryptorGCMaddAAD \(r)", level: .Debug)
    }
    static func  update(ctx:CCCryptorRef,data:Data,dataOut:UnsafeMutableRawPointer,tagOut:UnsafeMutableRawPointer,tagLength:UnsafeMutablePointer<Int>,en:Bool){
        let c = (data as NSData).bytes
        if en {
            let r =  gcmen_update(ctx,c,CInt(data.count),dataOut)
            AxLogger.log("gcm_update \(r)", level: .Debug)
            print("-- \(r)")
        }else {
            let r =  gcmde_update(ctx,c,CInt(data.count),dataOut)
            AxLogger.log("gcm_update \(r)", level: .Debug)
            print("-- \(r)")
        }
        
        
        
        
        let rr = CCCryptorGCMFinal(ctx,tagOut,tagLength)
        AxLogger.log("CCCryptorGCMaddAAD \(rr)", level: .Debug)
    }
}
public class AEAD {
    static func crypto_derive_key(_ pass: String) -> Data {
        //AEAE,key max 32 ,two time md5
        let bytes = pass.data(using: .utf8, allowLossyConversion: false)!
        // memcpy((m?.mutableBytes)!, bytes.bytes , password.characters.count)
        let md5 = bytes.md5x
        var res = Data()
        res.append(md5)
        let context = UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1)
        var digest = Array<UInt8>(repeating:0, count:Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5_Init(context)
        let byts = (md5 as NSData).bytes
        CC_MD5_Update(context, byts, 16)
        CC_MD5_Update(context, pass, CC_LONG(pass.lengthOfBytes(using: String.Encoding.utf8)))
        CC_MD5_Final(&digest, context)
        context.deallocate(capacity: 1)
        
        for byte in digest {
            res.append(byte)
        }
        
        return res
    }
    
}
let  CHUNK_SIZE_LEN = 2
let CHUNK_SIZE_MASK = 0x3FFF
//
public class aead_ctx {
    var key:Data?
    var key_bitlen:Int {
        get {
            if m.rawValue >= CryptoMethod.CHACHA20IETF305.rawValue{
                return m.key_size * 8
                
            }else {
                return m.key_size
            }
        }
    }
    var iv_size:Int {//for new protocol
        get{
            if m.rawValue >= CryptoMethod.CHACHA20IETF305.rawValue{
                return m.iv_size
                
            }else {
                return m.iv_size
            }
        }
    }
    var nonce_len:Int {
        get {
            return m.nonce_len
        }
    }
    var tag_len:Int{
        get {
            return m.tag_len
        }
    }
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
    //    init(){
    //        IV = Data()
    //        ctx = nil
    //    }
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
            
            if method == .AES128GCM || method == .AES192GCM || method == .AES256GCM {
                loadSys.loadFuncs()
            }
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
//key_bitlen = supported_aead_ciphers_key_size*8
// iv_size = supported_aead_ciphers_nonce_size
public class AEADCrypto {
    
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
    
    func aead_init(pass:String ,key:String) {
        
    }
    func aead_key_init(pass:String ,key:String){
        
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
    public init(password:String,key:String,method:String) {
        
        m = CryptoMethod.init(cipher: method)
        //var keyData:Data
        if key.isEmpty {
            ramdonKey = AEAD.crypto_derive_key(password)
        }else {
            ramdonKey = AEAD.crypto_derive_key(key)
        }
        //print("method:\(m.description)")
        //ramdonKey  = SSEncrypt.evpBytesToKey(password: password,keyLen: m.key_size)
        
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
    
    
    
}
extension AEADCrypto{
    public func testGCM() {
        var taglen:Int = 16;
        let ctx = self.send_ctx.ctx!
        loadSys.addIV(ctx: ctx, iv: "1234567890qwerty".data(using: .utf8)!)
        loadSys.addAAD(ctx: ctx, aData: "12345678".data(using: .utf8)!)
        var data = Data.init(count: 16)
        var data11 = Data.init(count: 16)
        var p:UnsafeMutableRawPointer?
        _ = data.withUnsafeMutableBytes { mutableBytes in
            p = UnsafeMutableRawPointer.init(mutableBytes)
        }
        var tagout:UnsafeMutableRawPointer?
        _ = data11.withUnsafeMutableBytes {mutableBytes in
            tagout = UnsafeMutableRawPointer.init(mutableBytes)
        }
        loadSys.update(ctx: ctx, data: "1234567890qwerty".data(using: .utf8)!, dataOut: p!, tagOut: tagout!, tagLength: &taglen, en: true)
        
        var data2 = Data.init(count: 16)
        _ = Data.init(count: 16)
        var p2:UnsafeMutableRawPointer?
        _ = data2.withUnsafeMutableBytes { mutableBytes in
            p2 = UnsafeMutableRawPointer.init(mutableBytes)
        }
        
        self.recv_ctx = enc_ctx.init(key: ramdonKey!, iv: self.send_ctx.IV, encrypt: false,method:m)
        loadSys.addIV(ctx: self.recv_ctx.ctx!, iv: "1234567890qwerty".data(using: .utf8)!)
        loadSys.addAAD(ctx: self.recv_ctx.ctx!, aData: "12345678".data(using: .utf8)!)
        loadSys.update(ctx: self.recv_ctx.ctx!, data: data, dataOut: p2!, tagOut: tagout!, tagLength: &taglen, en: false)
        print("\(data2 as NSData)")
        print(String.init(data: data2, encoding: .utf8)!)
        
        let key = AEAD.crypto_derive_key("12345678")
        print(key as NSData)
        
    }
    func crypto_hkdf(salt:Data,salt_len:Int,ikm:Data,ikm_len:Int,info:Data,info_len:Int, okm:inout Data,okm_len:Int) ->Int{
        //sha1
        var prk:Data = Data.init(count:Int(CC_SHA1_DIGEST_LENGTH) )
        
        var dataptr:UnsafeMutablePointer<Any>?
        _ = prk.withUnsafeMutableBytes { (ptr:UnsafeMutablePointer)  in
            dataptr = ptr
        }
        
        var saltptr:UnsafeRawPointer?
        var salt_len2 = salt_len
        if salt.isEmpty {
            let hash_len = Int(CC_SHA1_DIGEST_LENGTH)
            var null = 0x00
            let saltData:Data = Data.init(bytes: &null, count: hash_len)
            salt_len2 = Int(CC_SHA1_DIGEST_LENGTH)
            _ = saltData.withUnsafeRawPointer { (ptr:UnsafeRawPointer)  in
                saltptr = ptr
            }
        }else {
            _ = salt.withUnsafeRawPointer { (ptr:UnsafeRawPointer)  in
                saltptr = ptr
            }
        }
        
        
        
        
        var ikmptr:UnsafeRawPointer?
        _ = ikm.withUnsafeRawPointer { (ptr:UnsafeRawPointer)  in
            ikmptr = ptr
        }
        //mbedtls_md_hmac
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), saltptr, salt_len2, ikmptr, ikm_len, dataptr)
       // CCHmac(<#T##algorithm: CCHmacAlgorithm##CCHmacAlgorithm#>, <#T##key: UnsafeRawPointer!##UnsafeRawPointer!#>, <#T##keyLength: Int##Int#>, <#T##data: UnsafeRawPointer!##UnsafeRawPointer!#>, <#T##dataLength: Int##Int#>, <#T##macOut: UnsafeMutableRawPointer!##UnsafeMutableRawPointer!#>)
        //crypto_hkdf_expand
        
        
        
        let hash_len:Int = Int(CC_SHA1_DIGEST_LENGTH)
        var iterations:Int = okm_len / hash_len
        if okm_len % hash_len != 0 {
            iterations += 1
        }
        var mixin:Data = Data()
        //var results:Data = Data()
        
        for i in 1...iterations{
            let ctx:UnsafeMutablePointer<CCHmacContext> = UnsafeMutablePointer.allocate(capacity: 1)
            var mixinptr:UnsafeRawPointer?
            CCHmacInit(ctx, CCHmacAlgorithm(kCCHmacAlgSHA1), dataptr, Int(CC_SHA1_DIGEST_LENGTH))
            _ = mixin.withUnsafeRawPointer { (ptr:UnsafeRawPointer)  in
                mixinptr = ptr
            }
            var infoptr:UnsafeRawPointer?
            _ = info.withUnsafeRawPointer { (ptr:UnsafeRawPointer)  in
                infoptr = ptr
            }
            if !info.isEmpty {
                 CCHmacUpdate(ctx, infoptr, info_len);
            }
            var c:UInt8 = UInt8(i + 1)
            CCHmacUpdate(ctx,&c,1)
            CCHmacUpdate(ctx, mixinptr, mixin.count)
            
            var null = 0x00
            var T:Data = Data.init(bytes: &null, count: Int(CC_SHA1_DIGEST_LENGTH))
            
            var tptr:UnsafeMutablePointer<Any>?
            _ = T.withUnsafeMutableBytes { (ptr:UnsafeMutablePointer)  in
               tptr = ptr
            }
            
            CCHmacFinal(ctx, tptr)
            //CCHmacFinal(<#T##ctx: UnsafeMutablePointer<CCHmacContext>!##UnsafeMutablePointer<CCHmacContext>!#>, <#T##macOut: UnsafeMutableRawPointer!##UnsafeMutableRawPointer!#>)
            //results.append(T)
            okm.append(T)
            mixin = T
        }
        return 0
    }
}

//#import <CommonCrypto/CommonCrypto.h>
//// ...
//
//NSData * HKDF_SHA256(NSData *seed, NSData *info, NSData *salt, int outputSize) {
//    char prk[CC_SHA256_DIGEST_LENGTH] = {0};
//    CCHmac(kCCHmacAlgSHA256, [salt bytes], [salt length], [seed bytes], [seed length], prk);
//    
//    int             iterations = (int)ceil((double)outputSize/(double)CC_SHA256_DIGEST_LENGTH);
//    NSData          *mixin = [NSData data];
//    NSMutableData   *results = [NSMutableData data];
//    
//    for (int i=0; i<iterations; i++) {
//        CCHmacContext ctx;
//        CCHmacInit(&ctx, kCCHmacAlgSHA256, prk, CC_SHA256_DIGEST_LENGTH);
//        CCHmacUpdate(&ctx, [mixin bytes], [mixin length]);
//        if (info != nil) {
//            CCHmacUpdate(&ctx, [info bytes], [info length]);
//        }
//        
//        unsigned char c = i+1;
//        CCHmacUpdate(&ctx, &c, 1);
//        
//        unsigned char T[CC_SHA256_DIGEST_LENGTH];
//        memset(T, 0, CC_SHA256_DIGEST_LENGTH);
//        CCHmacFinal(&ctx, T);
//        NSData *stepResult = [NSData dataWithBytes:T length:sizeof(T)];
//        [results appendData:stepResult];
//        mixin = [stepResult copy];
//    }
//    
//    return [NSData dataWithData:results];
//}
//line 5 should be char prk[CC_SHA256_DIGEST_LENGTH] and line 6 CCHmac(kCCHmacAlgSHA256... maybe a typo
