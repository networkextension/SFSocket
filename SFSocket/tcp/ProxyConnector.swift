//
//  ProxyConnector.swift
//  Surf
//
//  Created by yarshure on 16/1/7.
//  Copyright © 2016年 yarshure. All rights reserved.
//

import Foundation
import AxLogger
import NetworkExtension
import Security
public class ProxyConnector: NWTCPSocket,NWTCPConnectionAuthenticationDelegate {
    var proxy:SFProxy
    var tlsSupport:Bool = false
    var targetHost:String = ""
    var targetPort:UInt16 = 0
    var tlsEvaluate:Bool = false
    #if os(iOS)
    let acceptableCipherSuites:Set<NSNumber> = [
        
        NSNumber(value: TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256),
        NSNumber(value: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
        NSNumber(value: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        NSNumber(value: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
        NSNumber(value: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
        NSNumber(value: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        NSNumber(value: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
        NSNumber(value: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        NSNumber(value: TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384),
        NSNumber(value: TLS_RSA_WITH_AES_256_GCM_SHA384),
        NSNumber(value: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384),
        NSNumber(value: TLS_DH_RSA_WITH_AES_256_GCM_SHA384)
            
        
        
        
//    public var TLS_RSA_WITH_AES_256_GCM_SHA384: SSLCipherSuite { get }
//    public var TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: SSLCipherSuite { get }
//    public var TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: SSLCipherSuite { get }
//    public var TLS_DH_RSA_WITH_AES_128_GCM_SHA256: SSLCipherSuite { get }
//    public var TLS_DH_RSA_WITH_AES_256_GCM_SHA384: SSLCipherSuite { get }
        
        
    ]
    #else
    let acceptableCipherSuites = [
    NSNumber(value: TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256),
    NSNumber(value: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
    NSNumber(value: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    NSNumber(value: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
    NSNumber(value: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
    NSNumber(value: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    NSNumber(value: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    
    ]
    #endif
    var pFrontAddress:String = ""
    var pFrontPort:UInt16 = 0
    init(p:SFProxy) {
        proxy = p
        
        super.init()
        
        //cIDFunc()
    }
    override public func start() {
        guard let port = Int(proxy.serverPort) else {
            return
        }
        if proxy.type == .SS {
            try! self.connectTo(proxy.serverAddress, port: port, enableTLS: false, tlsSettings: nil)
        }else {
            try! self.connectTo(proxy.serverAddress, port: port, enableTLS: proxy.tlsEnable, tlsSettings: nil)
        }
        
    }
    override public func connectTo(_ host: String, port: Int, enableTLS: Bool, tlsSettings: [NSObject : AnyObject]?) throws {
       
        
        if enableTLS {
             let endpoint = NWHostEndpoint(hostname: host, port: "\(port)")
            let tlsParameters = NWTLSParameters()
            if let tlsSettings = tlsSettings as? [String: AnyObject] {
                tlsParameters.setValuesForKeys(tlsSettings)
            }else {
                tlsParameters.sslCipherSuites = acceptableCipherSuites 

            }
            let v = SSLProtocol.tlsProtocol12
            tlsParameters.minimumSSLProtocolVersion = Int(v.rawValue)
            guard let c = RawSocketFactory.TunnelProvider?.createTCPConnection(to: endpoint, enableTLS: enableTLS, tlsParameters: tlsParameters, delegate: nil) else {
                // This should only happen when the extension is already stoped and `RawSocketFactory.TunnelProvider` is set to `nil`.
                return
            }
            
            connection = c
            connection!.addObserver(self, forKeyPath: "state", options: [.initial, .new], context: nil)
        }else {
            do {
                try super.connectTo(host, port: port, enableTLS: false, tlsSettings: tlsSettings)
            }catch let e as NSError{
                throw e
            }
            
        }
        

    }
    
    @nonobjc public func shouldEvaluateTrustForConnection(connection: NWTCPConnection) -> Bool{
        return true
    }
    
    @nonobjc public func evaluateTrustForConnection(connection: NWTCPConnection, peerCertificateChain: [AnyObject], completionHandler completion: @escaping (SecTrust) -> Void){
        let remoteAddress = connection.remoteAddress as? NWHostEndpoint
        AxLogger.log("debug :\(remoteAddress?.hostname)", level: .Debug)
        let myPolicy = SecPolicyCreateSSL(true, nil)//proxy.serverAddress
        
        var possibleTrust: SecTrust?
        
        let x = SecTrustCreateWithCertificates(peerCertificateChain.first!, myPolicy,
                                       &possibleTrust)
        if x != 0 {
             AxLogger.log("debug :\(remoteAddress?.hostname) \(x)", level: .Debug)
        }
        if let trust = possibleTrust {
            //let's do test by ourself first
            
             var trustResult : SecTrustResultType = .invalid
             let r = SecTrustEvaluate(trust, &trustResult)
            if r != 0{
                AxLogger.log("debug :\(remoteAddress?.hostname) error code:\(r)", level: .Debug)
            }
            if trustResult == .proceed {
                AxLogger.log("debug :\(remoteAddress?.hostname) Proceed", level: .Debug)
            }else {
                AxLogger.log("debug :\(remoteAddress?.hostname) Proceed error", level: .Debug)
            }
             //print(trustResult)  // the result is 5, is it
             //kSecTrustResultRecoverableTrustFailure?
             
            completion(trust)
        }else {
             AxLogger.log("debug :\(remoteAddress?.hostname) error", level: .Debug)
        }
    }
 
//    override public func observeValueForKeyPath(keyPath: String?, ofObject object: AnyObject?, change: [String : AnyObject]?, context: UnsafeMutablePointer<Void>) {
//        let x = connection.endpoint as! NWHostEndpoint
//        if  keyPath == "state" {
//            
//            
//            var stateString = ""
//            switch connection.state {
//            case .Connected:
//                stateString = "Connected"
//                if proxy.tlsEnable == true && proxy.type != .SS {
//                    AxLogger.log("\(cIDString) host:\(x) tls handshake passed", level: .Debug)
//                }
//                    queueCall {
//                        self.socketConnectd()
//                    }
//            
//            case .Disconnected:
//                stateString =  "Disconnected"
//                cancel()
//            case .Cancelled:
//                stateString =  "Cancelled"
//                queueCall {
//                    let delegate = self.delegate
//                    self.delegate = nil
//                    delegate?.didDisconnect(self)
//                    
//                }
//            case .Connecting:
//                stateString = "Connecting"
//            case .Waiting:
//                stateString =  "Waiting"
//            case .Invalid:
//                stateString = "Invalid"
//                
//            }
//            AxLogger.log("\(cIDString) host:\(x) " + stateString, level: .Debug)
//        }
// 
//    }
}
