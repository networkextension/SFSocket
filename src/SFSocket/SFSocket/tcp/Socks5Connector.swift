//
//  ProxyConnectorSOCKS5.swift
//  SimpleTunnel
//
//  Created by yarshure on 15/11/11.
//  Copyright © 2015年 Apple Inc. All rights reserved.
//

import Foundation
import CocoaAsyncSocket
import AxLogger
public enum SFSocks5Stage:Int8,CustomStringConvertible{
    case Auth = 0
    case AuthSend = 2
    case Bind = 1
    case Connected = 5
    public var description: String {
        switch self {
        case .Auth :return "Auth"
        case .AuthSend: return "AuthSend"
        case .Bind: return "Bind"
        case .Connected: return "Connected"
        }
    }
}

//
//
// 050000010000000001BB

public class Socks5Connector:ProxyConnector{
    var host:String?
    var port:UInt16 = 0
    var stage:SFSocks5Stage = .Auth
    var recvBuffer:Data?
    static var  ReadTag:Int = -3000
    static func connectorWithSelectorPolicy(selectorPolicy:SFPolicy ,targetHostname hostname:String, targetPort port:UInt16,p:SFProxy) ->Socks5Connector{
        let c:Socks5Connector = Socks5Connector(p: p)
        //c.manager = man
        
        c.targetHost = hostname
        c.targetPort = port
        //c.cIDFunc()
        //c.start()
        return c
    }
    func sendAuth(){
        var buffer = Data() //req 050100
        buffer.append(SOCKS_VERSION)
        
        if proxy.method.isEmpty && proxy.password.isEmpty {
            let authCount:UInt8 = 0x01 //支持认证
            buffer.append(authCount)
            let auth:UInt8 = 0x00
            buffer.append(auth)
        }else {
            let authCount:UInt8 = 0x02 //支持认证
            buffer.append(authCount)
            let auth:UInt8 = 0x00
            buffer.append(auth)
            let authup:UInt8 = 0x02
            buffer.append(authup)

        }
        
       //AxLogger.log("\(cIDString) send  .Auth req \(buffer)",level:.Trace)
        self.writeData(buffer,withTag: Socks5Connector.ReadTag)
    }
    func sendUserAndPassword(){
        var buffer = Data()
        //buffer.write(SOCKS_VERSION)
        let auth:UInt8 = 0x01
        buffer.append(auth) //auth version
        var len:UInt8 = UInt8(proxy.method.characters.count)
        buffer.append(len)
        buffer.append(proxy.method.data(using: .utf8)!)
        len = UInt8(proxy.password.characters.count)
        buffer.append(len)
        buffer.append(proxy.password.data(using: .utf8)!)
        
        self.writeData( buffer, withTag: Socks5Connector.ReadTag)
        
    }
    func sendBind(){
        //req 050100030F6170692E747769747465722E636F6D01BB
        var buffer = SFData() //req 050100
        buffer.append(SOCKS_VERSION)
        let connect:UInt8 = 0x01
        buffer.append(connect)
        
        let reserved:UInt8 = 0x00
        buffer.append(reserved)
        let  request_atyp:SOCKS5HostType = validateIpAddr(candidate: targetHost)
        if  request_atyp == .IPV4{
            //ip
            
            buffer.append(SOCKS_IPV4)
            let i :UInt32 = inet_addr(targetHost.cString(using: .utf8))
            buffer.append(i)
            buffer.append(targetPort.byteSwapped)
        }else if request_atyp == .DOMAIN {
            //domain name
            
            buffer.append(SOCKS_DOMAIN)
            let name_len = targetHost.characters.count
            buffer.append(UInt8(name_len))
            buffer.append(targetHost.data(using: .utf8)!)
            buffer.append(targetPort.byteSwapped)
        }else  if request_atyp == .IPV6 {
            buffer.append(SOCKS_IPV6)
            if let data =  toIPv6Addr(ipString: targetHost) {
                
             
               //AxLogger.log("\(cIDString) convert \(targetHost) to Data:\(data)",level: .Info)
                buffer.append(data)
                //buffer.append(targetPort.byteSwapped)
            }else {
               //AxLogger.log("\(cIDString) convert \(targetHost) to in6_addr error )",level: .Warning)
                return
            }
            
        }
    
       //AxLogger.log("\(cIDString) send  .Bind req \(buffer)",level: .Trace)
        self.writeData(buffer.data, withTag: Socks5Connector.ReadTag)
    }
    public override func socketConnectd(){
         if stage == .Auth {
            sendAuth()
         }else {
           self.delegate?.didConnect(self)
        }
        
    }
    

    override func readCallback(data: Data?, tag: Int) {
        
        if stage == .Auth {
            //ans 0500
            if recvBuffer == nil {
                recvBuffer = Data()
            }
            recvBuffer?.append(data!)
           //AxLogger.log("\(cIDString)  .Auth  respon buf \(recvBuffer)",level: .Trace)
            guard var buffer = recvBuffer else {return }
            let version : UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
            buffer.copyBytes(to: version, count: 1)
            
            let auth : UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
            buffer.copyBytes(to: auth, from: Range(1 ... 1))
            if version.pointee == SOCKS_VERSION {
                
                //buffer
                if auth.pointee == 0x00 {
                    //no auth
                    if buffer.count > 2 {
                        buffer =  buffer.subdata(in: Range(2 ..< buffer.count))
                    }else {
                        recvBuffer = Data()
                    }
                    stage = .Bind
                   //AxLogger.log("\(cIDString) recv .Auth respon and send Bind req",level: .Debug)
                    sendBind()
                }else if auth.pointee == 0x02 {
                    //user/password auth
                    if buffer.count > 2 {
                        buffer =  buffer.subdata(in: Range(2 ..< buffer.count))
                    }else {
                        recvBuffer = Data()
                    }
                    stage = .AuthSend
                    sendUserAndPassword()
                }else if auth.pointee == 0xff {
                   AxLogger.log("socks5 client don't have auth type, need close",level: .Error)
                    self.forceDisconnect()
                } else {
                   AxLogger.log("socks5 auth type:\(auth.pointee) don't support, need close",level: .Error)
                    self.forceDisconnect()
                }
                
            }else {
               AxLogger.log("socks5 client don't recv  respon ver error ver:\(version.pointee)",level: .Debug)
            }
            version.deallocate(capacity: 1)
            auth.deallocate(capacity: 1)
        }else if stage == .AuthSend {
            if recvBuffer == nil {
                recvBuffer = Data()
            }
            recvBuffer?.append(data!)
           //AxLogger.log("\(cIDString)  .AuthSend   respon buf \(recvBuffer)",level: .Debug)
            guard var buffer = recvBuffer else {return }
            let version : UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
            buffer.copyBytes(to: version, count: 1)
            
            let result : UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
            buffer.copyBytes(to: result, count: 1)
            if version.pointee == SOCKS_AUTH_VERSION && result.pointee == SOCKS_AUTH_SUCCESS {
                if buffer.count > 2 {
                    buffer = buffer.subdata(in: Range(2 ..< buffer.count))
                }else {
                    recvBuffer = Data()
                }
               //AxLogger.log("\(cIDString)  .Auth Success and send BIND CMD",level: .Warning)
                sendBind()
                stage = .Bind
            }else {
               AxLogger.log("socks5 client  .Auth failure",level: .Warning)
                self.forceDisconnect()
            }
            version.deallocate(capacity: 1)
            result.deallocate(capacity: 1)
        }else if stage == .Bind {
            if recvBuffer == nil {
                recvBuffer = Data()
            }
            recvBuffer?.append(data!)
           //AxLogger.log("\(cIDString)  .Bind  respon buf \(recvBuffer)",level: .Debug)
            //05000001 c0a80251 c4bf
            guard let buffer = recvBuffer else {return }
            let version : UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
            buffer.copyBytes(to: version, count: 1)
            
            let result : UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
            buffer.copyBytes(to: result, from: Range(1 ... 1))
            if version.pointee == SOCKS_VERSION && result.pointee == 0x00 {
                
                //buffer
                let reserved: UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
                buffer.copyBytes(to: reserved, from: Range(2 ... 2))
                
                let type: UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
                 buffer.copyBytes(to: type, from: Range(3...3))
                if type.pointee == 1 {
                    let ip: UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 4)
                    buffer.copyBytes(to: ip, from: Range(4 ... 8))
                    
                    let port: UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 2)
                    buffer.copyBytes(to: port, from: Range(8 ... 10))
                   //AxLogger.log("\(cIDString) Bind respond \(ip.pointee):\(port.pointee)",level: .Debug)
                    if buffer.count > 10  {
                        recvBuffer = buffer.subdata(in: Range(10 ...  buffer.count))
                    }else {
                        recvBuffer = nil
                    }
                    ip.deallocate(capacity: 4)
                    port.deallocate(capacity: 2)
                }else if type.pointee == SOCKS_DOMAIN  {
                    let length: UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
                    buffer.copyBytes(to: length, from: Range(4 ..< 5))
                    _ = buffer.subdata(in: Range(5 ..< 5 +  Int(length.pointee)))
                    let port: UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.allocate(capacity: 2)
                    buffer.copyBytes(to: port, from: Range(5+Int(length.pointee) ..< 7+Int(length.pointee)))
                   //AxLogger.log("\(cIDString) Bind respond domain name length:\(length.pointee) \(domainname):\(port.pointee)",level: .Debug)
                    let len = 5+Int(length.pointee) + 2
                    if buffer.count >  len {
                        recvBuffer = buffer.subdata(in: Range(len ... buffer.count ))
                    }else {
                        recvBuffer = nil
                    }
                    length.deallocate(capacity: 1)
                    port.deallocate(capacity: 1)
                }else if type.pointee == SOCKS_IPV6 {
                    //AxLogger.log("\(cIDString) Bind respond ipv6 currnetly don't support",level:.Error)
                }
                
                stage = .Connected
               //AxLogger.log("\(cIDString) recv .Bind respon and Connected now \(recvBuffer)",level: .Debug)
                sock5connected()
                reserved.deallocate(capacity: 1)
                type.deallocate(capacity: 1)
            }else {
               //AxLogger.log("\(cIDString) don't recv .Bind respon",level: .Debug)
            }
            version.deallocate(capacity: 1)
            result.deallocate(capacity: 1)
        }else if stage == .Connected {
            queueCall {
                if let buffer = self.recvBuffer  {
                    self.recvBuffer!.append(data!)
                    if let d = self.delegate {
                        //d.connector(self, didReadData: buffer, withTag: Int64(tag))
                        d.didReadData(buffer, withTag: tag, from: self)
                    }
                    
                    self.recvBuffer = nil
                }else {
                    if let d = self.delegate {
                        //d.connector(self, didReadData: data, withTag: Int64(tag))
                        d.didReadData( data!, withTag: tag, from: self)
                    }
                    
                    
                }
            }

            
        }
    }
    func sock5connected(){
        if let d = delegate {
            //d.connectorDidBecomeAvailable(self)
            d.didConnect( self)
        }
        
    }
    
    public override func sendData(data: Data, withTag tag: Int) {
        if writePending {
            return
        }
        writePending = true
        if isConnected == false {
            AxLogger.log("isConnected error", level: .Error)
            return
        }
        self.connection!.write(data) {[weak self] error in
            guard let strong = self else  {return}
            strong.writePending = false
            
            guard error == nil else {
                AxLogger.log("NWTCPSocket got an error when writing data: \(error!.localizedDescription)",level: .Debug)
                strong.forceDisconnect()
                return
            }
            
            strong.queueCall {
                if strong.stage != .Connected {
                    strong.readDataWithTag(Socks5Connector.ReadTag)
                }else {
                    strong.queueCall { autoreleasepool {
                        strong.delegate?.didWriteData(data, withTag: tag, from: strong)
                        }}
                    
                }
                
            }
            strong.checkStatus()
        }
    }

    public override func start() {
        tlsSupport = proxy.tlsEnable
        super.start()
    }

}
