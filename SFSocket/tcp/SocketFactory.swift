//
//  SocketFactory.swift
//  SFSocket
//
//  Created by 孔祥波 on 16/03/2017.
//  Copyright © 2017 Kong XiangBo. All rights reserved.
//

import Foundation
import AxLogger
public class SocketFactory {
    //proxy chain suport flag
    public var proxy:SFProxy? //first proxy, support proxy chain
    
    public static var shared = SocketFactory()
    //var proxyChain:Bool = false
    public func socketFromProxy(_ p: SFProxy?,policy:SFPolicy,targetHost:String,Port:UInt16) ->NWTCPSocket? {
        
        if policy == .Direct {
            //基本上网需求
            guard let chain = proxy else {
                return DirectConnector.connectorWithHost(targetHost: targetHost, targetPort: Int(Port))
            }
            switch chain.type {
            case .HTTP,.HTTPS:
                let connector = HTTPProxyConnector.connectorWithSelectorPolicy(targetHostname: targetHost, targetPort: Port, p: chain)
                let data = SFHTTPRequestHeader.buildCONNECTHead(targetHost, port: String(Port),proxy: chain)
                let message = String.init(format:"http proxy %@ %d", targetHost,Port )
                AxLogger.log(message,level: .Trace)
                //let c = connector as! HTTPProxyConnector
                connector.reqHeader = SFHTTPRequestHeader(data: data)
                if connector.reqHeader == nil {
                    fatalError("HTTP Request Header nil")
                }
                return connector
            case .SOCKS5:
                return  Socks5Connector.connectorWithSelectorPolicy(policy, targetHostname: targetHost, targetPort: Port, p: chain)
                
            default:
                return nil
            }
        }else {
            if let chain = proxy {
                guard let p = p else { return nil}
                guard let adapter = Adapter.createAdapter(p, host: targetHost, port: Port) else  {
                    return nil
                }
                switch chain.type {
                case .HTTP:
                    let connector = CHTTPProxConnector.create(targetHostname: adapter.targetHost, targetPort: adapter.targetPort, p: chain,adapter:adapter)
                    let data = SFHTTPRequestHeader.buildCONNECTHead(adapter.targetHost, port: String(adapter.targetPort),proxy: chain)
                    let message = String.init(format:"http proxy %@ %d", adapter.targetPort,adapter.targetPort )
                    AxLogger.log(message,level: .Trace)
                    //let c = connector as! HTTPProxyConnector
                    connector.reqHeader = SFHTTPRequestHeader(data: data)
                    if connector.reqHeader == nil {
                        fatalError("HTTP Request Header nil")
                    }
                    
                    return connector
                case .SOCKS5:
                    return  CSocks5Connector.create(policy, targetHostname: adapter.targetHost, targetPort: adapter.targetPort, p: chain,adapter: adapter)
                default:
                    return nil
                }
                
                
                
            }else {
                guard let p = p else { return nil}
                let message = String.init(format:"proxy server %@:%@", p.serverAddress,p.serverPort)
                AxLogger.log(message,level: .Trace)
                switch p.type {
                case .HTTP,.HTTPS:
                    let connector = HTTPProxyConnector.connectorWithSelectorPolicy(targetHostname: targetHost, targetPort: Port, p: p)
                    let data = SFHTTPRequestHeader.buildCONNECTHead(targetHost, port: String(Port),proxy: p)
                    let message = String.init(format:"http proxy %@ %d", targetHost,Port )
                    AxLogger.log(message,level: .Trace)
                    //let c = connector as! HTTPProxyConnector
                    connector.reqHeader = SFHTTPRequestHeader(data: data)
                    if connector.reqHeader == nil {
                        fatalError("HTTP Request Header nil")
                    }
                    return connector
                case .SS:
                    return   TCPSSConnector.connectorWithSelectorPolicy(policy, targetHostname: targetHost, targetPort: Port, p: p)
                case .SS3:
                    return   TCPSS3Connector.connectorWithSelectorPolicy(policy, targetHostname: targetHost, targetPort: Port, p: p)
                    
                    
                case .SOCKS5:
                    return  Socks5Connector.connectorWithSelectorPolicy(policy, targetHostname: targetHost, targetPort: Port, p: p)
                    
                default:
                    
                    return nil
                }
            }
            
        }
        
       
    }
}
