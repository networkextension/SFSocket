//
//  SocketFactory.swift
//  SFSocket
//
//  Created by 孔祥波 on 16/03/2017.
//  Copyright © 2017 Kong XiangBo. All rights reserved.
//

import Foundation
import AxLogger
class SocketFactory {
    
    static func socketFromProxy(_ p: SFProxy?,policy:SFPolicy,targetHost:String,Port:UInt16) ->NWTCPSocket? {
        
        if policy == .Direct {
            return DirectConnector.connectorWithHost(targetHost: targetHost, targetPort: Int(Port))
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
