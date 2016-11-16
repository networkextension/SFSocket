//
//  DirectConnector.swift
//  SimpleTunnel
//
//  Created by yarshure on 15/11/11.
//  Copyright © 2015年 Apple Inc. All rights reserved.
//

import Foundation
import AxLogger
//import CocoaAsyncSocket

public class DirectConnector:NWTCPSocket{
    var interfaceName:String?
    var targetHost:String = ""
    var targetPort:Int = 0
    //var ipAddress:String?
    override public func start() {
         autoreleasepool { do {
            
            try  super.connectTo(self.targetHost, port: Int(self.targetPort), enableTLS: false, tlsSettings: nil)
        }catch let e as NSError {
            //throw e
            AxLogger.log("connectTo error \(e.localizedDescription)", level: .Error)
            }
        }
    }
    public override  func connectTo(_ host: String, port: Int, enableTLS: Bool, tlsSettings: [NSObject : AnyObject]?) throws {
        do {
           try  super.connectTo(host, port: port, enableTLS: false, tlsSettings: nil)
        }catch let e  {
            throw e
        }
        
        
    }
    public static func connectorWithHost(targetHost:String,targetPort:Int) ->DirectConnector{
    //public func
        let c = DirectConnector()
        c.targetPort = targetPort
        c.targetHost = targetHost
        return c
    }
}


