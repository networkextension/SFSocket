//
//  Adapter.swift
//  SFSocket
//
//  Created by 孔祥波 on 27/03/2017.
//  Copyright © 2017 Kong XiangBo. All rights reserved.
//

import Foundation

protocol AdapterProtocol {
    var streaming:Bool{ get }
    func send(_ data:Data) ->Data
    func recv(_ data:Data) ->Data
}
class Adapter:AdapterProtocol {
    func recv(_ data: Data) -> Data {
        return Data()
    }

    func send(_ data: Data) -> Data {
        return Data()
    }

    var streaming:Bool{
        get {
            return false
        }
    }
    var proxy:SFProxy
    var realHost:String
    var realPort:UInt16
    init(p:SFProxy,h:String,port:UInt16) {
        proxy = p
        realHost = h
        realPort = port
    }
    var targetHost:String {
        return proxy.serverAddress
    }
    var targetPort:UInt16{
        return UInt16(proxy.serverPort)!
    }
    static func createAdapter(_ proxy:SFProxy,host:String,port:UInt16) -> Adapter? {
        switch proxy.type {
        case .HTTP:
            return nil
        case .SOCKS5:
            return nil
        case .SS:
            return SSAdapter(p: proxy, h: host, port: port)
        case .SS3:
            return  SS3Adapter(p: proxy, h: host, port: port)
        default:
            return nil
        }
    }
    
}
