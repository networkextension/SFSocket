//
//  CSocks5Connector.swift
//  SFSocket
//
//  Created by 孔祥波 on 27/03/2017.
//  Copyright © 2017 Kong XiangBo. All rights reserved.
//

import Foundation

class CSocks5Connector: Socks5Connector {
    var adapter:Adapter?
    public static func create(_ selectorPolicy:SFPolicy ,targetHostname hostname:String, targetPort port:UInt16,p:SFProxy,adapter:Adapter) ->CSocks5Connector{
        let c:CSocks5Connector = CSocks5Connector(p: p)
        //c.manager = man
        
        c.targetHost = hostname
        c.targetPort = port
        c.adapter = adapter
        //c.cIDFunc()
        //c.start()
        return c
    }
}
