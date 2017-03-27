//
//  CHTTPProxConnector.swift
//  SFSocket
//
//  Created by 孔祥波 on 27/03/2017.
//  Copyright © 2017 Kong XiangBo. All rights reserved.
//

import Foundation

class CHTTPProxConnector: HTTPProxyConnector {
    var adapter:Adapter?
    public static func create(targetHostname hostname:String, targetPort port:UInt16,p:SFProxy,adapter:Adapter) ->CHTTPProxConnector{
        let c:CHTTPProxConnector = CHTTPProxConnector(p: p)
        //c.manager = man
        //c.cIDFunc()
        c.targetHost = hostname
        c.targetPort = port
        c.adapter = adapter
        //c.start()
        return c
    }
}
