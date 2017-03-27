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
    override func readCallback(data: Data?, tag: Int) {
        guard let  adapter = adapter else { return  }
        let newdata = adapter.recv(data!)
        super.readCallback(data: newdata, tag: tag)
    }
    public override func sendData(data: Data, withTag tag: Int) {
        guard let  adapter = adapter else { return  }
        let newdata = adapter.send(data)
        super.sendData(data: newdata , withTag: tag)
    }
}
