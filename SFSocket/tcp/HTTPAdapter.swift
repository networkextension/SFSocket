//
//  File.swift
//  SFSocket
//
//  Created by 孔祥波 on 27/03/2017.
//  Copyright © 2017 Kong XiangBo. All rights reserved.
//

import Foundation

class HTTPAdapter: Adapter {
    override var streaming:Bool{
        get {
            return false
        }
    }
    override func recv(_ data: Data) -> Data {
        return Data()
    }
    
    override func send(_ data: Data) -> Data {
        return Data()
    }
}
