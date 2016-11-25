//
//  SFConnection.swift
//  SFSocket
//
//  Created by 孔祥波 on 23/11/2016.
//  Copyright © 2016 Kong XiangBo. All rights reserved.
//

import Foundation
//For TCP Connection
open class SFConnection :RawTCPSocketDelegate{
    
    
    
    open func didDisconnect(_ socket: RawTCPSocketProtocol){
        
    }
    open func didReadData(_ data: Data, withTag: Int, from: RawTCPSocketProtocol){
        
    }
    
    open func didWriteData(_ data: Data?, withTag: Int, from: RawTCPSocketProtocol){
        
    }
    
    open func didConnect(_ socket: RawTCPSocketProtocol){
        
    }
}
