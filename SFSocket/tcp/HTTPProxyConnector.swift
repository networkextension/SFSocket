//
//  HTTPProxyConnector.swift
//  SimpleTunnel
//
//  Created by yarshure on 15/11/11.
//  Copyright © 2015年 Apple Inc. All rights reserved.
//

import Foundation
import AxLogger
public enum SFConnectionMode:String {
    case HTTP = "HTTP"
    case HTTPS = "HTTPS"
    case TCP = "TCP"
    //case CONNECT = "CONNECT"
    public var description: String {
        switch self {
        case .HTTP: return "HTTP"
        case .HTTPS: return "HTTPS"
        case .TCP: return "TCP"
            //case CONNECT: return "CONNECT"
        }
    }
    
}
public  class HTTPProxyConnector:ProxyConnector {
    
    var connectionMode:SFConnectionMode = .HTTP
    public var reqHeader:SFHTTPRequestHeader?
    public var respHeader:SFHTTPResponseHeader?
    var httpConnected:Bool = false
    var headerData:Data = Data()
    static let ReadTag:Int = -2000
    // https support current don't support
    deinit {
        //reqHeader = nil
        //respHeader = nil
        AxLogger.log("\(cIDString) deinit", level: .Debug)
    }
    func sendReq() {
        if let req = reqHeader  {
            if let data = req.buildCONNECTHead(self.proxy) {
                AxLogger.log("\(cIDString) sending CONNECTHead \(data) \(req.method)",level: .Debug)
                self.writeData(data, withTag: HTTPProxyConnector.ReadTag)
            }else {
               AxLogger.log("\(cIDString) buildCONNECTHead error",level: .Error)
            }
        }else {
            //sleep(1)
            //sendReq()
           AxLogger.log("\(cIDString)  not reqHeader  error",level: .Error)
        }

    }
    func recvHeaderData(data:Data) ->Int{
        // only use display response status,recent request feature need
        if let r = data.range(of:hData, options: Data.SearchOptions.init(rawValue: 0)){
        
            // body found
            if headerData.count == 0 {
                headerData = data
            }else {
                headerData.append( data)
            }
            //headerData.append( data.subdata(in: r))
            
            respHeader = SFHTTPResponseHeader(data: headerData)
            if let r = respHeader, r.sCode != 200 {
                AxLogger.log("\(self) CONNECT status\(r.sCode) ",level: .Error)
                //有bug
                
                //let e = NSError(domain:errDomain , code: 10,userInfo:["reason":"http auth failure!!!"])
                AxLogger.log("socketDidCloseReadStream  \(data)",level:.Error)
                self.forceDisconnect()
                //sendReq()
                //NSLog("CONNECT status\(r.sCode) ")
            }
        
           
            
            return r.upperBound // https need delete CONNECT respond
        }else {
            headerData.append(data)
            
        }
        return 0
    }
 
    override func readCallback(data: Data?, tag: Int) {
        
        
        queueCall {
            guard let data = data else {return}
            //AxLogger.log("read data \(data)", level: .Debug)
            if self.httpConnected == false {
                if self.respHeader == nil {
                    let len = self.recvHeaderData(data: data)
                    
                    if len == 0{
                        AxLogger.log("http  don't found resp header",level: .Warning)
                    }else {
                        //找到resp header
                        self.httpConnected = true
                        if let d = self.delegate {
                            d.didConnect(self)
                        }
                        if len < data.count {
                            let dataX = data.subdata(in: Range(len ..< data.count ))
                            //delegate?.connector(self, didReadData: dataX, withTag: 0)
                            self.delegate?.didReadData( dataX, withTag: tag, from: self)
                            //AxLogger.log("\(cIDString) CONNECT response data\(data)",level: .Error)
                        }
                    }
                }

                //self.readDataWithTag(-1)
            }else {
                self.delegate?.didReadData( data, withTag: tag, from: self)
            }
            
        }
    }
    

    override public func socketConnectd() {
       
        if httpConnected == false {
            self.sendReq()
        }else {
            self.delegate?.didConnect( self)
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
                if strong.httpConnected == false {
                    strong.readDataWithTag(HTTPProxyConnector.ReadTag)
                }else {
                    strong.queueCall { autoreleasepool {
                        strong.delegate?.didWriteData(data, withTag: tag, from: strong)
                    }}
                }
                
            }
            strong.checkStatus()
        }
    }
    override public func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
      
        guard keyPath == "state" else {
            return
        }
        //crash
       
        
        if object == nil {
            AxLogger.log("\(cIDString) connection lost", level: .Error)
            disconnect()
            return
        }
        
        
        switch connection!.state {
        case .connected:
            queueCall {[weak self] in
                if let strong = self {
                    strong.socketConnectd()
                }
                
            }
        case .disconnected:
            cancel()
        case .cancelled:
            queueCall {
                if let delegate = self.delegate{
                    delegate.didDisconnect(self)
                }
                
                //self.delegate = nil
            }
        default:
            break
            //        case .Connecting:
            //            stateString = "Connecting"
            //        case .Waiting:
            //            stateString =  "Waiting"
            //        case .Invalid:
            //            stateString = "Invalid"
            
        }
        //        if let  x = connection.endpoint as! NWHostEndpoint {
        //
        //        }
        AxLogger.log("\(cIDString) stat: \(connection!.state.description)", level: .Debug)
    }

    public static func connectorWithSelectorPolicy(targetHostname hostname:String, targetPort port:UInt16,p:SFProxy) ->HTTPProxyConnector{
        let c:HTTPProxyConnector = HTTPProxyConnector(p: p)
        //c.manager = man
        //c.cIDFunc()
        c.targetHost = hostname
        c.targetPort = port
        
        //c.start()
        return c
    }
}
