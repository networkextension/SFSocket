//
//  StringExtension.swift
//  Surf
//
//  Created by 孔祥波 on 11/5/16.
//  Copyright © 2016 yarshure. All rights reserved.
//

import Foundation

public enum SFPolicy :String{
    case Direct = "DIRECT"
    case Reject = "REJECT"
    case Proxy = "Proxy"
    case Random =  "RANDOM"
    public var description: String {
        switch self {
        case .Direct: return "DIRECT"
        case .Reject: return "REJECT"
        case .Proxy: return "Proxy"
        case .Random: return "RANDOM"
        }
    }
}
let SOCKS_VERSION:UInt8 = 0x05
let SOCKS_AUTH_VERSION:UInt8 = 0x01
let SOCKS_AUTH_SUCCESS:UInt8 = 0x00
let SOCKS_CMD_CONNECT:UInt8 = 0x01
let SOCKS_IPV4:UInt8 = 0x01
let SOCKS_DOMAIN :UInt8 = 0x03
let SOCKS_IPV6:UInt8 = 0x04
let SOCKS_CMD_NOT_SUPPORTED :UInt8 = 0x07
public enum SOCKS5HostType:UInt8,CustomStringConvertible{
    case IPV4 = 0x01
    case DOMAIN = 0x03
    case IPV6 = 0x04
    public var description: String {
        switch self {
        case .IPV4 :return "SFSocks5HostTypeIPV4"
        case .DOMAIN: return "SFSocks5HostTypeDOMAIN"
        case .IPV6: return "SFSocks5HostTypeIPV6"
        }
    }
}

extension String {
    public func to(index:Int) ->String{
        return self.substring(to: self.index(self.startIndex, offsetBy: index))
    }
    public func validateIpAddr() ->SOCKS5HostType{
        var sin = sockaddr_in()
        var sin6 = sockaddr_in6()
        
        if self.withCString({ cstring in inet_pton(AF_INET6, cstring, &sin6.sin6_addr) }) == 1 {
            // IPv6 peer.
            return .IPV6
        }
        else if self.withCString({ cstring in inet_pton(AF_INET, cstring, &sin.sin_addr) }) == 1 {
            // IPv4 peer.
            return .IPV4
        }
        
        return .DOMAIN
        
    }
}

public func toIPv6Addr(ipString:String) -> Data?  {
    var addr = in6_addr()
    let retval = withUnsafeMutablePointer(to: &addr) {
        inet_pton(AF_INET6, ipString, UnsafeMutablePointer($0))
    }
    if retval < 0 {
        return nil
    }
    
    let data = NSMutableData.init(length: 16)
    let p = UnsafeMutableRawPointer.init(mutating: (data?.bytes)!)
    //let addr6 =
    //#if swift("2.2")
    //memcpy(p, &(addr.__u6_addr), 16)
    memcpy(p, &addr, 16)
    //#else
    //#endif
    //print(addr.__u6_addr)
    return data as Data?
}
extension Data{
  
    public func withUnsafeRawPointer<ResultType>(_ body: (UnsafeRawPointer) throws -> ResultType) rethrows -> ResultType {
        return try self.withUnsafeBytes { (ptr: UnsafePointer<Int8>) -> ResultType in
            let rawPtr = UnsafeRawPointer(ptr)
            return try body(rawPtr)
        }
    }
    public func scanValue<T>(start: Int, length: Int) -> T {
        //start+length > Data.last is security?
        return self.subdata(in: start..<start+length).withUnsafeBytes { $0.pointee }
    }
    public var length:Int{
        get {
            return self.count
        }
    }
}
extension Range{
    //<Data.Index>
    public func length() -> Int{
        return 0 //
    }
}
