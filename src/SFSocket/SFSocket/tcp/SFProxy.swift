//
//  File.swift
//  Surf
//
//  Created by yarshure on 15/12/23.
//  Copyright © 2015年 yarshure. All rights reserved.
//

import Foundation
import SwiftyJSON
public enum SFProxyType :Int, CustomStringConvertible{
    case HTTP = 0
    case HTTPS = 1
    case SS = 2
    case SOCKS5 = 3
    case HTTPAES  = 4
    case LANTERN  = 5
    public var description: String {
        switch self {
        case .HTTP: return "HTTP"
        case .HTTPS: return "HTTPS"
        case .SS: return "SS"
        case .SOCKS5: return "SOCKS5"
        case .HTTPAES: return "GFW Press"
        case .LANTERN: return "LANTERN"
        }
    }
}
class SFProxy {
    var proxyName:String
    var serverAddress:String
    var serverPort:String
    var password:String
    var method:String
    var tlsEnable:Bool = false //对于ss ,就是OTA 是否支持
    var type:SFProxyType
    var pingValue:Float = 0
    var tcpValue:Double = 0
    var dnsValue:Double = 0
    var priority:Int = 0
    var enable:Bool = true
    var serverIP:String = ""
    var countryFlag:String = ""
    var isoCode:String = ""
    var udpRelay:Bool = false
    func countryFlagFunc() ->String{
        if countryFlag.isEmpty {
            return showString()
        }else {
            return countryFlag + " " + proxyName
        }
    }
    static func createProxyWithLine(line:String,pname:String) ->SFProxy? {
        
        let name = pname.trimmingCharacters(in:
            NSCharacterSet.whitespacesAndNewlines)
        
        
        
        let list =  line.components(separatedBy: ",")
        
        if list.count >= 5{
            let t = list.first?.uppercased().trimmingCharacters(in:
                NSCharacterSet.whitespacesAndNewlines)
            //占位
            let proxy:SFProxy = SFProxy.init(name: name, type: .SS, address: "", port: "443", passwd: "", method: "aes-256-cfb", tls: false)
            if t == "HTTP" {
                proxy.type = .HTTP
            }else if t == "HTTPS" {
                proxy.type = .HTTPS
                proxy.tlsEnable = true
            }else if t == "SOCKS5" {
                proxy.type = .SOCKS5
            }else if t == "SS" {
                proxy.type = .SS
            }else {
                //alertMessageAction("\(scheme) Invilad", complete: nil)
                //return
            }
            
            proxy.serverAddress =  list[1].trimmingCharacters(in:
                NSCharacterSet.whitespacesAndNewlines)
            proxy.serverPort =   list[2].trimmingCharacters(in:
                NSCharacterSet.whitespacesAndNewlines)
            proxy.method =   list[3].trimmingCharacters(in:
                NSCharacterSet.whitespacesAndNewlines).lowercased()
            proxy.password =   list[4].trimmingCharacters(in:
                NSCharacterSet.whitespacesAndNewlines)
            
            if  list.count >= 6 {
                let temp = list[5]
                let tt = temp.components(separatedBy: "=")
                if tt.count == 2{
                    if tt.first! == "tls" {
                        if tt.last! == "true"{
                            proxy.tlsEnable = true
                        }
                    }
                }
            }
            return proxy
        }
        return nil
        
        
        
    }
    init(name:String,type:SFProxyType ,address:String,port:String , passwd:String,method:String,tls:Bool){
        self.proxyName = name
        self.serverAddress = address
        self.serverPort = port
        self.password = passwd
        self.method = method
        if type == .HTTPS {
            self.tlsEnable = true
        }else {
            self.tlsEnable = tls
        }
        
        if method == "aes" {
            self.type = .HTTPAES
        }else {
            self.type = type
        }
        
        
    }
    func showString() ->String {
        if !proxyName.isEmpty{
            return proxyName
        }else {
            if !isoCode.isEmpty {
                return  isoCode
            }
        }
        return serverAddress
    }
    func resp() ->[String:Any]{
        return ["name":proxyName as AnyObject,"host":serverAddress as AnyObject,"port":serverPort,"protocol":type.description,"method":method,"passwd":password,"tls":NSNumber.init(value: tlsEnable),"priority":NSNumber.init(value: priority),"enable":NSNumber.init(value: enable),"countryFlag":countryFlag,"isoCode":isoCode,"ipaddress":serverIP]
    }
    static func map(name:String,value:JSON) ->SFProxy{
        let i = value
        let px = i["protocol"].stringValue as NSString
        let proto = px.uppercased
        var type :SFProxyType
        if proto == "HTTP"{
            type = .HTTP
        }else if proto == "HTTPS" {
            type = .HTTPS
        }else if proto == "CUSTOM" {
            type = .SS
        }else if proto == "SS" {
            type = .SS
        }else if proto == "SOCKS5" {
            type = .SOCKS5
        }else {
            type = .LANTERN
        }
        
        
        let a = i["host"].stringValue, p = i["port"].stringValue , pass = i["passwd"].stringValue , m = i["method"].stringValue
        
        var tlsEnable = false
        let tls = i["tls"]
        if tls.error == nil {
            tlsEnable = tls.boolValue
        }
        
        var enable = false
        let penable = i["enable"]
        if penable.error == nil {
            enable = penable.boolValue
        }
        
        var pName = name
        if i["name"].error == nil {
            pName = i["name"].stringValue
        }
        let sp = SFProxy(name: pName, type: type, address: a, port: p, passwd: pass, method: m,tls: tlsEnable)
        
        
        if type == .SS {
            //sp.udpRelay = true
        }
        
        sp.enable = enable
        let cFlag = i["countryFlag"]
        sp.countryFlag = cFlag.stringValue
        let priJ = i["priority"]
        if priJ.error == nil {
            sp.priority = priJ.intValue
        }
        if i["isoCode"].error == nil {
            sp.isoCode = i["isoCode"].stringValue
        }
        if i["ipaddress"].error == nil {
            sp.serverIP = i["ipaddress"].stringValue
        }
        return sp
    }
    func typeDesc() ->String{
        if tlsEnable && type == .HTTP {
            return "Type: " + "HTTPS"
        }
        return "Type: " + type.description
    }
    func base64String() ->String {
        let tls = tlsEnable ? "1" : "0"

        let string = method + ":" + password + "@" + serverAddress  + ":" + serverPort
        
        //let string = config.method + ":" + config.password + "@" + a + ":" + p
        
        //let string = "aes-256-cfb:fb4b532cb4180c9037c5b64bb3c09f7e@108.61.126.194:14860"//
        let utf8str = string.data(using: .utf8)
        let base64Encoded = type.description.lowercased()  + "://" + utf8str!.base64EncodedString(options: .endLineWithLineFeed) +   "?tlsEnable=" + tls
        return base64Encoded
    }
   
    deinit{
        
    }
}
