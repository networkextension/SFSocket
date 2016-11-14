//
//  File.swift
//  Surf
//
//  Created by yarshure on 15/12/28.
//  Copyright © 2015年 yarshure. All rights reserved.
//
//Transfer-Encoding
//chunked, compress, deflate, gzip, identity.
//https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
import Foundation
import AxLogger
public enum HTTPMethod: String {
    case DELETE = "DELETE"
    case GET = "GET"
    case HEAD = "HEAD"
    case OPTIONS = "OPTIONS"
    case PATCH = "PATCH"
    case POST = "POST"
    case PUT = "PUT"
    case CONNECT = "CONNECT"
//    public var description: String {
//        switch self {
//        case DELETE: return "DELETE"
//        case GET: return "GET"
//        case HEAD:return "HEAD"
//        case OPTIONS : return "OPTIONS"
//        case PATCH : return  "PATCH"
//        case POST: return "POST"
//        case PUT: return "PUT"
//        case CONNECT: return "CONNECT"
//        
//    }

}
public enum HTTPHeaderKey: String {
    case Host = "Host"
    case Method = "Method"
    case Url = "Url"
    case Accept = "Accept"
    case ProxyConnection = "Proxy-Connection"
    case Cookie = "Cookie"
    case UserAgent = "User-Agent"
    case Connection = "Connection"
    case AcceptLanguage = "Accept-Language"
    case Referer = "Referer"
    case AcceptEncoding = "Accept-Encoding"
    case CacheControl = "Cache-Control"
    case TransferEncoding = "Transfer-Encoding"
 }
public let sepData:Data = "\r\n".data(using: .utf8)!
public let hData:Data = "\r\n\r\n".data(using: .utf8)!
public let cData:Data = "CONNECT".data(using: .utf8)!
public let SSL_CONNECTION_RESPONSE = "HTTP/1.1 200 Connection established\r\n\r\n"
public let http:Data = "HTTP".data(using: .utf8)!

public let http503 = "HTTP/1.1 503 Service Unavailable\r\rServer: A.BIG.T/2.0\r\nContent-Type: text/html\r\nAccept-Ranges: bytes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


public protocol HTTPProtocol {
    var length:Int  { get set }
    var version:String  { get set }
    //var ContentLength:UInt  { get set }
//    var params:[String:String] { get set }
}
public class  HTTPHeader {
    public var length:Int = 0
    public var bodyLeftLength:Int = 0
    public var version:String = ""
    public var contentLength:Int = 0
    public var params:[String:String] = [:]
    public init? (data:Data) {
        length = data.count + 4
        
    }
    public var app:String {
        if let app = params["User-Agent"]{
            return app
        }
        return ""
    }
    public func bodyReadFinish() ->Bool{
        return false
    }
    public func parserData(_ lines:[String]){
        for line in lines {
            if let r = line.range(of: ": ") {
                
            
//                let start = line.startIndex
//                let end = line.endIndex
               
                
                let key = line.substring(to: r.lowerBound) //substringToIndex(r.startIndex)
                //print("key:" + key)
                let v = line.substring(from: r.upperBound)//substringFromIndex(r.endIndex)
                //print("value:" + v)
                params[key] = v
            }
//            let b = line.components(separatedBy: ": ")
//            if b.count > 1{
//                params[b.first!] = b[1]
//            }
        }
        
    }
    public func headerData(_ proxy:SFProxy?)->Data {
        let f = headerString( proxy)
        
        if let d = f.data(using: .utf8) {
           return d
        }
        return Data()
        
    }
    public func headerString(_ proxy:SFProxy?)->String {
        return ""
    }
    deinit {
        AxLogger.log("HTTPHeader dealloc",level: .Debug)
    }
}
public enum HTTPResponseMode :String{
    case ContentLength = "Content-Length"
    case TransferEncoding = "Transfer-Encoding"
    case ContentEncoding = "Content-Encoding"
}
public struct chunked{
    var len:Int = 0
    var leftLen:Int = 0
    var data:Data?
    init(l:Int,left:Int){
        len = l
        leftLen = left
    }
}
public func hexDataToInt(d:Data) ->UInt32{
    
    
    var result:UInt32 = 0
    if let r = String.init(data: d, encoding: .utf8) {
        let x = "0x" + r
        let s = Scanner.init(string: x)
        s.scanHexInt32(&result)
    }
    //let x = "0x" + String.init(data: d, encoding: .utf8)!
    //print("xx:" + x)
    
    
    
    
    //_ = Scanner(string:x).scanHexInt32(&result)
    return result
}
public class  HTTPResponseHeader :HTTPHeader{
    public var sCode:Int = 0 //http response status code
    public var mode:HTTPResponseMode = .TransferEncoding
    public var close:Bool = false
    public var chunk_packet:chunked?
    public override init? (data:Data) {
        super.init(data: data)
        guard let row = String.init(data: data , encoding: .utf8) else {
            return nil
        }
        if row.characters.count == 0 {
            return nil
        }
        //length = data.length
        var lines = row.components(separatedBy: "\r\n")
        var f:String = ""
        if lines.count > 2{
            f = lines.removeFirst()
        }else {
            f = lines.first!
        }
        
        
        let c = f.components(separatedBy: " ")
        
        //response
        //let c = f.components(separatedBy: " ")
        
        if c.count > 1 {
            
            self.version = c[0]
            self.sCode = Int(c[1])!
        }else {
            //AxLogger.log("\(row) packet error",level: .Error)
            //print("http \(row) response no params")
        }

        if lines.count > 1 {
            lines.remove(at: 1)
            self.parserData(lines)
        }
        if params.count > 0 {
            if let len = params["Content-Length"]{
                if let x = Int(len){
                    contentLength = x
                    if let ContentRange = params["Content-Range"]{
                        //Content-Range parser  bytes 一般是这个
                        // 500-1023/1024
                        let dwW = ContentRange.components(separatedBy: " " )
                        let x = dwW.last!.components(separatedBy: "/")
                        let total = Int(x.last!)
                        let yy = x.first!.components(separatedBy: "-")
                        let index = Int(yy.first!)
                        if let end = x.last {
                            bodyLeftLength = Int(end)! - index! + 1
                        }else {
                             bodyLeftLength = total! - index!
                        }
                       
                    }else {
                        bodyLeftLength = contentLength
                    }
                    
                }
                self.mode = .ContentLength
            }else if  let ContentRange = params["Content-Range"]{
                    //Content-Range parser  bytes 一般是这个
                    // 500-1023/1024
                    let dwW = ContentRange.components(separatedBy: " ")
                    let x = dwW.last!.components(separatedBy:"/")
                    let total = Int(x.last!)
                    let yy = x.first!.components(separatedBy:"-")
                    let index = Int(yy.first!)
                    if let end = x.last {
                        bodyLeftLength = Int(end)! - index! + 1 //fix less 1
                    }else {
                        bodyLeftLength = total! - index!
                    }
            }else {
                
                if let _ = params["Transfer-Encoding"]{
                    //ContentLength = Int(len)!
                    self.mode = .TransferEncoding
                    //NSLog("%@", params)
                }else {
                    if let _ = params["Content-Encoding"] {
                        self.mode = .ContentEncoding
                    }else {
                        self.mode = .ContentEncoding //啥也没有饿
                    }
                   // NSLog("Connection:\(params["Connection"])")
                }
            }
        }
        if let x = params["Connection"] {
            if x == "close" {
                close = true
            }else {
                close = false
            }
        }
        
    }
    public func statusLine() ->String{
        return "\(version) \(sCode) \(statusCodeDescriptions[sCode])"
    }
    var finished:Bool  = false
    public override func bodyReadFinish() ->Bool{
        if mode == .ContentLength {
            if bodyLeftLength <= 0 {
                return  true
            }
        }else {
           return finished
        }
    
        return false
    }
    public func contentLength() ->Int {
        if self.mode == .ContentLength {
            if let len = params["Content-Length"]{
                if let ContentRange = params["Content-Range"]{
                    //Content-Range parser  bytes 一般是这个
                    // 500-1023/1024
                    let dwW = ContentRange.components(separatedBy:" ")
                    let x = dwW.last!.components(separatedBy:"/")
                    let total = Int(x.last!)
                    let yy = x.first!.components(separatedBy:"-")
                    let index = Int(yy.first!)
                    if let end = x.last {
                        bodyLeftLength = Int(end)! - index! + 1
                    }else {
                        bodyLeftLength = total! - index!
                    }
                    
                }else {
                    if let x =  Int(len) {
                        return x
                    }
                    //bodyLeftLength = contentLength
                }

                
            } else if  let ContentRange = params["Content-Range"]{
                //Content-Range parser  bytes 一般是这个
                // 500-1023/1024
                let dwW = ContentRange.components(separatedBy: " ")
                let x = dwW.last!.components(separatedBy: "/")
                let total = Int(x.last!)
                let yy = x.first!.components(separatedBy: "-")
                let index = Int(yy.first!)
                if let end = x.last {
                    bodyLeftLength = Int(end)! - index! + 1 //fix less 1
                }else {
                    bodyLeftLength = total! - index!
                }
                bodyLeftLength = bodyLeftLength
            }else {
                return 0
            }
            
        }
        return 0
    }

    public func shouldColse2(hostname:String) ->Bool {
        //
        //优化协议
        //fixme
//        if let c = params["Connection"] where c == "close" {
//            if sCode >= 300 && sCode < 400 {
//                if let u = params["Location"]{
//                    if let url = URL.init(string: u), url.host != hostname {
//                        return true
//                    }
//                }
//                
//            }
//        }

        
        return false
    }
    public override func headerString(_ proxy:SFProxy?)->String {
        var f = ""
        let s = "\r\n"
        let p = params
        
        if let rep = statusCodeDescriptions[sCode] {
            f = version + " \(sCode) " + rep + s
        }else {
            f = version + " \(sCode) " + "Header Invalid" + s
        }
        
        for (key,value) in p {
            f = f + key + ": " + value + "\r\n"
        }
        
        f = f + "\r\n"
        return f

    }
    public func shouldClose() ->Bool{
        if mode == .ContentLength {
            if bodyLeftLength <= 0 {
                return close
            }else {
                return false
            }
        }else {
            AxLogger.log("Transfer-Encoding parser will support future",level: .Notify)
            return false
        }
    }
 

    deinit {
         AxLogger.log("[HTTPRespHeader] deinit",level: .Debug)
    }
}

let pattern = "::ffff:(.*)"
public class  HTTPRequestHeader :HTTPHeader{
    public var Host:String = ""
    public var Port:Int = 0
    public var Method:HTTPMethod = .GET
    public var Url:String = ""
    public var location:String = ""
    public var ipAddressV4:String = ""
    public var ipAddressV6:String = ""
    public var mode:HTTPResponseMode = .ContentLength
    public var hostChanged:Bool = false
    static func listGroups(string : String) -> [String] {
        //523 byte one time , too many memory
        let regex = try! NSRegularExpression(pattern: pattern, options: .caseInsensitive)
        let range = NSMakeRange(0, string.characters.count)
        let matches = regex.matches(in: string, options: [], range: range)
        
        var groupMatches = [String]()
        for match in matches {
            let rangeCount = match.numberOfRanges
            //print(match)
            for group in 0..<rangeCount {
                let result = (string as NSString).substring(with: match.rangeAt(group))
                print(result)
                if result.characters.count != string.characters.count && result.characters.count >= 7 {
                    groupMatches.append(result)
                }
                
            }
        }
        
        return groupMatches
    }
    func genPath() -> String {
        //print(index)
        var u = self.Url
        if !location.isEmpty{
            u = self.location
        }
        if u.hasPrefix("http") {
            var index = 0
            var t = 0
            for i in u.characters {
                if i == "/"{
                    t += 1
                    if t == 3 {
                        break
                    }
                }
                index += 1
                
            }
            let i = u.index(u.startIndex, offsetBy: index)
            let x = u.substring(from: i)
            return x
        }else {
            return u
        }
        
    }
    override public func bodyReadFinish() ->Bool{
        
        
        if bodyLeftLength <= 0  {
            return true
        }else {
            return false
        }
        
    }
    func forceSend() -> Bool{
        if let status = params["Proxy-Connection"], status == "close" {
            return true
        }
        return false
    }
    deinit {
        AxLogger.log("HTTPRequestHeader dealloc",level: .Debug)
    }

    override init? (data:Data){
        super.init(data: data)
        guard let row = String.init(data: data, encoding: .utf8) else {
            return nil
        }
        length = data.count + 4
        var lines = row.components(separatedBy: "\r\n")
        var f:String = ""
        if lines.count > 2{
            f = lines.removeFirst()
        }else {
            f = lines.first!
        }
        if lines.count > 0 {
            parserData(lines)
        }

        if self.Host.isEmpty {
            if let h = params["Host"]{
                var  x =  h.components(separatedBy:":")
                if x.count == 2 {
                    self.Host = x.first!
                    self.Port = Int(x.last!)!
                }else if x.count == 1 {
                    self.Host = h
                }else {
                    // > 3 IPv6
                    self.Port = Int(x.last!)!
                    x.removeLast()
                    self.Host = x.joined(separator: ":")
                }
            }
        }
        let c = f.components(separatedBy:" ")
        if c.count == 3 {
            self.Method = HTTPMethod.init(rawValue: c.first!)!
            self.Url = c[1]
            //NSLog("url %@",self.Url)
            if self.Url.isEmpty {
                AxLogger.log("HTTPRequest \(row) not url  \(c) ",level: .Trace)
                
            }
            if self.Method == .CONNECT {
                let u = self.Url.components(separatedBy:":")
                if u.count == 2 {
                    self.Host = u.first!
                    self.Port = Int(u.last!)!
                }else {
                    //self.Host = u.first!
                    self.Port = 443
                }
            }else {
                //这里可能有错误的情况
                
                if let u = NSURL.init(string: self.Url) {
                    if self.Method == .POST {
                        AxLogger.log("request \(Url)",level: .Trace)
                    }
                    if  let port = u.port {
                        self.Port = port.intValue
                    }else {
                        self.Port = 80
                    }
                    if let uhost = u.host{
                        //[::ffff:58.221.77.19]
                        //::ffff:58.221.77.19 是这货
                        // 每次节省710byte
                        if uhost.hasPrefix("::ffff:"){
                            self.Host = uhost
                            let list = uhost.components(separatedBy: "::ffff:")
                            if list.count == 2 {
                                self.ipAddressV4 = list.last!
                            }
                        }else {
                            self.Host = uhost
                        }
                        //let c = HTTPRequestHeader.listGroups(uhost)
                        //AxLogger.log("Host:\(uhost)",level: .Trace)
                        
//                        if let ip = c.first {
//                            let type = validateIpAddr(ip)
//                            if  type  == .IPV4 {
//                                self.ipAddressV4 = ip
//                                AxLogger.log("IP:\(self.ipAddressV4)",level:.Trace)
//                                //self.Url = "http://" + self.ipAddressV4 + self.Url
//                            }else {
//                                //self.Url = "http://" + uhost + self.Url
//                            }
//                            AxLogger.log("\(type.description)",level:.Trace)
//                        }else {
//                            AxLogger.log("\(uhost) ::ffff: failure",level: .Warning)
//                            //self.Url = "http://" + uhost + self.Url
//                        }
                        //if uhost.range(of:"[")
                    }else {
                        if !self.Url.hasPrefix("http://"){
                            self.Url = "http://" + self.Host + self.Url
                        }
                    }
                    if self.Method == .POST {
                        AxLogger.log("new request \(Url)",level:.Trace)
                    }
                }else {
                    //tcp raw 80 
                    self.Url = "http://" + self.Host + self.Url
                    self.Port = 80
                    //fatalError()
                    //x.stringByAddingPercentEscapesUsingEncoding(NSUTF8StringEncoding)!
                    //"http://eclick.baidu.com/fp.htm?sr=414x736x32x3&je=0&ce=1&tz=-480&pl=&sc=10&im=1&wf=0&ah=716&aw=414&cav=9b48d47b4fb362e58ecf1973dfbbcf21&com=0&lan=zh-cn|0|0&pla=0&bp=&ci=&bi=&de=ios&_=1457518739474"
                   //fatalError("HTTP Request \(row) not url  \(c) ")
                }
            }
            
            
            self.version = c[2]
        }else {
            //AxLogger.log("header error: \(c)",level: .Error)
            AxLogger.log("http \(row) response error",level:.Error)
        }
        
        
        //NSLog("#### host %@", Host)
        
//        if !self.Host.isEmpty{
//            let list = self.Host.components(separatedBy: ":")
//            self.Host = list[0]
//            if list.count > 1{
//                if let p =  Int(list.last!){
//                    self.Port = p
//                    
//                }
//            }
//        }
        if params.count > 0 {
            if let len = params["Content-Length"]{
                if let x = Int(len){
                    contentLength = x
                    bodyLeftLength = x
                }
                
            }else {
                
                if let _ = params["Transfer-Encoding"]{
                    //ContentLength = Int(len)!
                    self.mode = .TransferEncoding
                    
                }
            }
        }
        
        if self.Url.characters.count == 0 {
            //fatalError("HTTP Request \(row) not url  \(c) ")
            //这里有问题啊
            //
        }
        
        
        
        //NSLog("#### URL %@:%d", Host,Port)
    }

    
    public func parmas() -> [String:String]{
        var p = params
        if Method == .CONNECT
        {
            
        }else {
            
        }
        
        if let x = p.removeValue(forKey: "Proxy-Connection") {
            p["Connection"] = x
        }
        return p
    }
    func debugPareas (){
        //AxLogger.log("\(params)")
    }
    
    public override func headerString(_ proxy:SFProxy?)->String {
        var f = ""
        let s = "\r\n"
        var p = params
        
        if let proxy = proxy {
            let t = proxy.type
            switch t {
            case .HTTP, .HTTPS:
                if Method == .CONNECT
                {//https ?
                    f = Method.rawValue + " " + Url + " " + version + s
                }else {
                    let path = genPath()
                    if !path.isEmpty{
                        f = Method.rawValue + " " + path + " " + version + s
                    }else {
                        // fatalError()
                        f = Method.rawValue + " / " + version + s
                    }
                    //f = Method.rawValue + " " + Url + " " + version + s
                }
                //NSLog("http ######### url\(f),\(Url)")
                for (key,value) in p {
                    f = f + key + ": " + value + "\r\n"
                }
                if !proxy.method.isEmpty && !proxy.password.isEmpty {
                   //http basic auth
                    let temp = proxy.method + ":" + proxy.password
                    let utf8str = temp.data(using: .utf8)
                    if let base64Encoded = utf8str?.base64EncodedString(options: .endLineWithCarriageReturn) {
                        f = f + "Proxy-Authorization: Basic " + base64Encoded + "\r\n"
                    }
                }
            //case .HTTPS: break
            case .SS:
                if Method == .CONNECT
                {//https ?
                    f = Method.rawValue + " " + Url + " " + version + s
                }else {
                    
                    let path = genPath()
                    if !path.isEmpty{
                        f = Method.rawValue + " " + path + " " + version + s
                    }else {
                        //fatalError()
                        f = Method.rawValue + " " + "/" + " " + version + s
                    }
                    //NSLog("http ######### url \(f) ")
//                    var path = "/"
//                    if let u = NSURL(string: Url) {
//                        if let q = u.query {
//                            path = u.path! + "?" + q
//                        }else {
//                            path = u.path!
//                        }
//                        
//                    }else {
//                        //stringByAddingPercentEscapesUsingEncoding(NSUTF8StringEncoding)
//                        if  let s = Url.removingPercentEncoding, u = NSURL(string:s) {
//                            path = u.path! + "?" + u.query!
//                        }
//                    }
//                    f = Method.rawValue + " " + path + " " + version + s
                    //fatalError()
                }
                for (key,value) in p {
                    f = f + key + ": " + value + "\r\n"
                }
            default:break //不需要发送头部
                
                //            case .SOCKS5: break
                //            case .LANTERN: break
            }

        }else {
            //Direct
            p.removeValue(forKey: "Proxy-Connection")
            
            if Method == .CONNECT
            {//https ?
                f = Method.rawValue + " " + Url + " " + version + s
            }else {
                let path = genPath()
                if !path.isEmpty{
                    f = Method.rawValue + " " + path + " " + version + s
                    AxLogger.log("new request send line \(self.Host)",level:.Trace)
                }else {
                   // fatalError()
                    f = Method.rawValue + " / " + version + s
                }
                //NSLog("http ######### url \(f),\(Url)")
                
            }
            for (key,value) in p {
                f = f + key + ": " + value + "\r\n"
            }
        }
        
        f = f + "\r\n"
        return f
    }
    func app()->String{
        if let app = params["User-Agent"]{
            return app
        }
        return ""
    }
    func updateWithLocation(_ location:String) ->Data {
        //redirect
        self.location = location
        if let u = NSURL.init(string: self.location) {
            if let p = u.port{
                let Port = p.intValue
                if Port != self.Port {
                    hostChanged = true
                    self.Port = Port
                }
            }else {
                if let host = u.host{
                    if host != self.Host {
                        hostChanged = true
                        self.Host = host
                        self.params["Host"] = self.Host
                    }else {
                        //多次跳转
                        hostChanged = false
                        
                    }
                }

            }
            
        }
        let headerString = self.headerString(nil)
        let data = headerString.data(using: .utf8)!
        return data
    }
    //tcp connection pass through http proxy
    static func buildCONNECTHead(_ host:String, port:String,proxy:SFProxy) ->Data{
        let processinfo = ProcessInfo.processInfo
        //let version = kernelVersion()Darwin/\(version)
        var result = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n"
        
        
        result += "Host: " + host + "\r\n"
        result += "User-Agent: \(processinfo.processName)/version A.GIG.T/build)\r\n"
        //result += "User-Agent: \(processinfo.processName)/\(appVersion()) A.GIG.T/\(appBuild())\r\n"
        result += "Connection: keep-alive\r\n"
//        if proxy.method.characters.count > 0 && proxy.password.characters.count > 0 {
//            //http basic auth
//            let temp = proxy.method + ":" + proxy.password
//            let utf8str = temp.dataUsingEncoding(NSUTF8StringEncoding)
//            if let base64Encoded = utf8str?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0)) {
//                result = result + "Proxy-Authorization: Basic " + base64Encoded + "\r\n"
//            }
//        }
//        
        result += "Proxy-Connection: keep-alive\r\n"
        result += "\r\n"
        //print(result)
        return result.data(using: .utf8)!

    }
    func buildCONNECTHead(_ proxy:SFProxy?) -> Data? {
        if Method == .CONNECT {
            return headerData(proxy)
        }else {
            //normal http requst through http proxy
            //let processinfo = NSProcessInfo.processInfo()
            //let version = kernelVersion()Darwin/\(version)
            if !Host.isEmpty {
                var f = "CONNECT \(Host):\(Port) HTTP/1.1\r\n"
                
                for (key,value) in params {
                    f = f + key + ": " + value + "\r\n"
                }
                if let proxy = proxy {
                    if !proxy.method.isEmpty && !proxy.password.isEmpty  {
                        //http basic auth
                        let temp = proxy.method + ":" + proxy.password
                        
                        let utf8str = temp.data(using: .utf8)
                        
                        if let base64Encoded = utf8str?.base64EncodedString(options: .endLineWithLineFeed) {
                            f = f + "Proxy-Authorization: Basic " + base64Encoded + "\r\n"
                        }
                    }
                }
                
                f += "\r\n"
                //print(f)
                return f.data(using: .utf8)!
            }else {
                return nil
            }
            
        }
    }
}

let statusCodeDescriptions = [
    // Informational.
//    100: "continue"                      , 101: "switching protocols"             , 102: "processing"                           ,
//    103: "checkpoint"                    , 122: "uri too long"                    , 200: "ok"                                   ,
//    201: "created"                       , 202: "accepted"                        , 203: "non authoritative info"               ,
//    204: "no content"                    , 205: "reset content"                   , 206: "partial content"                      ,
//    207: "multi status"                  , 208: "already reported"                , 226: "im used"                              ,
//    
//    // Redirection.
//    300: "multiple choices"              , 301: "moved permanently"               , 302: "found"                                ,
//    303: "see other"                     , 304: "not modified"                    , 305: "use proxy"                            ,
//    306: "switch proxy"                  , 307: "temporary redirect"              , 308: "permanent redirect"                   ,
//    
//    // Client Error.
//    400: "bad request"                   , 401: "unauthorized"                    , 402: "payment required"                     ,
//    403: "forbidden"                     , 404: "not found"                       , 405: "method not allowed"                   ,
//    406: "not acceptable"                , 407: "proxy authentication required"   , 408: "request timeout"                      ,
//    409: "conflict"                      , 410: "gone"                            , 411: "length required"                      ,
//    412: "precondition failed"           , 413: "request entity too large"        , 414: "request uri too large"                ,
//    415: "unsupported media type"        , 416: "requested range not satisfiable" , 417: "expectation failed"                   ,
//    418: "im a teapot"                   , 422: "unprocessable entity"            , 423: "locked"                               ,
//    424: "failed dependency"             , 425: "unordered collection"            , 426: "upgrade required"                     ,
//    428: "precondition required"         , 429: "too many requests"               , 431: "header fields too large"              ,
//    444: "no response"                   , 449: "retry with"                      , 450: "blocked by windows parental controls" ,
//    451: "unavailable for legal reasons" , 499: "client closed request"           ,
//    
//    // Server Error.
//    500: "internal server error"         , 501: "not implemented"                 , 502: "bad gateway"                          ,
//    503: "service unavailable"           , 504: "gateway timeout"                 , 505: "http version not supported"           ,
//    506: "variant also negotiates"       , 507: "insufficient storage"            , 509: "bandwidth limit exceeded"             ,
//    510: "not extended"                  ,
    
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Checkpoint" ,
    122: "URI too long" ,
    
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi status"                  , 208: "Already reported"                , 226: "Im used",
    
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    306: "(Unused)",
    307: "Temporary Redirect",
    308: "Permanent redirect",
    
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Entity Too Large",
    414: "Request-URI Too Long",
    415: "Unsupported Media Type",
    416: "Requested Range Not Satisfiable",
    417: "Expectation Failed",
    418: "Im A Teapot"                   , 422: "Unprocessable Entity"            , 423: "Locked"                               ,
    424: "Failed Dependency"             , 425: "Unordered Collection"            , 426: "Upgrade Required"                     ,
    428: "Precondition Required"         , 429: "Too many Requests"               , 431: "Header Fields Too Large"              ,
    444: "No Response"                   , 449: "Retry With"                      , 450: "Blocked By Windows Parental controls" ,
    451: "Unavailable for legal reasons" , 499: "Client Closed Request"           ,


    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates"       , 507: "Insufficient Storage"            , 509: "Bandwidth Limit Exceeded"             ,
    510: "Not Extended",511:"Network Authentication Required",599:"Network Connect Timeout Error",
    
]


//1×× Informational
//100 Continue
//101 Switching Protocols
//102 Processing
//2×× Success
//200 OK
//201 Created
//202 Accepted
//203 Non-authoritative Information
//204 No Content
//205 Reset Content
//206 Partial Content
//207 Multi-Status
//208 Already Reported
//226 IM Used
//3×× Redirection
//300 Multiple Choices
//301 Moved Permanently
//302 Found
//303 See Other
//304 Not Modified
//305 Use Proxy
//307 Temporary Redirect
//308 Permanent Redirect
//4×× Client Error
//400 Bad Request
//401 Unauthorized
//402 Payment Required
//403 Forbidden
//404 Not Found
//405 Method Not Allowed
//406 Not Acceptable
//407 Proxy Authentication Required
//408 Request Timeout
//409 Conflict
//410 Gone
//411 Length Required
//412 Precondition Failed
//413 Payload Too Large
//414 Request-URI Too Long
//415 Unsupported Media Type
//416 Requested Range Not Satisfiable
//417 Expectation Failed
//418 I'm a teapot
//421 Misdirected Request
//422 Unprocessable Entity
//423 Locked
//424 Failed Dependency
//426 Upgrade Required
//428 Precondition Required
//429 Too Many Requests
//431 Request Header Fields Too Large
//451 Unavailable For Legal Reasons
//499 Client Closed Request
//5×× Server Error
//500 Internal Server Error
//501 Not Implemented
//502 Bad Gateway
//503 Service Unavailable
//504 Gateway Timeout
//505 HTTP Version Not Supported
//506 Variant Also Negotiates
//507 Insufficient Storage
//508 Loop Detected
//510 Not Extended
//511 Network Authentication Required
//599 Network Connect Timeout Error
