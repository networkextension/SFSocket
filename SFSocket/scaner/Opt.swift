import Foundation

public struct Opt {
    public static var MAXNWTCPSocketReadDataSize = 15000
    //fuck iOS9 limit allco memory use
    public static var MAXNWTCPSocketReadDataSize9 = 1024*8
    // This is only used in finding the end of HTTP header (as of now). There is no limit on the length of http header, but Apache set it to 8KB
    public static var MAXNWTCPScanLength = 8912

    public static var DNSFakeIPTTL = 300

    public static var DNSPendingSessionLifeTime = 10

    public static var UDPSocketActiveTimeout = 60//300

    public static var UDPSocketActiveCheckInterval = 5

    public static var MAXHTTPContentBlockLength = 10240

    public static var RejectAdapterDefaultDelay = 300
}
