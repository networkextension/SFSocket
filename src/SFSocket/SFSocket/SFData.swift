//
//  SFData.swift
//  Surf
//
//  Created by 孔祥波 on 11/10/16.
//  Copyright © 2016 yarshure. All rights reserved.
//

import Foundation
protocol BinaryConvertible
{
    init()
}

//extension UInt8 : BinaryConvertible {}
extension UInt16 : BinaryConvertible {}
extension UInt32 : BinaryConvertible {}
extension UInt64 : BinaryConvertible {}
extension Double : BinaryConvertible {} //<T:BinaryConvertible>:
public struct SFData:CustomStringConvertible {
    public var data = Data()
    public var description: String {
        return (data as NSData).description
    }
//    mutating func append(_ v:T) {
//        var value = v
//        let storage = withUnsafePointer(to: &value) {
//            Data(bytes: UnsafePointer($0), count: MemoryLayout.size(ofValue: v))
//        }
//        data.append(storage)
//    }
    
    public mutating func append(_ v:UInt8){
        data.append(v)
    }
    public mutating func append(_ v:Data){
        data.append(v)
    }
    public mutating func append(_ v:UInt32) {
        var value = v
        let storage = withUnsafePointer(to: &value) {
            Data(bytes: UnsafePointer($0), count: MemoryLayout.size(ofValue: v))
        }
        data.append(storage)
    }
    public mutating func append(_ newElement: CChar) {
        
    }
    public mutating func append(_ v:String){
        let storage = v.data(using: .utf8)
        
        data.append(storage!)
    }
   public mutating  func append(_ v:UInt16) {
        var value = v
        let storage = withUnsafePointer(to: &value) {
            Data(bytes: UnsafePointer($0), count: MemoryLayout.size(ofValue: v))
        }
        data.append(storage)
    }
    public mutating func append(_ v:Int16) {
        var value = v
        let storage = withUnsafePointer(to: &value) {
            Data(bytes: UnsafePointer($0), count: MemoryLayout.size(ofValue: v))
        }
        data.append(storage)
    }
    public func length(_ r:Range<Data.Index>) ->Int {
        return r.upperBound - r.lowerBound
    }
}
