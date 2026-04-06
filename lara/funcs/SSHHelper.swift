//
//  SSHHelper.swift
//  lara
//
//  Created for SSH integration.
//

import Foundation
import Darwin

/// Returns the device's current Wi-Fi IPv4 address, or nil if unavailable.
func getWifiIPAddress() -> String? {
    var address: String?
    var ifaList: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaList) == 0 else { return nil }
    defer { freeifaddrs(ifaList) }

    var ptr = ifaList
    while let ifa = ptr {
        let name = String(cString: ifa.pointee.ifa_name)
        let family = ifa.pointee.ifa_addr.pointee.sa_family

        // en0 = Wi-Fi, AF_INET = IPv4
        if name == "en0", family == UInt8(AF_INET) {
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(
                ifa.pointee.ifa_addr,
                socklen_t(ifa.pointee.ifa_addr.pointee.sa_len),
                &hostname,
                socklen_t(hostname.count),
                nil, 0,
                NI_NUMERICHOST
            ) == 0 {
                address = String(cString: hostname)
            }
        }
        ptr = ifa.pointee.ifa_next
    }
    return address
}

/// Returns the SSH connection string for display, e.g. "ssh mobile@192.168.1.10"
func sshConnectString() -> String {
    if let ip = getWifiIPAddress() {
        return "ssh mobile@\(ip)"
    }
    return "ssh mobile@<device-ip>"
}
