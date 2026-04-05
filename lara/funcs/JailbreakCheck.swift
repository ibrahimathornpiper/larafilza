//
//  JailbreakCheck.swift
//  lara
//
//  Multi-signal jailbreak detection — checks whether the device
//  is currently jailbroken (by Lara or another tool).
//

import Foundation
import Darwin

/// Comprehensive jailbreak status with individual check results
struct JailbreakStatus {
    /// Rootless jailbreak directory exists (/private/var/mobile/procursus)
    var hasJbRoot: Bool = false
    
    /// /var/jb symlink exists and is valid
    var hasVarJb: Bool = false
    
    /// Sileo.app is installed at jb path
    var hasSileo: Bool = false
    
    /// dpkg binary exists
    var hasDpkg: Bool = false
    
    /// Can write to /var/mobile (sandbox escaped)
    var sandboxEscaped: Bool = false
    
    /// fork() succeeds (unsandboxed)
    var canFork: Bool = false
    
    /// DYLD_INSERT_LIBRARIES is set (tweak injection active)
    var hasDyldInsert: Bool = false
    
    /// Kernel exploit primitives are active (ds_is_ready)
    var kernelExploitActive: Bool = false
    
    /// dpkg status file exists and has entries
    var dpkgPackageCount: Int = 0
    
    /// Summary: is device currently jailbroken?
    var isJailbroken: Bool {
        // Jailbroken if we have the JB root AND at least one escape method works
        return hasJbRoot && (sandboxEscaped || canFork || kernelExploitActive)
    }
    
    /// Summary: is bootstrap installed?
    var isBootstrapped: Bool {
        return hasJbRoot && hasDpkg && dpkgPackageCount > 0
    }
    
    /// Summary: is Sileo ready?
    var isSileoInstalled: Bool {
        return hasSileo && isBootstrapped
    }
    
    /// Human-readable overall status
    var statusText: String {
        if isSileoInstalled { return "Jailbroken (Sileo Installed)" }
        if isBootstrapped { return "Jailbroken (Bootstrap Only)" }
        if isJailbroken { return "Jailbroken (No Bootstrap)" }
        if kernelExploitActive { return "Exploit Active (Not Escaped)" }
        if hasJbRoot { return "JB Root Exists (Not Active)" }
        return "Not Jailbroken"
    }
    
    /// Number of checks that pass
    var passCount: Int {
        var c = 0
        if hasJbRoot { c += 1 }
        if hasVarJb { c += 1 }
        if hasSileo { c += 1 }
        if hasDpkg { c += 1 }
        if sandboxEscaped { c += 1 }
        if canFork { c += 1 }
        if kernelExploitActive { c += 1 }
        if dpkgPackageCount > 0 { c += 1 }
        return c
    }
    
    static let totalChecks = 8
}

/// Perform all jailbreak detection checks
func checkJailbreakStatus() -> JailbreakStatus {
    var status = JailbreakStatus()
    let fm = FileManager.default
    
    let jbRoot = "/private/var/mobile/procursus"
    
    // 1. Check JB root directory
    var isDir: ObjCBool = false
    status.hasJbRoot = fm.fileExists(atPath: jbRoot, isDirectory: &isDir) && isDir.boolValue
    
    // 2. Check /var/jb symlink
    let varJb = "/private/var/jb"
    if let dest = try? fm.destinationOfSymbolicLink(atPath: varJb) {
        status.hasVarJb = fm.fileExists(atPath: dest)
    } else {
        status.hasVarJb = fm.fileExists(atPath: varJb)
    }
    
    // 3. Check Sileo.app
    let sileoPaths = [
        "\(jbRoot)/Applications/Sileo.app",
        "\(jbRoot)/Applications/Sileo.app/Sileo",
        "/var/jb/Applications/Sileo.app"
    ]
    status.hasSileo = sileoPaths.contains { fm.fileExists(atPath: $0) }
    
    // 4. Check dpkg binary
    let dpkgPaths = [
        "\(jbRoot)/usr/bin/dpkg",
        "\(jbRoot)/bin/dpkg",
        "/var/jb/usr/bin/dpkg"
    ]
    status.hasDpkg = dpkgPaths.contains { fm.fileExists(atPath: $0) }
    
    // 5. Sandbox escape check — try writing to /var/mobile
    let testPath = "/var/mobile/.lara_jb_test_\(arc4random())"
    let fd = open(testPath, O_WRONLY | O_CREAT | O_TRUNC, 0644)
    if fd >= 0 {
        close(fd)
        unlink(testPath)
        status.sandboxEscaped = true
    }
    
    // 6. Process spawn check — sandboxed apps cannot spawn processes
    var spawnPid: pid_t = 0
    let argv: [UnsafeMutablePointer<CChar>?] = [
        strdup("/bin/sh"),
        strdup("-c"),
        strdup("true"),
        nil
    ]
    let spawnResult = posix_spawn(&spawnPid, "/bin/sh", nil, nil, argv, nil)
    argv.forEach { free($0) }
    if spawnResult == 0 && spawnPid > 0 {
        var exitStatus: Int32 = 0
        waitpid(spawnPid, &exitStatus, 0)
        status.canFork = true
    }
    // spawnResult != 0 means spawn failed (sandboxed) — canFork stays false
    
    // 7. DYLD_INSERT_LIBRARIES check
    if let dyld = getenv("DYLD_INSERT_LIBRARIES") {
        let val = String(cString: dyld)
        status.hasDyldInsert = !val.isEmpty
    }
    
    // 8. Kernel exploit check
    status.kernelExploitActive = ds_is_ready()
    
    // 9. dpkg status file — count installed packages
    let statusPaths = [
        "\(jbRoot)/Library/dpkg/status",
        "\(jbRoot)/var/lib/dpkg/status"
    ]
    for path in statusPaths {
        if let content = try? String(contentsOfFile: path, encoding: .utf8) {
            // Count "Package:" lines
            let pkgCount = content.components(separatedBy: "\n")
                .filter { $0.hasPrefix("Package:") }
                .count
            status.dpkgPackageCount = pkgCount
            break
        }
    }
    
    return status
}
