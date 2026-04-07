//
//  laramgr.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import Combine
import Darwin
import Foundation
import SQLite3
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
    
    @Published var macfready: Bool = false
    @Published var macfattempted: Bool = false
    @Published var macffailed: Bool = false
    
    @Published var sbxExtEscaped: Bool = false
    
    @Published var jbStatus: JailbreakStatus = JailbreakStatus()
    
    @Published var sshRunning: Bool = false
    
    static let shared = laramgr()
    static let fontpath = "/System/Library/Fonts/Core/SFUI.ttf"
    static let jbRoot = "/private/var/mobile/procursus"
    private init() {}
    
    func run(completion: ((Bool) -> Void)? = nil) {
        guard !dsrunning else { return }
        // SAFETY: never re-run exploit if already succeeded — causes kernel panic
        if dsready && ds_is_ready() {
            logmsg("(ds) exploit already active, skipping re-run")
            completion?(true)
            return
        }
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
        // Crash-safe: also write to disk immediately (survives kernel panic)
        Self.appendLogToDisk(message)
    }

    // Write log line to Documents/lara_crash_log.txt (persists across panics)
    private static func appendLogToDisk(_ msg: String) {
        let docsDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first!
        let logPath = (docsDir as NSString).appendingPathComponent("lara_crash_log.txt")
        let line = msg + "\n"
        if let data = line.data(using: .utf8) {
            if FileManager.default.fileExists(atPath: logPath) {
                if let fh = FileHandle(forWritingAtPath: logPath) {
                    fh.seekToEndOfFile()
                    fh.write(data)
                    fh.synchronizeFile()
                    fh.closeFile()
                }
            } else {
                try? data.write(to: URL(fileURLWithPath: logPath))
            }
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
        let fm = FileManager.default

        // Invalidate icon cache so SpringBoard rebuilds it on restart
        let cacheDirs = [
            "/var/mobile/Library/Caches/com.apple.springboard.csstore",
            "/var/mobile/Library/Caches/com.apple.SpringBoard"
        ]
        for dir in cacheDirs {
            if fm.fileExists(atPath: dir) {
                try? fm.removeItem(atPath: dir)
            }
        }

        // Post registration notifications and give LaunchServices time to commit
        // IMPORTANT: sleep BEFORE killing SpringBoard so LS has time to write
        // the new app registration to its cache before SB restarts.
        notify_post("com.apple.mobile.application_installed")
        notify_post("com.apple.springboard.needsRefresh")
        Thread.sleep(forTimeInterval: 1.0)   // let LS commit registration

        // Kill SpringBoard — it will relaunch automatically
        let killResult = kill_process_by_name("SpringBoard")
        if killResult != 0 {
            // Fallback: userspace kill
            let killall = "/usr/bin/killall"
            if fm.fileExists(atPath: killall) {
                _ = spawnBinary(killall, args: ["-9", "SpringBoard"])
            } else {
                // Direct SIGKILL via Foundation
                if let pid = pidForProcessName("SpringBoard") {
                    Darwin.kill(pid, SIGKILL)
                }
            }
        }
    }

    /// Find the PID of a running process by name (userspace fallback)
    private func pidForProcessName(_ name: String) -> pid_t? {
        // Use sysctl to enumerate processes
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: size_t = 0
        sysctl(&mib, 4, nil, &size, nil, 0)
        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        sysctl(&mib, 4, &procs, &size, nil, 0)
        for p in procs {
            var pname = p.kp_proc.p_comm
            let procName = withUnsafeBytes(of: &pname) { buf -> String in
                String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
            }
            if procName == name { return p.kp_proc.p_pid }
        }
        return nil
    }

    /// Inject the app bundle URL directly into BackBoard's applicationState.db.
    /// This is the most reliable method on iOS 14+ rootless jailbreaks:
    /// SpringBoard reads this SQLite DB on launch to discover all user apps.
    /// The DB lives at /var/mobile/Library/BackBoard/applicationState.db.
    func injectIntoBBApplicationStateDB(bundlePath: String, bundleID: String) {
        let dbPath = "/var/mobile/Library/BackBoard/applicationState.db"
        guard FileManager.default.fileExists(atPath: dbPath) else {
            logmsg("(uicache) applicationState.db not found at \(dbPath)")
            return
        }

        // Open SQLite database
        var db: OpaquePointer?
        guard sqlite3_open(dbPath, &db) == SQLITE_OK, let db = db else {
            logmsg("(uicache) ❌ failed to open applicationState.db")
            return
        }
        defer { sqlite3_close(db) }

        // The schema used by BackBoard:
        //   CREATE TABLE IF NOT EXISTS application_state_internal (
        //     id INTEGER PRIMARY KEY,
        //     bundle_id TEXT NOT NULL UNIQUE,
        //     install_type INTEGER,
        //     path TEXT
        //   );
        // install_type 2 = user app; 1 = system app
        // Some iOS versions use a slightly different schema — we use INSERT OR REPLACE
        // to be safe, and fall back to a simpler INSERT.
        let bundleURL = "file://" + bundlePath + "/"

        let sql = """
            INSERT OR REPLACE INTO application_state_internal
            (bundle_id, install_type, path)
            VALUES (?, 2, ?);
            """
        let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt = stmt {
            sqlite3_bind_text(stmt, 1, bundleID, -1, sqliteTransient)
            sqlite3_bind_text(stmt, 2, bundleURL, -1, sqliteTransient)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            if rc == SQLITE_DONE {
                logmsg("(uicache) ✅ injected \(bundleID) into applicationState.db")
                return
            } else if let errMsg = sqlite3_errmsg(db) {
                logmsg("(uicache) ⚠️ applicationState.db step failed: \(String(cString: errMsg))")
            }
        } else if let errMsg = sqlite3_errmsg(db) {
            // Table schema may differ — log and continue
            logmsg("(uicache) ⚠️ applicationState.db prepare failed: \(String(cString: errMsg))")
        }
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

    // === MACF BYPASS ===
    
    func macfinit(completion: ((Bool) -> Void)? = nil) {
        macf_set_log_callback { msg in
            guard let msg = msg else { return }
            let s = String(cString: msg)
            DispatchQueue.main.async {
                laramgr.shared.logmsg("(macf) " + s)
            }
        }
        macfattempted = true
        macffailed = false
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let r = macf_init()
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.macfready = (r == 0 && macf_is_ready())
                if self.macfready {
                    self.macffailed = false
                    self.logmsg("\nmacf bypass ready!\n")
                } else {
                    self.macffailed = true
                    self.logmsg("\nmacf bypass init failed.\n")
                }
                completion?(self.macfready)
            }
        }
    }

    // === SANDBOX EXTENSION ESCAPE (from FilzaEscapedDS) ===
    
    func sandboxExtEscape() {
        sbx_ext_set_log { msg in
            guard let msg = msg else { return }
            let s = String(cString: msg)
            DispatchQueue.main.async {
                laramgr.shared.logmsg("(sbx-ext) " + s)
            }
        }
        
        logmsg("\n(sbx-ext) starting sandbox extension escape...")
        let result = sandbox_ext_escape()
        sbxExtEscaped = (result == 0 && sbx_ext_is_escaped())
        
        if sbxExtEscaped {
            logmsg("(sbx-ext) *** SANDBOX ESCAPED — full R+W access! ***\n")
        } else {
            logmsg("(sbx-ext) sandbox extension escape failed\n")
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
    @Published var elevated: Bool = false
    
    @discardableResult
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
    
    // Privilege escalation: sandbox null + csflags bypass
    // NOTE: On iOS 18, uid=0 (root) requires PPL bypass which is not available.
    // This function removes sandbox and patches csflags only.
    @discardableResult
    func fullEscalation(pid: pid_t? = nil) -> Bool {
        guard dsready else {
            logmsg("(elevate) exploit not ready")
            return false
        }
        
        let targetPid = pid ?? getpid()
        logmsg("(elevate) escalation for pid \(targetPid)...")
        logmsg("(elevate) NOTE: uid=0 not available on iOS 18 (PPL)")
        
        let result = elevate_to_root(targetPid)
        if result == 0 {
            self.sandboxBypassed = true
            self.elevated = true // sandbox removed + csflags patched
            logmsg("(elevate) SUCCESS: sandbox removed + csflags patched")
            return true
        } else {
            logmsg("(elevate) escalation failed for pid \(targetPid)")
            return sandboxBypass(pid: targetPid)
        }
    }
    
    // Create rootless jailbreak directory structure
    // Target: /private/var/mobile/procursus (we have R+W here after sandbox escape)
    // Symlink: /var/jb → /private/var/mobile/procursus
    @discardableResult
    func createVarJb() -> Bool {
        let fm = FileManager.default

        let jbRoot = Self.jbRoot
        let subdirs = ["bin", "lib", "etc", "var", "tmp", "usr",
                       "usr/bin", "usr/lib", "usr/local", "usr/libexec",
                       "Library", "Library/dpkg", "Library/dpkg/info",
                       "Applications", "basebin"]

        logmsg("(jb) creating rootless jailbreak at \(jbRoot)...")

        if sbxExtEscaped {
            // Primary: sandbox escaped — direct write to /private/var/mobile
            do {
                if !fm.fileExists(atPath: jbRoot) {
                    try fm.createDirectory(atPath: jbRoot, withIntermediateDirectories: true)
                }
                logmsg("(jb) ✅ \(jbRoot) CREATED!")

                for sub in subdirs {
                    let subPath = (jbRoot as NSString).appendingPathComponent(sub)
                    if !fm.fileExists(atPath: subPath) {
                        try fm.createDirectory(atPath: subPath, withIntermediateDirectories: true)
                    }
                }
                logmsg("(jb) directory structure ready")

                // Note: /var/jb symlink/directory cannot be created on iOS 18
                // (MACF blocks writes to /private/var/ even with sandbox escape).
                // The jailbreak check treats the procursus root itself as the
                // /var/jb equivalent — all paths use jbRoot directly.

                return true
            } catch {
                logmsg("(jb) ❌ failed to create \(jbRoot): \(error.localizedDescription)")
                return false
            }
        } else {
            // Fallback: local container directory
            let docsDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first!
            let localJbPath = (docsDir as NSString).appendingPathComponent("jb")
            logmsg("(jb) sandbox not escaped — using local path: \(localJbPath)")
            do {
                try fm.createDirectory(atPath: localJbPath, withIntermediateDirectories: true)
                for sub in subdirs {
                    let subPath = (localJbPath as NSString).appendingPathComponent(sub)
                    if !fm.fileExists(atPath: subPath) {
                        try? fm.createDirectory(atPath: subPath, withIntermediateDirectories: true)
                    }
                }
            } catch {
                logmsg("(jb) local jb also failed: \(error.localizedDescription)")
                return false
            }
            return true
        }
    }
    
    func launchFilza() -> Bool {
        logmsg("(filza) launching Filza File Manager...")
        
        // Try global kernel sandbox bypass first
        logmsg("(filza) applying global kernel sandbox bypass...")
        let globalResult = global_sandbox_bypass()
        if globalResult == 0 {
            logmsg("(filza) global sandbox bypass SUCCESS")
        } else {
            logmsg("(filza) global sandbox bypass failed (kernel text likely PPL-protected)")
            logmsg("(filza) will apply per-process bypass after launch...")
        }
        
        // Launch Filza first
        var launched = false
        
        // Try LSApplicationWorkspace openURL:
        if let wsClass = NSClassFromString("LSApplicationWorkspace") {
            let ws = (wsClass as AnyObject).value(forKey: "defaultWorkspace")
                ?? (wsClass as AnyObject).value(forKey: "sharedWorkspace")
            
            if let ws = ws as? NSObject {
                let openSel = NSSelectorFromString("openURL:")
                if ws.responds(to: openSel),
                   let url = URL(string: "filza://") {
                    _ = ws.perform(openSel, with: url)
                    logmsg("(filza) openURL: called on LSApplicationWorkspace")
                    launched = true
                }
            }
        }
        
        // Fallback: try UIApplication openURL:
        if !launched {
            if let appClass = NSClassFromString("UIApplication") {
                if let shared = (appClass as AnyObject).value(forKey: "sharedApplication") as? NSObject {
                    let openSel = NSSelectorFromString("openURL:")
                    if shared.responds(to: openSel),
                       let url = URL(string: "filza://") {
                        _ = shared.perform(openSel, with: url)
                        logmsg("(filza) openURL: called on UIApplication")
                        launched = true
                    }
                }
            }
        }
        
        guard launched else {
            logmsg("(filza) all launch methods failed")
            return false
        }
        
        // Apply per-process privilege escalation to Filza
        // (sandbox null + ucred steal for root access)
        logmsg("(filza) applying full privilege escalation to Filza...")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // Wait for Filza to launch and appear in proc list
            usleep(1_500_000) // 1.5 seconds
            
            // Try common Filza process names
            let filzaNames = ["Filza", "FilzaFileManager", "filza"]
            var elevated = false
            
            for name in filzaNames {
                let result = elevate_to_root_by_name(name)
                if result == 0 {
                    DispatchQueue.main.async {
                        self?.logmsg("(filza) full privilege escalation SUCCESS for \(name)")
                        self?.logmsg("(filza) \(name) now has uid=0 (root) + no sandbox")
                    }
                    elevated = true
                    break
                }
            }
            
            if !elevated {
                DispatchQueue.main.async {
                    self?.logmsg("(filza) WARNING: privilege escalation failed for Filza")
                    self?.logmsg("(filza) Filza may have limited file access")
                }
            }
        }
        
        self.filzaLaunched = true
        return true
    }
    
    /// Install a .deb file to the jailbreak root with dpkg metadata registration
    func installDebToSystem(debURL: URL, completion: @escaping (Bool) -> Void) {
        let targetDir = Self.jbRoot
        
        DispatchQueue.global(qos: .userInitiated).async {
            self.logmsg("(deb) installing \(debURL.lastPathComponent)...")
            
            // Use full extraction — gets both data files and control metadata
            // Procursus rootless debs use ./var/jb/ prefix in data.tar
            let result = Extractor.extractDebFull(fileURL: debURL, destPath: targetDir, stripPrefix: "./var/jb/")
            
            guard result.dataOK else {
                self.logmsg("(deb) ❌ data extraction failed for \(debURL.lastPathComponent)")
                DispatchQueue.main.async { completion(false) }
                return
            }
            self.logmsg("(deb) ✅ files extracted to \(targetDir)")
            
            // Register in dpkg if we have control info
            if let controlInfo = result.controlInfo {
                self.registerDpkgPackage(controlInfo: controlInfo)
            } else {
                self.logmsg("(deb) ⚠️ no control info found, skipping dpkg registration")
            }
            
            DispatchQueue.main.async {
                self.refreshJailbreakStatus()
                completion(true)
            }
        }
    }
    
    /// Register a package in dpkg status file
    private func registerDpkgPackage(controlInfo: String) {
        let fm = FileManager.default
        let dpkgDir = (Self.jbRoot as NSString).appendingPathComponent("Library/dpkg")
        let statusPath = (dpkgDir as NSString).appendingPathComponent("status")
        let infoDir = (dpkgDir as NSString).appendingPathComponent("info")
        
        // Ensure dpkg directories exist
        try? fm.createDirectory(atPath: dpkgDir, withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: infoDir, withIntermediateDirectories: true)
        
        // Parse package name from control info
        var packageName = "unknown"
        for line in controlInfo.components(separatedBy: "\n") {
            if line.hasPrefix("Package:") {
                packageName = line.replacingOccurrences(of: "Package:", with: "").trimmingCharacters(in: .whitespaces)
                break
            }
        }
        
        // Build dpkg status entry — add "Status: install ok installed"
        var statusEntry = ""
        var hasStatus = false
        for line in controlInfo.components(separatedBy: "\n") {
            if line.hasPrefix("Status:") {
                hasStatus = true
            }
            statusEntry += line + "\n"
        }
        if !hasStatus {
            // Insert Status line after Package line
            statusEntry = controlInfo.components(separatedBy: "\n").map { line -> String in
                if line.hasPrefix("Package:") {
                    return line + "\nStatus: install ok installed"
                }
                return line
            }.joined(separator: "\n")
        }
        
        // Ensure entry ends with double newline (dpkg format)
        statusEntry = statusEntry.trimmingCharacters(in: .whitespacesAndNewlines) + "\n\n"
        
        // Append to status file
        if fm.fileExists(atPath: statusPath) {
            if let fh = FileHandle(forWritingAtPath: statusPath) {
                fh.seekToEndOfFile()
                if let data = statusEntry.data(using: .utf8) {
                    fh.write(data)
                }
                fh.synchronizeFile()
                fh.closeFile()
                logmsg("(dpkg) appended \(packageName) to status file")
            }
        } else {
            try? statusEntry.write(toFile: statusPath, atomically: true, encoding: .utf8)
            logmsg("(dpkg) created status file with \(packageName)")
        }
        
        // Write control file to dpkg info directory
        let controlPath = (infoDir as NSString).appendingPathComponent("\(packageName).control")
        try? controlInfo.write(toFile: controlPath, atomically: true, encoding: .utf8)
        
        // Write empty list file (dpkg requires it)
        let listPath = (infoDir as NSString).appendingPathComponent("\(packageName).list")
        if !fm.fileExists(atPath: listPath) {
            try? "".write(toFile: listPath, atomically: true, encoding: .utf8)
        }
        
        logmsg("(dpkg) ✅ registered package: \(packageName)")
    }
    
    func deployBootstrap(completion: @escaping (Bool) -> Void) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let bsURL = URL(string: "https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst")!
        let bsDest = docs.appendingPathComponent("bootstrap.tar.zst")
        let bsTar = docs.appendingPathComponent("bootstrap.tar")
        
        let sileoURL = URL(string: "https://github.com/Sileo/Sileo/releases/download/2.5.1/org.coolstar.sileo_2.5.1_iphoneos-arm64.deb")!
        let sileoDest = docs.appendingPathComponent("sileo.deb")
        
        let targetDir = Self.jbRoot
        
        self.logmsg("(jb) downloading bootstrap...")
        Extractor.downloadFile(url: bsURL, destURL: bsDest) { success in
            guard success else {
                self.logmsg("(jb) bootstrap download failed")
                completion(false)
                return
            }
            self.logmsg("(jb) downloaded bootstrap. decompressing zstd...")
            
            DispatchQueue.global(qos: .userInitiated).async {
                guard Extractor.decompressZSTD(src: bsDest, dst: bsTar) else {
                    self.logmsg("(jb) zstd decompression failed")
                    DispatchQueue.main.async { completion(false) }
                    return
                }
                
                self.logmsg("(jb) zstd decompressed. untarring to \(targetDir)...")
                guard let tarData = try? Data(contentsOf: bsTar) else {
                    self.logmsg("(jb) failed to read tar")
                    DispatchQueue.main.async { completion(false) }
                    return
                }
                
                let extractOK = Extractor.extractTar(data: tarData, destPath: targetDir, stripPrefix: "./var/jb/")
                if extractOK {
                    self.logmsg("(jb) ✅ bootstrap extracted!")
                    
                    // Run prep_bootstrap.sh if it exists
                    let prepScript = (targetDir as NSString).appendingPathComponent("prep_bootstrap.sh")
                    let jbSh = (targetDir as NSString).appendingPathComponent("bin/sh")
                    if FileManager.default.fileExists(atPath: prepScript) {
                        // Make script executable
                        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: prepScript)
                        if FileManager.default.fileExists(atPath: jbSh) {
                            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: jbSh)
                            self.logmsg("(jb) running prep_bootstrap.sh...")
                            // Pass NO_PASSWORD_PROMPT=1 to skip uialert (can't show from background spawn)
                            // Pass PATH so procursus binaries are found
                            let cmd = "NO_PASSWORD_PROMPT=1 PATH=\(targetDir)/usr/bin:\(targetDir)/bin:/usr/bin:/bin \(prepScript)"
                            let ret = self.spawnBinary(jbSh, args: ["-c", cmd])
                            self.logmsg("(jb) prep_bootstrap.sh exited with code \(ret)")
                        } else {
                            self.logmsg("(jb) ⚠️ bin/sh not found at \(jbSh) — skipping prep_bootstrap.sh")
                        }
                    }
                } else {
                    self.logmsg("(jb) ❌ bootstrap extraction failed")
                    DispatchQueue.main.async { completion(false) }
                    return
                }
                
                // Download and install Sileo deb properly
                self.logmsg("(jb) downloading sileo...")
                Extractor.downloadFile(url: sileoURL, destURL: sileoDest) { sSuccess in
                    guard sSuccess else {
                        self.logmsg("(jb) sileo download failed")
                        completion(false)
                        return
                    }
                    self.logmsg("(jb) sileo downloaded. installing deb...")
                    
                    // Use proper deb installer with dpkg registration
                    self.installDebToSystem(debURL: sileoDest) { installOK in
                        if installOK {
                            self.logmsg("(jb) ✅ sileo installed!")
                            
                            // Register Sileo.app bundle path directly — no symlink needed
                            let sileoBundlePath = (Self.jbRoot as NSString).appendingPathComponent("Applications/Sileo.app")
                            
                            // Register Sileo with SpringBoard
                            self.registerAppWithSpringBoard(bundlePath: sileoBundlePath)
                            
                            // Scan and register ALL apps in the jailbreak Applications directory
                            self.uicacheAll()
                        } else {
                            self.logmsg("(jb) ❌ sileo deb install failed")
                            DispatchQueue.main.async { completion(false) }
                            return
                        }
                        
                        // === Install OpenSSH ===
                        let opensshURL = URL(string: "https://apt.procurs.us/pool/main/o/openssh/openssh_9.7p1-1_iphoneos-arm64.deb")!
                        let opensshDest = docs.appendingPathComponent("openssh.deb")
                        self.logmsg("(jb) downloading openssh...")
                        Extractor.downloadFile(url: opensshURL, destURL: opensshDest) { dlOK in
                            if dlOK {
                                self.logmsg("(jb) openssh downloaded. installing deb...")
                                self.installDebToSystem(debURL: opensshDest) { sshOK in
                                    if sshOK {
                                        self.logmsg("(jb) ✅ openssh installed! rootless jailbreak complete.")
                                    } else {
                                        self.logmsg("(jb) ⚠️ openssh install failed (SSH wont work)")
                                    }
                                    
                                    // Trigger respring so SpringBoard picks up the new apps
                                    self.respring()
                                    
                                    DispatchQueue.main.async { completion(sshOK || installOK) }
                                }
                            } else {
                                self.logmsg("(jb) ⚠️ openssh download failed (SSH wont work, jailbreak still ok)")
                                
                                // Still respring even if openssh download failed
                                self.respring()
                                
                                DispatchQueue.main.async { completion(installOK) }
                            }
                        }
                    }
                }
            }
        }
    }
    
    func fullJailbreakFlow(completion: ((Bool) -> Void)? = nil) {
        let docsDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first!
        let crashLog = (docsDir as NSString).appendingPathComponent("lara_crash_log.txt")
        try? "=== JB FLOW ===\n".write(toFile: crashLog, atomically: true, encoding: .utf8)

        logmsg("(flow) step 1: exploit...")
        run { exploitSuccess in
            guard exploitSuccess else {
                self.logmsg("(flow) exploit FAILED")
                completion?(false)
                return
            }
            self.logmsg("(flow) exploit OK — running sandbox escape IMMEDIATELY...")

            self.sandboxExtEscape()
            self.logmsg("(flow) escape result: \(self.sbxExtEscaped)")

            if self.sbxExtEscaped {
                // Initialize VFS (kernel filesystem access) before creating dirs
                self.logmsg("(flow) initializing VFS...")
                vfs_init()
                if vfs_isready() {
                    self.logmsg("(flow) VFS ready!")
                } else {
                    self.logmsg("(flow) VFS init failed — vnode redirect won't be available")
                }
                
                self.logmsg("(flow) creating jb dirs...")
                DispatchQueue.main.async {
                    self.createVarJb()
                    self.deployBootstrap { success in
                        self.refreshJailbreakStatus()
                        self.logmsg("(flow) Full Jailbreak DONE!")
                        completion?(success)
                    }
                }
            } else {
                self.logmsg("(flow) escape failed")
                completion?(false)
            }
        }
    }
    
    // === JAILBREAK STATUS ===
    
    func refreshJailbreakStatus() {
        let status = checkJailbreakStatus()
        DispatchQueue.main.async {
            self.jbStatus = status
            self.logmsg("(jb-check) status: \(status.statusText) (\(status.passCount)/\(JailbreakStatus.totalChecks) checks pass)")
        }
    }
    
    // === App Registration ===

    /// Register an app bundle with SpringBoard so it appears on the home screen.
    /// Uses (in priority order):
    ///   1. uicache bootstrap binary
    ///   2. _LSRegisterURL via dlsym into MobileInstallation (what uicache does internally)
    ///   3. LSApplicationWorkspace -_LSRegisterURL: selector
    ///   4. Fallback notification hints
    func registerAppWithSpringBoard(bundlePath: String) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: bundlePath) else {
            logmsg("(uicache) app bundle not found: \(bundlePath)")
            return
        }

        logmsg("(uicache) registering \(bundlePath) with SpringBoard...")

        // Read bundle ID from Info.plist (needed by all methods)
        let bundleURL = URL(fileURLWithPath: bundlePath)
        let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
        let bundleID: String
        if let info = NSDictionary(contentsOf: infoPlistURL),
           let bid = info["CFBundleIdentifier"] as? String {
            bundleID = bid
        } else {
            logmsg("(uicache) ⚠️ can't read bundle ID — will skip bundle-ID methods")
            bundleID = ""
        }

        // ── Method 1: uicache binary from bootstrap ──────────────────────────
        let uicachePath = (Self.jbRoot as NSString).appendingPathComponent("usr/bin/uicache")
        if fm.fileExists(atPath: uicachePath) {
            try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: uicachePath)
            let ret = spawnBinary(uicachePath, args: ["-p", bundlePath])
            logmsg("(uicache) uicache -p returned \(ret)")
            if ret == 0 {
                notify_post("com.apple.mobile.application_installed")
                return
            }
        }

        // ── Method 2: _LSRegisterURL via dlsym (MobileInstallation framework) ───
        // This is what the uicache binary does internally on iOS 14+.
        // The private symbol `_LSRegisterURL` lives in the LaunchServices/
        // MobileInstallation shared library loaded into every process.
        logmsg("(uicache) using LSApplicationWorkspace API...")

        // Build the file:// URL that LaunchServices expects
        let appFileURL = URL(fileURLWithPath: bundlePath, isDirectory: true) as NSURL

        // Try _LSRegisterURL via selector on workspace (bridged in-process)
        if let lsClass = NSClassFromString("LSApplicationWorkspace") as? NSObject.Type {
            let dwSel = NSSelectorFromString("defaultWorkspace")
            if lsClass.responds(to: dwSel),
               let wsObj = lsClass.perform(dwSel)?.takeUnretainedValue() as? NSObject {

                // iOS 14+ correct registration method: -_LSRegisterURL:withOptions:
                let regURLSel = NSSelectorFromString("_LSRegisterURL:withOptions:")
                if wsObj.responds(to: regURLSel) {
                    let options: NSDictionary = [
                        "LSInstallType": 2, // LSApplicationTypeUser in LS enum
                        "ApplicationDSID": 0,
                        "IsAdHocSigned": true,
                        "CFBundleIdentifier": bundleID
                    ]
                    _ = wsObj.perform(regURLSel, with: appFileURL, with: options)
                    logmsg("(uicache) ✅ registered \(bundleID) via _LSRegisterURL:withOptions:")
                    notify_post("com.apple.mobile.application_installed")
                    logmsg("(uicache) posted application_installed notification to SpringBoard")
                    return
                }

                // Older fallback: -_LSRegisterURL:
                let regURLSel2 = NSSelectorFromString("_LSRegisterURL:")
                if wsObj.responds(to: regURLSel2) {
                    _ = wsObj.perform(regURLSel2, with: appFileURL)
                    logmsg("(uicache) ✅ registered \(bundleID) via _LSRegisterURL:")
                    notify_post("com.apple.mobile.application_installed")
                    logmsg("(uicache) posted application_installed notification to SpringBoard")
                    return
                }

                // Last-resort: registerApplicationDictionary (deprecated, may be no-op on iOS 15+)
                let dictSel = NSSelectorFromString("registerApplicationDictionary:")
                if wsObj.responds(to: dictSel) {
                    let appDict: NSDictionary = [
                        "ApplicationType": "User",
                        "CFBundleIdentifier": bundleID,
                        "Path": bundlePath,
                        "IsDeletable": false,
                        "IsAdHocSigned": true
                    ]
                    _ = wsObj.perform(dictSel, with: appDict)
                    logmsg("(uicache) ✅ registered \(bundleID) via registerApplicationDictionary:")
                } else {
                    logmsg("(uicache) ❌ no LSApplicationWorkspace registration selector responded")
                }
            } else {
                logmsg("(uicache) ❌ couldn't get defaultWorkspace")
            }
        } else {
            logmsg("(uicache) ❌ LSApplicationWorkspace class not available")
        }

        // ── Method 3: Direct applicationState.db injection (most reliable on iOS 14+) ──
        // _LSRegisterURL needs entitlements we don't have. Writing directly into
        // BackBoard's SQLite database is always read by SpringBoard on relaunch.
        if !bundleID.isEmpty {
            injectIntoBBApplicationStateDB(bundlePath: bundlePath, bundleID: bundleID)
        }

        notify_post("com.apple.mobile.application_installed")
        logmsg("(uicache) posted application_installed notification to SpringBoard")
    }

    /// Scan all .app bundles in the jailbreak Applications directory and register each with SpringBoard.
    /// Posts a single SpringBoard refresh notification after all apps are registered.
    func uicacheAll() {
        let appsDir = (Self.jbRoot as NSString).appendingPathComponent("Applications")
        let fm = FileManager.default
        guard let appBundles = try? fm.contentsOfDirectory(atPath: appsDir) else {
            logmsg("(uicache) ❌ cannot list \(appsDir)")
            return
        }

        logmsg("(uicache) scanning \(appsDir) for .app bundles...")
        var registered = 0
        for entry in appBundles where entry.hasSuffix(".app") {
            let bundlePath = (appsDir as NSString).appendingPathComponent(entry)
            registerAppWithSpringBoard(bundlePath: bundlePath)
            registered += 1
        }
        logmsg("(uicache) ✅ registered \(registered) app(s)")
    }
    
    // === SSH ===
    
    /// Spawn a binary using posix_spawn (iOS-compatible, no Foundation.Process)
    @discardableResult
    private func spawnBinary(_ path: String, args: [String]) -> Int32 {
        let cPath = strdup(path)
        defer { free(cPath) }
        
        // Build null-terminated argv array: [path, arg1, arg2, ..., nil]
        var cArgs: [UnsafeMutablePointer<CChar>?] = [cPath]
        let duped = args.map { strdup($0) }
        cArgs.append(contentsOf: duped.map { $0 as UnsafeMutablePointer<CChar>? })
        cArgs.append(nil)
        defer { duped.forEach { free($0) } }
        
        var pid: pid_t = 0
        let status = posix_spawn(&pid, path, nil, nil, &cArgs, nil)
        if status != 0 {
            return status
        }
        
        // Wait for child to finish
        var exitStatus: Int32 = 0
        waitpid(pid, &exitStatus, 0)
        return exitStatus
    }
    
    /// Start sshd from the procursus bootstrap.
    func startSSH() {
        let sshd = "\(Self.jbRoot)/usr/sbin/sshd"
        let keygen = "\(Self.jbRoot)/usr/bin/ssh-keygen"
        let etcSSH = "\(Self.jbRoot)/etc/ssh"
        let sshdConfig = "\(etcSSH)/sshd_config"
        
        guard FileManager.default.fileExists(atPath: sshd) else {
            logmsg("(ssh) sshd not found at \(sshd) — install openssh first via Full Jailbreak")
            return
        }
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Ensure etc/ssh directory exists
            try? FileManager.default.createDirectory(atPath: etcSSH, withIntermediateDirectories: true)
            
            // Generate host keys if missing
            let keyTypes = ["rsa", "ecdsa", "ed25519"]
            for ktype in keyTypes {
                let keyPath = "\(etcSSH)/ssh_host_\(ktype)_key"
                if !FileManager.default.fileExists(atPath: keyPath) {
                    self.logmsg("(ssh) generating \(ktype) host key...")
                    let r = self.spawnBinary(keygen, args: ["-t", ktype, "-f", keyPath, "-N", ""])
                    if r != 0 {
                        self.logmsg("(ssh) ⚠️ keygen for \(ktype) returned \(r)")
                    }
                }
            }
            
            // Launch sshd via posix_spawn (non-blocking — we don't waitpid so it stays running)
            let cPath = strdup(sshd)
            defer { free(cPath) }
            
            var argv: [UnsafeMutablePointer<CChar>?] = [cPath]
            let sshdArgs: [String]
            if FileManager.default.fileExists(atPath: sshdConfig) {
                sshdArgs = ["-f", sshdConfig, "-p", "22"]
            } else {
                sshdArgs = ["-p", "22"]
            }
            let duped = sshdArgs.map { strdup($0) }
            argv.append(contentsOf: duped.map { $0 as UnsafeMutablePointer<CChar>? })
            argv.append(nil)
            defer { duped.forEach { free($0) } }
            
            var pid: pid_t = 0
            let spawnResult = posix_spawn(&pid, sshd, nil, nil, &argv, nil)
            
            if spawnResult == 0 {
                DispatchQueue.main.async {
                    self.sshRunning = true
                    self.logmsg("(ssh) ✅ sshd started (pid \(pid)) on port 22")
                    if let ip = getWifiIPAddress() {
                        self.logmsg("(ssh) connect: ssh mobile@\(ip)")
                    }
                }
            } else {
                DispatchQueue.main.async {
                    self.logmsg("(ssh) ❌ posix_spawn failed with code \(spawnResult)")
                }
            }
        }
    }

}

