//
//  ContentView.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @AppStorage("showfmintabs") private var showfmintabs: Bool = true
    @ObservedObject private var mgr = laramgr.shared
    @State private var uid: uid_t = getuid()
    @State private var pid: pid_t = getpid()
    @State private var hasoffsets = haskernproc()
    @State private var showsettings = false
    @State private var showJbDetails = false
    
    var body: some View {
        NavigationStack {
            List {
                // === JAILBREAK STATUS ===
                Section {
                    HStack {
                        Image(systemName: jbStatusIcon)
                            .foregroundColor(jbStatusColor)
                            .font(.title2)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(mgr.jbStatus.statusText)
                                .font(.headline)
                            Text("\(mgr.jbStatus.passCount)/\(JailbreakStatus.totalChecks) checks pass")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button {
                            mgr.refreshJailbreakStatus()
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                    }
                    
                    if showJbDetails {
                        jbCheckRow("JB Root", check: mgr.jbStatus.hasJbRoot)
                        jbCheckRow("/var/jb Symlink", check: mgr.jbStatus.hasVarJb)
                        jbCheckRow("Sileo Installed", check: mgr.jbStatus.hasSileo)
                        jbCheckRow("dpkg Binary", check: mgr.jbStatus.hasDpkg)
                        jbCheckRow("Sandbox Escaped", check: mgr.jbStatus.sandboxEscaped)
                        jbCheckRow("Fork Test", check: mgr.jbStatus.canFork)
                        jbCheckRow("Kernel Exploit", check: mgr.jbStatus.kernelExploitActive)
                        jbCheckRow("dpkg Packages", check: mgr.jbStatus.dpkgPackageCount > 0,
                                   detail: mgr.jbStatus.dpkgPackageCount > 0 ? "\(mgr.jbStatus.dpkgPackageCount) pkgs" : nil)
                    }
                    
                    Button(showJbDetails ? "Hide Details" : "Show Details") {
                        withAnimation { showJbDetails.toggle() }
                    }
                    .font(.caption)
                    .foregroundColor(.accentColor)
                } header: {
                    Text("Jailbreak Status")
                }
                
                if !hasoffsets {
                    Section("Setup") {
                        Text("Kernelcache offsets are missing. Download them in Settings.")
                            .foregroundColor(.secondary)
                        Button("Open Settings") {
                            showsettings = true
                        }
                    }
                } else {
                    Section {
                        Button {
                            mgr.run()
                        } label: {
                            if mgr.dsrunning {
                                HStack {
                                    ProgressView(value: mgr.dsprogress)
                                        .progressViewStyle(.circular)
                                        .frame(width: 18, height: 18)
                                    Text("Running...")
                                    Spacer()
                                    Text("\(Int(mgr.dsprogress * 100))%")
                                }
                            } else {
                                if mgr.dsready {
                                    HStack {
                                        Text("Ran Exploit")
                                        Spacer()
                                        Image(systemName: "checkmark.circle")
                                            .foregroundColor(.green)
                                    }
                                } else if mgr.dsattempted && mgr.dsfailed {
                                    HStack {
                                        Text("Exploit Failed")
                                        Spacer()
                                        Image(systemName: "xmark.circle")
                                            .foregroundColor(.red)
                                    }
                                } else {
                                    Text("Run Exploit")
                                }
                            }
                        }
                        .disabled(mgr.dsrunning)
                        .disabled(mgr.dsready)
                        
                        HStack {
                            Text("kernproc:")
                            Spacer()
                            Text(String(format: "0x%llx", getrootvnode()))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        
                        HStack {
                            Text("rootvnode:")
                            Spacer()
                            Text(String(format: "0x%llx", getkernproc()))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        
                        if mgr.dsready {
                            HStack {
                                Text("kernel_base:")
                                Spacer()
                                Text(String(format: "0x%llx", mgr.kernbase))
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                            
                            HStack {
                                Text("kernel_slide:")
                                Spacer()
                                Text(String(format: "0x%llx", mgr.kernslide))
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                        }
                    } header: {
                        Text("Kernel Read Write")
                    } footer: {
                        if g_isunsupported {
                            Text("Your device/installation method may not be supported.")
                        }
                    }

                    Section("Virtual File System") {
                        Button {
                            mgr.vfsinit()
                        } label: {
                            if mgr.vfsrunning {
                                HStack {
                                    ProgressView(value: mgr.vfsprogress)
                                        .progressViewStyle(.circular)
                                        .frame(width: 18, height: 18)
                                    Text("Initialising VFS...")
                                    Spacer()
                                    Text("\(Int(mgr.vfsprogress * 100))%")
                                }
                            } else if !mgr.vfsready {
                                if mgr.vfsattempted && mgr.vfsfailed {
                                    HStack {
                                        Text("VFS Init Failed")
                                        Spacer()
                                        Image(systemName: "xmark.circle")
                                            .foregroundColor(.red)
                                    }
                                } else {
                                    Text("Initialise VFS")
                                }
                            } else {
                                HStack {
                                    Text("Initialised VFS")
                                    Spacer()
                                    Image(systemName: "checkmark.circle")
                                        .foregroundColor(.green)
                                }
                            }
                        }
                        .disabled(!mgr.dsready || mgr.vfsready || mgr.vfsrunning)
                        
                        if mgr.vfsready {
                            NavigationLink("Font Overwrite") {
                                FontPicker(mgr: mgr)
                            }
                            
                            NavigationLink("DirtyZero (Broken)") {
                                ZeroView(mgr: mgr)
                            }

                            if !showfmintabs {
                                NavigationLink("File Manager") {
                                    SantanderView(startPath: "/")
                                }
                            }
                            
                            if 1 == 2 {
                                NavigationLink("3 App Bypass") {
                                    AppsView(mgr: mgr)
                                }
                                
                                NavigationLink("Passcode Theme") {
                                    PasscodeView(mgr: mgr)
                                }
                                
                                NavigationLink("Unblacklist") {
                                    WhitelistView()
                                }

                                NavigationLink("MobileGestalt") {
                                    EditorView()
                                }
                            }
                        }
                        
                        HStack {
                            Text("UID:")
                            
                            Spacer()
                            
                            Text("\(uid)")
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                            
                            Button {
                                uid = getuid()
                                print(uid)
                            } label: {
                                Image(systemName: "arrow.clockwise")
                            }
                        }
                        
                        HStack {
                            Text("PID:")
                            
                            Spacer()
                            
                            Text("\(pid)")
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                            
                            Button {
                                pid = getpid()
                                print(pid)
                            } label: {
                                Image(systemName: "arrow.clockwise")
                            }
                        }
                    }
                    
                    Section {
                        NavigationLink("Tools") {
                            ToolsView()
                        }
                        
                        if #unavailable(iOS 18.2) {
                            Button("Respring") {
                                mgr.respring()
                            }
                        }
                        
                        Button("Panic!") {
                            mgr.panic()
                        }
                        .disabled(!mgr.dsready)
                        
                        if mgr.dsready {
                            Button {
                                mgr.fullEscalation()
                            } label: {
                                if mgr.elevated {
                                    HStack {
                                        Text("Elevated to Root")
                                        Spacer()
                                        Image(systemName: "checkmark.circle")
                                            .foregroundColor(.green)
                                    }
                                } else if mgr.sandboxBypassed {
                                    HStack {
                                        Text("Sandbox Bypassed (no root)")
                                        Spacer()
                                        Image(systemName: "exclamationmark.circle")
                                            .foregroundColor(.orange)
                                    }
                                } else {
                                    HStack {
                                        Image(systemName: "bolt.shield")
                                        Text("Escalate (Sandbox + CSFlags)")
                                    }
                                }
                            }
                            .disabled(mgr.elevated)
                            
                            Button {
                                mgr.createVarJb()
                            } label: {
                                HStack {
                                    Image(systemName: "folder.badge.plus")
                                    Text("Create JB Directories")
                                }
                            }
                            
                            NavigationLink {
                                RWFileManagerView(path: NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first ?? "/")
                            } label: {
                                HStack {
                                    Image(systemName: "doc.text.magnifyingglass")
                                    Text("File Manager")
                                }
                            }
                            
                            Button {
                                mgr.launchFilza()
                            } label: {
                                if mgr.filzaLaunched {
                                    HStack {
                                        Text("Filza Launched")
                                        Spacer()
                                        Image(systemName: "checkmark.circle")
                                            .foregroundColor(.green)
                                    }
                                } else {
                                    HStack {
                                        Image(systemName: "folder")
                                        Text("Launch Filza")
                                    }
                                }
                            }
                            
                            NavigationLink {
                                SandboxInfoView()
                            } label: {
                                HStack {
                                    Image(systemName: "lock.shield")
                                    Text("Sandbox Extensions")
                                }
                            }
                            
                            NavigationLink {
                                ProcessListView()
                            } label: {
                                HStack {
                                    Image(systemName: "list.number")
                                    Text("Kernel Processes")
                                }
                            }
                            
                            Button {
                                mgr.fullJailbreakFlow { success in
                                    if success {
                                        mgr.logmsg("Full jailbreak flow complete!")
                                    } else {
                                        mgr.logmsg("Full jailbreak flow failed.")
                                    }
                                }
                            } label: {
                                HStack {
                                    Image(systemName: "sparkles")
                                    Text("Full Jailbreak (Auto)")
                                }
                            }
                            .disabled(mgr.dsrunning)
                        }
                    } header: {
                        Text("Jailbreak")
                    }
                    
                    // === SSH / REMOTE ACCESS ===
                    if mgr.elevated {
                        Section {
                            HStack {
                                Image(systemName: "terminal")
                                    .foregroundColor(.cyan)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("SSH Connection")
                                        .font(.subheadline)
                                    Text(sshConnectString())
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundColor(.secondary)
                                        .textSelection(.enabled)
                                }
                                Spacer()
                                if mgr.sshRunning {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(.green)
                                }
                            }
                            
                            Button {
                                mgr.startSSH()
                            } label: {
                                if mgr.sshRunning {
                                    HStack {
                                        Text("SSH Running")
                                        Spacer()
                                        Image(systemName: "network")
                                            .foregroundColor(.green)
                                    }
                                } else {
                                    HStack {
                                        Image(systemName: "bolt.horizontal")
                                        Text("Start SSH  (port 22)")
                                    }
                                }
                            }
                            .disabled(mgr.sshRunning)
                        } header: {
                            Text("Remote Access")
                        } footer: {
                            Text("Connect with the password set during bootstrap. User: mobile.")
                        }
                    }
                }
                
            }
            .navigationTitle("lara")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showsettings = true
                    } label: {
                        Image(systemName: "gear")
                    }
                }
            }
            .onAppear {
                mgr.refreshJailbreakStatus()
            }
        }
        .sheet(isPresented: $showsettings) {
            SettingsView(hasoffsets: $hasoffsets)
        }
    }
    
    // MARK: - Jailbreak Status Helpers
    
    private var jbStatusIcon: String {
        if mgr.jbStatus.isSileoInstalled { return "checkmark.seal.fill" }
        if mgr.jbStatus.isBootstrapped { return "checkmark.circle.fill" }
        if mgr.jbStatus.isJailbroken { return "bolt.fill" }
        if mgr.jbStatus.kernelExploitActive { return "bolt.circle" }
        return "lock.fill"
    }
    
    private var jbStatusColor: Color {
        if mgr.jbStatus.isSileoInstalled { return .green }
        if mgr.jbStatus.isBootstrapped { return .green }
        if mgr.jbStatus.isJailbroken { return .orange }
        if mgr.jbStatus.kernelExploitActive { return .yellow }
        return .secondary
    }
    
    @ViewBuilder
    private func jbCheckRow(_ label: String, check: Bool, detail: String? = nil) -> some View {
        HStack {
            Image(systemName: check ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundColor(check ? .green : .red.opacity(0.5))
                .font(.caption)
            Text(label)
                .font(.subheadline)
            Spacer()
            if let detail = detail {
                Text(detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

