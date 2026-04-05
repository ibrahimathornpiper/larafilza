//
//  SandboxInfoView.swift
//  lara
//
//  Displays sandbox extension tokens with copy functionality
//

import SwiftUI

struct SandboxToken: Identifiable, Hashable {
    let id = UUID()
    let token: String
    let address: UInt64
}

struct SandboxInfo {
    let procAddr: UInt64
    let sandboxPtr: UInt64
    let containerAddr: UInt64
    let containerPath: String
    let profileName: String
    let tokens: [SandboxToken]
    let hasSandbox: Bool
}

struct SandboxInfoView: View {
    @ObservedObject private var mgr = laramgr.shared
    @State private var targetPid: String = ""
    @State private var targetName: String = ""
    @State private var sandboxInfo: SandboxInfo?
    @State private var isLoading = false
    @State private var errorMsg: String?
    @State private var copiedToken: UUID?
    @State private var copiedAll = false
    @State private var useNameMode = false
    
    var body: some View {
        List {
            Section {
                Picker("Look up by", selection: $useNameMode) {
                    Text("PID").tag(false)
                    Text("Name").tag(true)
                }
                .pickerStyle(.segmented)
                
                if useNameMode {
                    HStack {
                        TextField("Process name (e.g. Filza)", text: $targetName)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        
                        Button {
                            loadByName()
                        } label: {
                            if isLoading {
                                ProgressView()
                                    .frame(width: 20, height: 20)
                            } else {
                                Image(systemName: "magnifyingglass")
                            }
                        }
                        .disabled(targetName.isEmpty || isLoading || !mgr.dsready)
                    }
                } else {
                    HStack {
                        TextField("PID", text: $targetPid)
                            .keyboardType(.numberPad)
                        
                        Button("Self") {
                            targetPid = "\(getpid())"
                        }
                        .font(.caption)
                        .buttonStyle(.bordered)
                        
                        Button {
                            loadByPid()
                        } label: {
                            if isLoading {
                                ProgressView()
                                    .frame(width: 20, height: 20)
                            } else {
                                Image(systemName: "magnifyingglass")
                            }
                        }
                        .disabled(targetPid.isEmpty || isLoading || !mgr.dsready)
                    }
                }
            } header: {
                Text("Target Process")
            } footer: {
                if !mgr.dsready {
                    Text("Run exploit first to enable sandbox reading.")
                        .foregroundColor(.red)
                }
            }
            
            if let error = errorMsg {
                Section("Error") {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.system(.caption, design: .monospaced))
                }
            }
            
            if let info = sandboxInfo {
                Section("Process Info") {
                    InfoRow(label: "proc", value: String(format: "0x%llx", info.procAddr))
                    InfoRow(label: "p_sandbox", value: info.hasSandbox
                            ? String(format: "0x%llx", info.sandboxPtr)
                            : "NULL (no sandbox)")
                    
                    if !info.containerPath.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Container Path")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(info.containerPath)
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        .contextMenu {
                            Button {
                                UIPasteboard.general.string = info.containerPath
                            } label: {
                                Label("Copy Path", systemImage: "doc.on.doc")
                            }
                        }
                    }
                    
                    if !info.profileName.isEmpty {
                        InfoRow(label: "Profile", value: info.profileName)
                    }
                }
                
                Section {
                    if info.tokens.isEmpty {
                        if info.hasSandbox {
                            Text("No extension tokens found (structure may differ on this iOS version)")
                                .foregroundColor(.secondary)
                                .font(.caption)
                        } else {
                            Text("Process has no sandbox — no extensions to show")
                                .foregroundColor(.secondary)
                                .font(.caption)
                        }
                    } else {
                        ForEach(info.tokens) { token in
                            TokenRow(token: token,
                                     isCopied: copiedToken == token.id,
                                     onCopy: {
                                UIPasteboard.general.string = token.token
                                withAnimation {
                                    copiedToken = token.id
                                }
                                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                                    withAnimation {
                                        if copiedToken == token.id {
                                            copiedToken = nil
                                        }
                                    }
                                }
                            })
                        }
                    }
                } header: {
                    HStack {
                        Text("Extension Tokens (\(info.tokens.count))")
                        Spacer()
                        if !info.tokens.isEmpty {
                            Button {
                                copyAll()
                            } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: copiedAll ? "checkmark" : "doc.on.doc")
                                    Text(copiedAll ? "Copied!" : "Copy All")
                                }
                                .font(.caption)
                            }
                        }
                    }
                }
                
                if info.hasSandbox {
                    Section {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Raw Sandbox Label")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(String(format: "0x%llx", info.sandboxPtr))
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        .contextMenu {
                            Button {
                                UIPasteboard.general.string = String(format: "0x%llx", info.sandboxPtr)
                            } label: {
                                Label("Copy Address", systemImage: "doc.on.doc")
                            }
                        }
                    } header: {
                        Text("Debug")
                    }
                }
            }
        }
        .navigationTitle("Sandbox Extensions")
        .onAppear {
            targetPid = "\(getpid())"
        }
    }
    
    private func loadByPid() {
        guard let pid = Int32(targetPid) else {
            errorMsg = "Invalid PID"
            return
        }
        isLoading = true
        errorMsg = nil
        sandboxInfo = nil
        copiedToken = nil
        copiedAll = false
        
        DispatchQueue.global(qos: .userInitiated).async {
            let result = readSandboxInfo(pid: pid)
            DispatchQueue.main.async {
                self.sandboxInfo = result.info
                self.errorMsg = result.error
                self.isLoading = false
            }
        }
    }
    
    private func loadByName() {
        isLoading = true
        errorMsg = nil
        sandboxInfo = nil
        copiedToken = nil
        copiedAll = false
        
        DispatchQueue.global(qos: .userInitiated).async {
            let result = readSandboxInfoByName(name: targetName)
            DispatchQueue.main.async {
                self.sandboxInfo = result.info
                self.errorMsg = result.error
                self.isLoading = false
            }
        }
    }
    
    private func copyAll() {
        guard let info = sandboxInfo else { return }
        
        var text = "Sandbox Extension Tokens\n"
        text += "========================\n"
        text += String(format: "proc: 0x%llx\n", info.procAddr)
        text += String(format: "p_sandbox: 0x%llx\n", info.sandboxPtr)
        
        if !info.containerPath.isEmpty {
            text += "container: \(info.containerPath)\n"
        }
        if !info.profileName.isEmpty {
            text += "profile: \(info.profileName)\n"
        }
        
        text += "\nTokens (\(info.tokens.count)):\n"
        for (i, token) in info.tokens.enumerated() {
            text += "  [\(i)] \(token.token)\n"
            text += "       @ \(String(format: "0x%llx", token.address))\n"
        }
        
        UIPasteboard.general.string = text
        withAnimation { copiedAll = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            withAnimation { copiedAll = false }
        }
    }
    
    // MARK: - Kernel Reading
    
    private func readSandboxInfo(pid: pid_t) -> (info: SandboxInfo?, error: String?) {
        guard let rawInfo = sbext_read_pid(pid) else {
            return (nil, "Failed to read sandbox info for PID \(pid)")
        }
        defer { sbext_info_free(rawInfo) }
        return (convertInfo(rawInfo), nil)
    }
    
    private func readSandboxInfoByName(name: String) -> (info: SandboxInfo?, error: String?) {
        guard let rawInfo = name.withCString({ sbext_read_name($0) }) else {
            return (nil, "Failed to find process '\(name)' or read sandbox info")
        }
        defer { sbext_info_free(rawInfo) }
        return (convertInfo(rawInfo), nil)
    }
    
    private func convertInfo(_ raw: UnsafeMutablePointer<sbext_info_t>) -> SandboxInfo {
        let info = raw.pointee
        
        var tokens: [SandboxToken] = []
        if let tokenPtr = info.tokens {
            for i in 0..<Int(info.token_count) {
                let t = tokenPtr[i]
                let tokenStr = withUnsafePointer(to: t.token) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: 512) {
                        String(cString: $0)
                    }
                }
                tokens.append(SandboxToken(token: tokenStr, address: t.kaddr))
            }
        }
        
        let containerPath = withUnsafePointer(to: info.container_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: 1024) {
                String(cString: $0)
            }
        }
        
        let profileName = withUnsafePointer(to: info.profile_name) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: 256) {
                String(cString: $0)
            }
        }
        
        return SandboxInfo(
            procAddr: info.proc_addr,
            sandboxPtr: info.sandbox_ptr,
            containerAddr: info.container_addr,
            containerPath: containerPath,
            profileName: profileName,
            tokens: tokens,
            hasSandbox: info.sandbox_ptr != 0
        )
    }
}

// MARK: - Subviews

struct InfoRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .textSelection(.enabled)
        }
        .contextMenu {
            Button {
                UIPasteboard.general.string = value
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
        }
    }
}

struct TokenRow: View {
    let token: SandboxToken
    let isCopied: Bool
    let onCopy: () -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(token.token)
                .font(.system(.caption, design: .monospaced))
                .lineLimit(3)
                .textSelection(.enabled)
            
            HStack {
                Text(String(format: "@ 0x%llx", token.address))
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.secondary)
                
                Spacer()
                
                Button {
                    onCopy()
                } label: {
                    HStack(spacing: 2) {
                        Image(systemName: isCopied ? "checkmark" : "doc.on.doc")
                        Text(isCopied ? "Copied" : "Copy")
                    }
                    .font(.caption2)
                    .foregroundColor(isCopied ? .green : .accentColor)
                }
                .buttonStyle(.bordered)
                .controlSize(.mini)
            }
        }
        .padding(.vertical, 2)
    }
}
