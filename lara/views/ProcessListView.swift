//
//  ProcessListView.swift
//  lara
//
//  Displays all kernel processes with their details
//

import SwiftUI

struct KernelProcess: Identifiable {
    let id = UUID()
    let pid: Int32
    let uid: UInt32
    let gid: UInt32
    let name: String
    let procAddr: UInt64
    var ucredAddr: UInt64
    var sandboxPtr: UInt64
    
    var isRoot: Bool { uid == 0 }
    var hasSandbox: Bool { sandboxPtr != 0 }
    var detailsLoaded: Bool { ucredAddr != 0 || sandboxPtr != 0 }
}

struct ProcessListView: View {
    @ObservedObject private var mgr = laramgr.shared
    @State private var processes: [KernelProcess] = []
    @State private var isLoading = false
    @State private var searchText = ""
    @State private var sortBy: SortOption = .pid
    @State private var showOnlySandboxed = false
    @State private var selectedProcess: KernelProcess?
    
    enum SortOption: String, CaseIterable {
        case pid = "PID"
        case name = "Name"
        case uid = "UID"
    }
    
    var filteredProcesses: [KernelProcess] {
        var result = processes
        
        if !searchText.isEmpty {
            result = result.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                "\($0.pid)".contains(searchText)
            }
        }
        
        if showOnlySandboxed {
            result = result.filter { $0.isRoot }
        }
        
        switch sortBy {
        case .pid:
            result.sort { $0.pid < $1.pid }
        case .name:
            result.sort { $0.name.lowercased() < $1.name.lowercased() }
        case .uid:
            result.sort { $0.uid < $1.uid }
        }
        
        return result
    }
    
    var body: some View {
        List {
            Section {
                HStack {
                    Button {
                        loadProcesses()
                    } label: {
                        HStack {
                            if isLoading {
                                ProgressView()
                                    .frame(width: 18, height: 18)
                                Text("Loading...")
                            } else {
                                Image(systemName: "arrow.clockwise")
                                Text("Refresh")
                            }
                        }
                    }
                    .disabled(isLoading || !mgr.dsready)
                    
                    Spacer()
                    
                    Text("\(processes.count) processes")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Picker("Sort by", selection: $sortBy) {
                    ForEach(SortOption.allCases, id: \.self) { opt in
                        Text(opt.rawValue).tag(opt)
                    }
                }
                .pickerStyle(.segmented)
                
                Toggle("Root only", isOn: $showOnlySandboxed)
            } header: {
                Text("Controls")
            }
            
            Section {
                if filteredProcesses.isEmpty && !isLoading {
                    if processes.isEmpty {
                        Text("Tap Refresh to load kernel process list")
                            .foregroundColor(.secondary)
                            .font(.caption)
                    } else {
                        Text("No processes match filter")
                            .foregroundColor(.secondary)
                            .font(.caption)
                    }
                }
                
                ForEach(filteredProcesses) { proc in
                    Button {
                        selectedProcess = proc
                    } label: {
                        ProcessRow(proc: proc)
                    }
                    .buttonStyle(.plain)
                }
            } header: {
                HStack {
                    Text("Processes (\(filteredProcesses.count))")
                    Spacer()
                    if !processes.isEmpty {
                        Button {
                            copyAllProcesses()
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: "doc.on.doc")
                                Text("Copy All")
                            }
                            .font(.caption)
                        }
                    }
                }
            }
        }
        .searchable(text: $searchText, prompt: "Search by name or PID")
        .navigationTitle("Kernel Processes")
        .sheet(item: $selectedProcess) { proc in
            ProcessDetailSheet(proc: proc, mgr: mgr)
        }
        .onAppear {
            // Don't auto-load — user must tap Refresh to avoid
            // overwhelming the kernel socket primitive
        }
    }
    
    private func loadProcesses() {
        isLoading = true
        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0
            guard let entries = proclist(nil, &count) else {
                DispatchQueue.main.async {
                    self.isLoading = false
                }
                return
            }
            defer { free_proclist(entries) }
            
            var procs: [KernelProcess] = []
            for i in 0..<Int(count) {
                var e = entries[i]
                let name = withUnsafePointer(to: &e.name) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: 32) {
                        String(cString: $0)
                    }
                }
                procs.append(KernelProcess(
                    pid: Int32(e.pid),
                    uid: e.uid,
                    gid: e.gid,
                    name: name,
                    procAddr: e.kaddr,
                    ucredAddr: 0,
                    sandboxPtr: 0
                ))
            }
            
            DispatchQueue.main.async {
                self.processes = procs
                self.isLoading = false
            }
        }
    }
    
    private func copyAllProcesses() {
        var text = "Kernel Process List (\(filteredProcesses.count) processes)\n"
        text += String(repeating: "=", count: 60) + "\n\n"
        text += String(format: "%-6s %-20s %-6s %-6s %-18s %s\n",
                       "PID", "NAME", "UID", "GID", "PROC_ADDR", "SANDBOX")
        text += String(repeating: "-", count: 80) + "\n"
        
        for proc in filteredProcesses {
            text += String(format: "%-6d %-20s %-6d %-6d 0x%llx %s\n",
                           proc.pid,
                           String(proc.name.prefix(20)),
                           proc.uid,
                           proc.gid,
                           proc.procAddr,
                           proc.hasSandbox ? String(format: "0x%llx", proc.sandboxPtr) : "NONE")
        }
        
        UIPasteboard.general.string = text
    }
}

// MARK: - Process Row

struct ProcessRow: View {
    let proc: KernelProcess
    
    var body: some View {
        HStack(spacing: 8) {
            // PID badge
            Text("\(proc.pid)")
                .font(.system(.caption, design: .monospaced))
                .frame(width: 44, alignment: .trailing)
                .foregroundColor(.secondary)
            
            // Status indicators
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(proc.name.isEmpty ? "(unnamed)" : proc.name)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                    
                    if proc.isRoot {
                        Text("root")
                            .font(.system(size: 9, weight: .bold))
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(Color.red.opacity(0.2))
                            .foregroundColor(.red)
                            .clipShape(Capsule())
                    }
                    
                    // Sandbox badge removed — loaded on-demand in detail view
                }
                
                HStack(spacing: 8) {
                    Text("uid:\(proc.uid)")
                    Text("gid:\(proc.gid)")
                    Text(String(format: "0x%llx", proc.procAddr))
                }
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Image(systemName: "chevron.right")
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Process Detail Sheet

struct ProcessDetailSheet: View {
    let proc: KernelProcess
    let mgr: laramgr
    @Environment(\.dismiss) private var dismiss
    @State private var actionLog = ""
    @State private var isActing = false
    
    var body: some View {
        NavigationStack {
            List {
                Section("Process Info") {
                    DetailRow(label: "PID", value: "\(proc.pid)")
                    DetailRow(label: "Name", value: proc.name)
                    DetailRow(label: "UID", value: "\(proc.uid)")
                    DetailRow(label: "GID", value: "\(proc.gid)")
                    DetailRow(label: "proc", value: String(format: "0x%llx", proc.procAddr))
                    DetailRow(label: "ucred", value: String(format: "0x%llx", proc.ucredAddr))
                    DetailRow(label: "p_sandbox",
                              value: proc.hasSandbox
                              ? String(format: "0x%llx", proc.sandboxPtr)
                              : "NULL (none)")
                }
                
                Section("Actions") {
                    Button {
                        performAction("sandbox_bypass") {
                            sandbox_bypass_pid(proc.pid)
                        }
                    } label: {
                        HStack {
                            Image(systemName: "shield.slash")
                            Text("Remove Sandbox")
                        }
                    }
                    .disabled(isActing)
                    
                    Button {
                        performAction("ucred_steal") {
                            ucred_steal_pid(proc.pid)
                        }
                    } label: {
                        HStack {
                            Image(systemName: "person.badge.key")
                            Text("Steal Root Credentials")
                        }
                    }
                    .disabled(isActing)
                    
                    Button {
                        performAction("elevate_to_root") {
                            elevate_to_root(proc.pid)
                        }
                    } label: {
                        HStack {
                            Image(systemName: "bolt.shield")
                            Text("Full Escalation (Sandbox + Root)")
                        }
                    }
                    .disabled(isActing)
                }
                
                if !actionLog.isEmpty {
                    Section("Log") {
                        Text(actionLog)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                
                Section {
                    Button {
                        var text = "Process: \(proc.name)\n"
                        text += "PID: \(proc.pid)\n"
                        text += "UID: \(proc.uid) GID: \(proc.gid)\n"
                        text += String(format: "proc: 0x%llx\n", proc.procAddr)
                        text += String(format: "ucred: 0x%llx\n", proc.ucredAddr)
                        text += String(format: "p_sandbox: 0x%llx\n", proc.sandboxPtr)
                        UIPasteboard.general.string = text
                    } label: {
                        HStack {
                            Image(systemName: "doc.on.doc")
                            Text("Copy All Info")
                        }
                    }
                }
            }
            .navigationTitle(proc.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
    
    private func performAction(_ name: String, action: @escaping () -> Int32) {
        isActing = true
        actionLog += "[\(name)] starting...\n"
        
        DispatchQueue.global(qos: .userInitiated).async {
            let result = action()
            DispatchQueue.main.async {
                if result == 0 {
                    actionLog += "[\(name)] SUCCESS ✓\n"
                } else {
                    actionLog += "[\(name)] FAILED (code \(result)) ✗\n"
                }
                isActing = false
            }
        }
    }
}

struct DetailRow: View {
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
