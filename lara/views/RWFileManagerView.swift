//
//  RWFileManagerView.swift
//  lara
//
//  In-app read/write file manager using standard APIs (works after root escalation)
//

import SwiftUI
import QuickLook
import UniformTypeIdentifiers

struct RWFileManagerView: View {
    @State var currentPath: String
    @ObservedObject private var mgr = laramgr.shared
    
    init(path: String = "/") {
        _currentPath = State(initialValue: path)
    }
    
    var body: some View {
        RWBrowserView(path: currentPath)
    }
}

// MARK: - Browser View

struct RWBrowserView: View {
    let path: String
    @State private var items: [FileItem] = []
    @State private var error: String?
    @State private var showHidden = true
    @State private var searchText = ""
    @State private var showNewFolder = false
    @State private var showNewFile = false
    @State private var newName = ""
    @State private var showGoTo = false
    @State private var goToPath = ""
    @State private var showDeleteConfirm = false
    @State private var itemToDelete: FileItem?
    @State private var copiedPath: String?
    
    var filteredItems: [FileItem] {
        var result = items
        if !showHidden {
            result = result.filter { !$0.name.hasPrefix(".") }
        }
        if !searchText.isEmpty {
            result = result.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
        }
        return result.sorted { a, b in
            if a.isDirectory != b.isDirectory { return a.isDirectory }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
    }
    
    var body: some View {
        List {
            if let error = error {
                Section {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.caption)
                }
            }
            
            Section {
                ForEach(filteredItems) { item in
                    if item.isDirectory {
                        NavigationLink {
                            RWBrowserView(path: item.fullPath)
                        } label: {
                            FileRow(item: item)
                        }
                        .contextMenu { fileContextMenu(item: item) }
                    } else {
                        NavigationLink {
                            RWFileEditorView(path: item.fullPath)
                        } label: {
                            FileRow(item: item)
                        }
                        .contextMenu { fileContextMenu(item: item) }
                    }
                }
            } header: {
                HStack {
                    Text("\(filteredItems.count) items")
                    Spacer()
                    Text(path)
                        .font(.system(.caption2, design: .monospaced))
                        .lineLimit(1)
                }
            }
        }
        .searchable(text: $searchText, prompt: "Filter files")
        .navigationTitle(path == "/" ? "/" : (path as NSString).lastPathComponent)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Menu {
                    Button {
                        showNewFolder = true
                        newName = ""
                    } label: {
                        Label("New Folder", systemImage: "folder.badge.plus")
                    }
                    
                    Button {
                        showNewFile = true
                        newName = ""
                    } label: {
                        Label("New File", systemImage: "doc.badge.plus")
                    }
                    
                    Divider()
                    
                    Toggle("Show Hidden Files", isOn: $showHidden)
                    
                    Button {
                        loadContents()
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    
                    Divider()
                    
                    Button {
                        goToPath = ""
                        showGoTo = true
                    } label: {
                        Label("Go to Path...", systemImage: "arrow.right.circle")
                    }
                    
                    Menu("Quick Nav") {
                        Button("/") { navigateTo("/") }
                        Button("/var") { navigateTo("/var") }
                        Button("/var/mobile") { navigateTo("/var/mobile") }
                        Button("/var/jb") { navigateTo("/var/jb") }
                        Button("/private/var") { navigateTo("/private/var") }
                        Button("/System") { navigateTo("/System") }
                        Button("/Applications") { navigateTo("/Applications") }
                        Button("Home") { navigateTo(NSHomeDirectory()) }
                    }
                    
                    Divider()
                    
                    Button {
                        UIPasteboard.general.string = path
                    } label: {
                        Label("Copy Path", systemImage: "doc.on.doc")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .alert("New Folder", isPresented: $showNewFolder) {
            TextField("Folder name", text: $newName)
            Button("Create") { createFolder() }
            Button("Cancel", role: .cancel) {}
        }
        .alert("New File", isPresented: $showNewFile) {
            TextField("File name", text: $newName)
            Button("Create") { createFile() }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Go to Path", isPresented: $showGoTo) {
            TextField("/path/to/dir", text: $goToPath)
            Button("Go") { /* handled by NavigationLink */ }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Delete?", isPresented: $showDeleteConfirm) {
            Button("Delete", role: .destructive) {
                if let item = itemToDelete {
                    deleteItem(item)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Delete \(itemToDelete?.name ?? "")? This cannot be undone.")
        }
        .onAppear { loadContents() }
    }
    
    @ViewBuilder
    private func fileContextMenu(item: FileItem) -> some View {
        Button {
            UIPasteboard.general.string = item.fullPath
        } label: {
            Label("Copy Path", systemImage: "doc.on.doc")
        }
        
        if !item.isDirectory {
            Button {
                // Copy file contents
                if let data = FileManager.default.contents(atPath: item.fullPath),
                   let str = String(data: data, encoding: .utf8) {
                    UIPasteboard.general.string = str
                }
            } label: {
                Label("Copy Contents", systemImage: "doc.on.clipboard")
            }
        }
        
        Divider()
        
        Button(role: .destructive) {
            itemToDelete = item
            showDeleteConfirm = true
        } label: {
            Label("Delete", systemImage: "trash")
        }
    }
    
    private func navigateTo(_ path: String) {
        // This requires a navigation approach - we'll use the path directly
        goToPath = path
    }
    
    private func loadContents() {
        error = nil
        do {
            let contents = try FileManager.default.contentsOfDirectory(atPath: path)
            items = contents.map { name in
                let fullPath = (path as NSString).appendingPathComponent(name)
                var isDir: ObjCBool = false
                FileManager.default.fileExists(atPath: fullPath, isDirectory: &isDir)
                
                let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath)
                let size = attrs?[.size] as? UInt64 ?? 0
                let modified = attrs?[.modificationDate] as? Date
                let permissions = attrs?[.posixPermissions] as? Int ?? 0
                let owner = attrs?[.ownerAccountName] as? String ?? "?"
                
                return FileItem(
                    name: name,
                    fullPath: fullPath,
                    isDirectory: isDir.boolValue,
                    size: size,
                    modified: modified,
                    permissions: permissions,
                    owner: owner
                )
            }
        } catch {
            self.error = "Failed to list: \(error.localizedDescription)"
            items = []
        }
    }
    
    private func createFolder() {
        guard !newName.isEmpty else { return }
        let newPath = (path as NSString).appendingPathComponent(newName)
        do {
            try FileManager.default.createDirectory(atPath: newPath, withIntermediateDirectories: true)
            loadContents()
        } catch {
            self.error = "Create folder failed: \(error.localizedDescription)"
        }
    }
    
    private func createFile() {
        guard !newName.isEmpty else { return }
        let newPath = (path as NSString).appendingPathComponent(newName)
        FileManager.default.createFile(atPath: newPath, contents: Data())
        loadContents()
    }
    
    private func deleteItem(_ item: FileItem) {
        do {
            try FileManager.default.removeItem(atPath: item.fullPath)
            loadContents()
        } catch {
            self.error = "Delete failed: \(error.localizedDescription)"
        }
    }
}

// MARK: - File Item Model

struct FileItem: Identifiable {
    let id = UUID()
    let name: String
    let fullPath: String
    let isDirectory: Bool
    let size: UInt64
    let modified: Date?
    let permissions: Int
    let owner: String
    
    var permissionsString: String {
        String(format: "%o", permissions)
    }
    
    var sizeString: String {
        if isDirectory { return "" }
        if size < 1024 { return "\(size) B" }
        if size < 1024 * 1024 { return String(format: "%.1f KB", Double(size) / 1024) }
        if size < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(size) / (1024 * 1024)) }
        return String(format: "%.1f GB", Double(size) / (1024 * 1024 * 1024))
    }
    
    var icon: String {
        if isDirectory { return "folder.fill" }
        let ext = (name as NSString).pathExtension.lowercased()
        switch ext {
        case "txt", "log", "md", "json", "xml", "plist", "yaml", "yml", "conf", "cfg":
            return "doc.text"
        case "png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp", "heic":
            return "photo"
        case "mp4", "mov", "m4v", "avi":
            return "play.rectangle"
        case "mp3", "aac", "wav", "m4a", "flac":
            return "waveform"
        case "dylib", "framework", "a":
            return "shippingbox"
        case "app":
            return "app"
        case "deb":
            return "shippingbox.fill"
        case "sh", "py", "rb", "js":
            return "terminal"
        default:
            return "doc"
        }
    }
    
    var iconColor: Color {
        if isDirectory { return .blue }
        let ext = (name as NSString).pathExtension.lowercased()
        switch ext {
        case "png", "jpg", "jpeg", "gif", "heic": return .green
        case "mp4", "mov": return .purple
        case "dylib", "framework": return .orange
        case "deb": return .red
        default: return .secondary
        }
    }
}

// MARK: - File Row

struct FileRow: View {
    let item: FileItem
    
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: item.icon)
                .foregroundColor(item.iconColor)
                .frame(width: 24)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .font(.system(.body, design: .default))
                    .lineLimit(1)
                    .foregroundColor(item.name.hasPrefix(".") ? .secondary : .primary)
                
                HStack(spacing: 8) {
                    if !item.isDirectory {
                        Text(item.sizeString)
                    }
                    Text(item.permissionsString)
                    Text(item.owner)
                }
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
            }
            
            Spacer()
        }
    }
}

// MARK: - File Editor View

struct RWFileEditorView: View {
    let path: String
    @State private var content = ""
    @State private var isEditing = false
    @State private var isBinary = false
    @State private var fileSize: UInt64 = 0
    @State private var error: String?
    @State private var saved = false
    @State private var hexDump = ""
    @State private var showInfo = false
    
    var body: some View {
        Group {
            if isBinary {
                ScrollView {
                    Text(hexDump)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding()
                }
            } else {
                if isEditing {
                    TextEditor(text: $content)
                        .font(.system(.body, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                } else {
                    ScrollView {
                        Text(content)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding()
                    }
                }
            }
        }
        .navigationTitle((path as NSString).lastPathComponent)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if !isBinary {
                    Button(isEditing ? "Done" : "Edit") {
                        isEditing.toggle()
                    }
                    
                    if isEditing {
                        Button {
                            saveFile()
                        } label: {
                            Image(systemName: saved ? "checkmark.circle.fill" : "square.and.arrow.down")
                                .foregroundColor(saved ? .green : .accentColor)
                        }
                    }
                }
                
                Menu {
                    Button {
                        UIPasteboard.general.string = content.isEmpty ? hexDump : content
                    } label: {
                        Label("Copy Contents", systemImage: "doc.on.doc")
                    }
                    
                    Button {
                        UIPasteboard.general.string = path
                    } label: {
                        Label("Copy Path", systemImage: "link")
                    }
                    
                    Button {
                        showInfo = true
                    } label: {
                        Label("File Info", systemImage: "info.circle")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .alert("File Info", isPresented: $showInfo) {
            Button("OK") {}
        } message: {
            let attrs = try? FileManager.default.attributesOfItem(atPath: path)
            let size = attrs?[.size] as? UInt64 ?? 0
            let perms = attrs?[.posixPermissions] as? Int ?? 0
            let owner = attrs?[.ownerAccountName] as? String ?? "?"
            let group = attrs?[.groupOwnerAccountName] as? String ?? "?"
            let mod = attrs?[.modificationDate] as? Date
            
            Text("""
            Path: \(path)
            Size: \(size) bytes
            Permissions: \(String(format: "%o", perms))
            Owner: \(owner):\(group)
            Modified: \(mod?.description ?? "?")
            """)
        }
        .alert("Error", isPresented: .constant(error != nil)) {
            Button("OK") { error = nil }
        } message: {
            Text(error ?? "")
        }
        .onAppear { loadFile() }
    }
    
    private func loadFile() {
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        fileSize = attrs?[.size] as? UInt64 ?? 0
        
        guard fileSize < 10 * 1024 * 1024 else {
            error = "File too large to open (\(fileSize) bytes)"
            return
        }
        
        guard let data = FileManager.default.contents(atPath: path) else {
            error = "Failed to read file"
            return
        }
        
        if let str = String(data: data, encoding: .utf8) {
            content = str
            isBinary = false
        } else {
            isBinary = true
            let maxBytes = min(data.count, 8192)
            var lines: [String] = []
            for offset in stride(from: 0, to: maxBytes, by: 16) {
                let end = min(offset + 16, maxBytes)
                let slice = data[offset..<end]
                let hex = slice.map { String(format: "%02x", $0) }.joined(separator: " ")
                let ascii = slice.map { (0x20...0x7E).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
                lines.append(String(format: "%08x  %-48s  %s", offset, hex, ascii))
            }
            if data.count > maxBytes {
                lines.append("... (\(data.count) bytes total)")
            }
            hexDump = lines.joined(separator: "\n")
        }
    }
    
    private func saveFile() {
        guard !isBinary else { return }
        guard let data = content.data(using: .utf8) else {
            error = "Failed to encode content"
            return
        }
        
        do {
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            saved = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                saved = false
            }
        } catch {
            self.error = "Save failed: \(error.localizedDescription)"
        }
    }
}
