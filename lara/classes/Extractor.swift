//
//  Extractor.swift
//  lara
//

import Foundation
import SwiftZSTD
import Compression

class Extractor {
    
    // Asynchronously downloads a file
    static func downloadFile(url: URL, destURL: URL, completion: @escaping (Bool) -> Void) {
        if FileManager.default.fileExists(atPath: destURL.path) {
            completion(true)
            return
        }
        print("(extractor) downloading \(url.lastPathComponent)...")
        let task = URLSession.shared.downloadTask(with: url) { tempURL, response, error in
            guard let tempURL = tempURL, error == nil else {
                print("(extractor) download failed: \(error?.localizedDescription ?? "unknown")")
                completion(false)
                return
            }
            do {
                try FileManager.default.moveItem(at: tempURL, to: destURL)
                completion(true)
            } catch {
                print("(extractor) move failed: \(error.localizedDescription)")
                completion(false)
            }
        }
        task.resume()
    }
    
    // Decompresses ZSTD file
    static func decompressZSTD(src: URL, dst: URL) -> Bool {
        do {
            let data = try Data(contentsOf: src)
            let processor = ZSTDProcessor()
            let decompressed = try processor.decompressFrame(data)
            try decompressed.write(to: dst)
            return true
        } catch {
            print("(extractor) ZSTD decompress failed: \(error.localizedDescription)")
            return false
        }
    }
    
    // Decompresses LZMA file
    static func decompressLZMA(srcData: Data) -> Data? {
        let bufferSize = 32_768
        var decompressed = Data()
        var index = 0
        
        let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { destinationBuffer.deallocate() }
        
        let stream = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { stream.deallocate() }
        
        compression_stream_init(stream, COMPRESSION_STREAM_DECODE, COMPRESSION_LZMA)
        defer { compression_stream_destroy(stream) }
        
        srcData.withUnsafeBytes { rawBuffer in
            guard let srcBase = rawBuffer.bindMemory(to: UInt8.self).baseAddress else { return }
            stream.pointee.src_ptr = srcBase
            stream.pointee.src_size = srcData.count
            
            while true {
                stream.pointee.dst_ptr = destinationBuffer
                stream.pointee.dst_size = bufferSize
                
                // 1 represents COMPRESSION_STREAM_FINALIZE
                let status = compression_stream_process(stream, 1)
                
                if status == COMPRESSION_STATUS_ERROR {
                    print("(extractor) LZMA decompression error")
                    break
                }
                
                let written = bufferSize - stream.pointee.dst_size
                decompressed.append(destinationBuffer, count: written)
                
                if status == COMPRESSION_STATUS_END {
                    break
                }
            }
        }
        return decompressed
    }
    
    // Parses Tar data and writes to destPath
    // stripPrefix: optional prefix to remove from tar entry names (e.g. "./var/jb/" for Procursus bootstrap)
    static func extractTar(data: Data, destPath: String, stripPrefix: String? = nil) -> Bool {
        var offset = 0
        let totalSize = data.count
        let fm = FileManager.default
        
        // Build list of prefixes to strip (handle with and without leading ./)
        var prefixesToStrip: [String] = []
        if let sp = stripPrefix {
            prefixesToStrip.append(sp)
            // Also handle variations: "./var/jb/" vs "var/jb/" vs "./var/jb" etc.
            if sp.hasPrefix("./") {
                prefixesToStrip.append(String(sp.dropFirst(2)))
            } else {
                prefixesToStrip.append("./" + sp)
            }
        }
        
        while offset + 512 <= totalSize {
            let header = data.subdata(in: offset..<offset+512)
            offset += 512
            
            // Null block means end of tar
            if header.allSatisfy({ $0 == 0 }) {
                let nextHeader = data.subdata(in: offset..<min(offset+512, totalSize))
                if nextHeader.allSatisfy({ $0 == 0 }) {
                    break // Two null blocks = end of archive
                }
                continue
            }
            
            // Read name — handle UStar long names (prefix at offset 345)
            let nameData = header.prefix(100)
            guard var nameStr = String(data: nameData.prefix(while: { $0 != 0 }), encoding: .utf8), !nameStr.isEmpty else {
                // Still need to skip file data
                let sizeData2 = header.subdata(in: 124..<136)
                let sizeStr2 = String(data: sizeData2.prefix(while: { $0 != 0 && $0 != 32 }), encoding: .ascii) ?? "0"
                let fileSize2 = Int(sizeStr2, radix: 8) ?? 0
                let padding2 = (512 - (fileSize2 % 512)) % 512
                offset += fileSize2 + padding2
                continue
            }
            
            // Check for UStar prefix (offset 345, 155 bytes)
            let prefixData = header.subdata(in: 345..<500)
            if let prefixStr = String(data: prefixData.prefix(while: { $0 != 0 }), encoding: .utf8), !prefixStr.isEmpty {
                nameStr = prefixStr + "/" + nameStr
            }
            
            // Read file size (octal ascii, 12 bytes at offset 124)
            let sizeData = header.subdata(in: 124..<136)
            let sizeStr = String(data: sizeData.prefix(while: { $0 != 0 && $0 != 32 }), encoding: .ascii) ?? "0"
            let fileSize = Int(sizeStr, radix: 8) ?? 0
            
            // Read typeflag (1 byte at offset 156)
            let typeflag = header[156]
            
            // Read linkname (100 bytes at offset 157)
            let linkData = header.subdata(in: 157..<257)
            let linkStr = String(data: linkData.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
            
            // Strip prefix from name if requested
            var strippedName = nameStr
            for prefix in prefixesToStrip {
                if strippedName.hasPrefix(prefix) {
                    strippedName = String(strippedName.dropFirst(prefix.count))
                    break
                }
            }
            
            // Skip empty names after stripping (means it was the prefix dir itself)
            if strippedName.isEmpty || strippedName == "." || strippedName == "./" {
                let padding = (512 - (fileSize % 512)) % 512
                offset += fileSize + padding
                continue
            }
            
            // Strip leading "./" if present
            if strippedName.hasPrefix("./") {
                strippedName = String(strippedName.dropFirst(2))
            }
            if strippedName.hasPrefix("/") {
                strippedName = String(strippedName.dropFirst(1))
            }
            
            // Skip if still empty
            guard !strippedName.isEmpty else {
                let padding = (512 - (fileSize % 512)) % 512
                offset += fileSize + padding
                continue
            }
            
            let targetURL = URL(fileURLWithPath: destPath).appendingPathComponent(strippedName)
            
            if typeflag == 48 || typeflag == 0 { // '0' or \0 = Regular file
                if offset + fileSize <= totalSize {
                    let fileData = data.subdata(in: offset..<offset+fileSize)
                    do {
                        let parent = targetURL.deletingLastPathComponent()
                        try fm.createDirectory(at: parent, withIntermediateDirectories: true)
                        // Remove existing file/symlink if needed (lstat-based, catches broken symlinks too)
                        if (try? fm.attributesOfItem(atPath: targetURL.path)) != nil {
                            try? fm.removeItem(at: targetURL)
                        }
                        try fileData.write(to: targetURL)
                        
                        // Mark bin files as executable
                        if strippedName.contains("/bin/") || strippedName.contains("/sbin/") || strippedName.hasSuffix(".dylib") {
                            try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: targetURL.path)
                        }
                    } catch {
                        print("(extractor) Failed to write file \(strippedName): \(error.localizedDescription)")
                    }
                }
            } else if typeflag == 53 { // '5' = Directory
                do {
                    try fm.createDirectory(at: targetURL, withIntermediateDirectories: true)
                    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: targetURL.path)
                } catch {
                    // Directory might already exist, that's OK
                }
            } else if typeflag == 49 || typeflag == 50 { // '1' = Hardlink, '2' = Symlink
                do {
                    let parent = targetURL.deletingLastPathComponent()
                    try fm.createDirectory(at: parent, withIntermediateDirectories: true)
                    
                    // Force-remove any existing item (file, symlink, or directory)
                    // Use lstat-based check: attributesOfItem doesn't follow symlinks
                    let exists = (try? fm.attributesOfItem(atPath: targetURL.path)) != nil
                    if exists {
                        try? fm.removeItem(atPath: targetURL.path)
                    }
                    
                    // Also strip prefix from link targets that use absolute /var/jb/ paths
                    var fixedLink = linkStr
                    if let sp = stripPrefix {
                        let absPrefix = "/" + sp.replacingOccurrences(of: "./", with: "")
                        if fixedLink.hasPrefix(absPrefix) {
                            // Convert absolute /var/jb/usr/bin/foo → relative path within jb root
                            fixedLink = String(fixedLink.dropFirst(absPrefix.count))
                            // Make it relative to destPath
                            fixedLink = destPath + "/" + fixedLink
                        }
                    }
                    
                    try fm.createSymbolicLink(atPath: targetURL.path, withDestinationPath: fixedLink)
                } catch {
                    print("(extractor) Failed to create symlink \(strippedName) -> \(linkStr): \(error.localizedDescription)")
                }
            }
            
            // Tar pads file data to 512 bytes
            let padding = (512 - (fileSize % 512)) % 512
            offset += fileSize + padding
        }
        return true
    }
    
    /// Clean ar member name — strips trailing "/" and whitespace
    private static func cleanArName(_ raw: String) -> String {
        var name = raw.trimmingCharacters(in: .whitespaces)
        if name.hasSuffix("/") { name = String(name.dropLast()) }
        return name
    }
    
    /// Decompress a tar payload based on its member name suffix
    private static func decompressTarPayload(name: String, payload: Data) -> Data? {
        if name.hasSuffix(".zst") {
            // ZSTD compressed (Sileo 2.5+ uses data.tar.zst)
            do {
                let processor = ZSTDProcessor()
                let decompressed = try processor.decompressFrame(payload)
                print("(extractor) decompressed \(name): \(payload.count) → \(decompressed.count) bytes")
                return decompressed
            } catch {
                print("(extractor) ZSTD decompress of \(name) failed: \(error.localizedDescription)")
                return nil
            }
        } else if name.hasSuffix(".lzma") || name.hasSuffix(".xz") {
            // LZMA/XZ compressed
            return decompressLZMA(srcData: payload)
        } else if name.hasSuffix(".gz") {
            // GZ compressed — use NSData decompression
            // For now treat as raw (gz support can be added if needed)
            print("(extractor) gz decompression not implemented for \(name)")
            return nil
        } else {
            // Uncompressed tar
            return payload
        }
    }
    
    /// Extract all ar members from a .deb file
    /// Returns dictionary of member name → data
    static func extractArMembers(from data: Data) -> [(name: String, data: Data)] {
        let magic = "!<arch>\n".data(using: .ascii)!
        guard data.prefix(magic.count) == magic else { return [] }
        
        var members: [(name: String, data: Data)] = []
        var offset = magic.count
        
        while offset < data.count {
            if offset + 60 > data.count { break }
            let header = data.subdata(in: offset..<offset+60)
            offset += 60
            
            let nameData = header.prefix(16)
            let rawName = String(data: nameData, encoding: .ascii) ?? ""
            let name = cleanArName(rawName)
            
            let sizeData = header.subdata(in: 48..<58)
            let sizeStr = String(data: sizeData, encoding: .ascii)?.trimmingCharacters(in: .whitespaces) ?? "0"
            let fileSize = Int(sizeStr) ?? 0
            
            if fileSize > 0 && offset + fileSize <= data.count {
                let memberData = data.subdata(in: offset..<offset+fileSize)
                members.append((name: name, data: memberData))
                print("(extractor) ar member: '\(name)' (\(fileSize) bytes)")
            }
            
            // Ar files align to 2 bytes
            let padding = fileSize % 2
            offset += fileSize + padding
        }
        
        return members
    }
    
    /// Extract a .deb file — handles data.tar.zst, data.tar.xz, data.tar.lzma, data.tar
    static func extractDeb(fileURL: URL, extractTarSuffix: String, destPath: String) -> Bool {
        guard let data = try? Data(contentsOf: fileURL) else {
            print("(extractor) failed to read deb file")
            return false
        }
        
        let members = extractArMembers(from: data)
        if members.isEmpty {
            print("(extractor) no ar members found (bad deb?)")
            return false
        }
        
        // Find the matching tar member
        for member in members {
            if member.name.hasPrefix(extractTarSuffix) {
                print("(extractor) found matching member: '\(member.name)' for prefix '\(extractTarSuffix)'")
                
                guard let tarData = decompressTarPayload(name: member.name, payload: member.data) else {
                    print("(extractor) failed to decompress \(member.name)")
                    return false
                }
                
                print("(extractor) extracting tar (\(tarData.count) bytes) to \(destPath)")
                return extractTar(data: tarData, destPath: destPath)
            }
        }
        
        print("(extractor) no member matching '\(extractTarSuffix)' found in deb")
        return false
    }
    
    /// Full deb extraction — extracts both data.tar and control.tar
    /// Returns (dataExtracted, controlData) where controlData is the raw control file contents
    static func extractDebFull(fileURL: URL, destPath: String) -> (dataOK: Bool, controlInfo: String?) {
        guard let data = try? Data(contentsOf: fileURL) else {
            print("(extractor) failed to read deb file")
            return (false, nil)
        }
        
        let members = extractArMembers(from: data)
        if members.isEmpty { return (false, nil) }
        
        var dataExtracted = false
        var controlInfo: String? = nil
        
        for member in members {
            // Extract data.tar.* → install files to destPath
            if member.name.hasPrefix("data.tar") {
                print("(extractor) extracting data from: '\(member.name)'")
                if let tarData = decompressTarPayload(name: member.name, payload: member.data) {
                    dataExtracted = extractTar(data: tarData, destPath: destPath)
                }
            }
            
            // Extract control.tar.* → read control file for dpkg metadata
            if member.name.hasPrefix("control.tar") {
                print("(extractor) extracting control from: '\(member.name)'")
                if let tarData = decompressTarPayload(name: member.name, payload: member.data) {
                    // Extract control tar to a temp directory to read control file
                    let tmpDir = NSTemporaryDirectory() + "deb_control_\(arc4random())"
                    try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
                    _ = extractTar(data: tarData, destPath: tmpDir)
                    
                    // Read the control file
                    let controlPath = (tmpDir as NSString).appendingPathComponent("control")
                    if let controlData = try? String(contentsOfFile: controlPath, encoding: .utf8) {
                        controlInfo = controlData
                        print("(extractor) read control file: \(controlData.prefix(200))")
                    } else {
                        // Try ./control (some debs have it with leading ./)
                        let altPath = (tmpDir as NSString).appendingPathComponent("./control")
                        controlInfo = try? String(contentsOfFile: altPath, encoding: .utf8)
                    }
                    
                    try? FileManager.default.removeItem(atPath: tmpDir)
                }
            }
        }
        
        return (dataExtracted, controlInfo)
    }
}

