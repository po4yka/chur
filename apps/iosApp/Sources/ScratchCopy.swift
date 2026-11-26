import Darwin
import Foundation

enum ScratchCopyError: Error, Equatable {
    case limitExceeded
    case cancelled
    case timedOut
    case sourceIncomplete
}

/// Copies a provider file with a fixed byte budget and removes incomplete output.
enum ScratchCopy {
    static let entryLimit: Int64 = 4 * 1024 * 1024 * 1024
    static let totalLimit: Int64 = 8 * 1024 * 1024 * 1024
    static let entryCountLimit = 4

    static func remainingBudget(in directories: [URL], maxEntries: Int = entryCountLimit, maxTotal: Int64 = totalLimit, maxEntry: Int64 = entryLimit) throws -> Int64 {
        var count = 0
        var used: Int64 = 0
        for directory in directories where FileManager.default.fileExists(atPath: directory.path) {
            guard let entries = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey]) else {
                throw CocoaError(.fileReadUnknown)
            }
            for case let entry as URL in entries {
                let values = try entry.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                guard values.isRegularFile == true else { continue }
                count += 1
                let size = Int64(values.fileSize ?? 0)
                guard size <= maxTotal - used else { throw ScratchCopyError.limitExceeded }
                used += size
            }
        }
        guard count < maxEntries, used < maxTotal else { throw ScratchCopyError.limitExceeded }
        guard let parent = directories.first else { throw CocoaError(.fileReadUnknown) }
        let free = try FileManager.default.attributesOfFileSystem(forPath: parent.path)[.systemFreeSize] as? NSNumber
        return min(maxEntry, maxTotal - used, free?.int64Value ?? 0)
    }

    static func copy(
        from source: URL,
        to target: URL,
        limit: Int64 = entryLimit,
        timeout: TimeInterval = 10 * 60,
        attributes: [FileAttributeKey: Any] = [:],
        progress: (Int64, Int64) -> Bool = { _, _ in true },
        shouldContinue: () -> Bool
    ) throws {
        let sourceSize = try source.resourceValues(forKeys: [.fileSizeKey]).fileSize
        guard limit >= 0, sourceSize.map({ Int64($0) <= limit }) != false else {
            throw ScratchCopyError.limitExceeded
        }
        guard shouldContinue() else { throw ScratchCopyError.cancelled }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let reader = try FileHandle(forReadingFrom: source)
        defer { try? reader.close() }
        let fd = Darwin.open(target.path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        let writer = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var complete = false
        defer {
            try? writer.close()
            if !complete { try? FileManager.default.removeItem(at: target) }
        }
        try FileManager.default.setAttributes(attributes, ofItemAtPath: target.path)
        var written: Int64 = 0
        while true {
            guard shouldContinue(), progress(written, Int64(sourceSize ?? 0)) else { throw ScratchCopyError.cancelled }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw ScratchCopyError.timedOut }
            guard let chunk = try reader.read(upToCount: 64 * 1024), !chunk.isEmpty else { break }
            guard Int64(chunk.count) <= limit - written else { throw ScratchCopyError.limitExceeded }
            try writer.write(contentsOf: chunk)
            written += Int64(chunk.count)
        }
        guard shouldContinue() else { throw ScratchCopyError.cancelled }
        if let sourceSize, written < Int64(sourceSize) { throw ScratchCopyError.sourceIncomplete }
        try writer.close()
        complete = true
    }
}
