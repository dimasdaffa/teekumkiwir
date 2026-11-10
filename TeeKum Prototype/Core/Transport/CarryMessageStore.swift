import Foundation

/// Bounded ciphertext custody for the active session. Owned by PeerTransportService.
/// shortcut: custody is in memory; persist encrypted entries if process-restart delivery is required.
nonisolated struct CarryMessageStore {
    static let retention: TimeInterval = 600
    private let capacity: Int
    private let retention: TimeInterval
    private struct Entry {
        let data: Data
        let expiresAt: Date
        let isForeign: Bool
        var attempts: [String: Date] = [:]
    }
    private var entries: [Data: Entry] = [:]
    private var order: [Data] = []

    init(capacity: Int = 256, retention: TimeInterval = Self.retention) {
        self.capacity = max(1, capacity)
        self.retention = max(1, retention)
    }

    mutating func remember(_ data: Data, isForeign: Bool, now: Date = Date()) {
        purge(now: now)
        guard let packet = try? RawWirePacket.fromWireData(data),
              packet.envelope.type == .chatMessage || packet.envelope.type == .ack else { return }
        let key = identity(data)
        // Retries and loops must not extend custody or reset the hop budget.
        guard entries[key] == nil else { return }
        while order.count >= capacity {
            entries.removeValue(forKey: order.removeFirst())
        }
        entries[key] = Entry(data: data, expiresAt: now.addingTimeInterval(retention), isForeign: isForeign)
        order.append(key)
    }

    /// Fairly visits packet/peer pairs, retrying unconfirmed links at most every 30 seconds.
    mutating func nextTransmission(to peers: [String], now: Date = Date()) -> (data: Data, peer: String, isForeign: Bool)? {
        purge(now: now)
        var candidate: (data: Data, peer: String, isForeign: Bool)?
        var oldest = Date.distantFuture
        for key in order {
            guard let entry = entries[key] else { continue }
            for peer in peers {
                let last = entry.attempts[peer] ?? .distantPast
                if now.timeIntervalSince(last) >= 30 && last < oldest {
                    oldest = last
                    candidate = (entry.data, peer, entry.isForeign)
                }
            }
        }
        return candidate
    }

    mutating func markAttempt(_ data: Data, to peer: String, now: Date = Date()) {
        entries[identity(data)]?.attempts[peer] = now
    }

    mutating func disconnected(_ peer: String) {
        for key in order { entries[key]?.attempts.removeValue(forKey: peer) }
    }

    mutating func removeForeign() {
        entries = entries.filter { !$0.value.isForeign }
        order.removeAll { entries[$0] == nil }
    }

    mutating func removeAll() {
        entries.removeAll()
        order.removeAll()
    }

    private mutating func purge(now: Date) {
        entries = entries.filter { $0.value.expiresAt > now }
        order.removeAll { entries[$0] == nil }
    }

    private func identity(_ data: Data) -> Data {
        var key = data
        if key.count > 2 { key[key.startIndex + 2] = 0 }
        return key
    }
}
