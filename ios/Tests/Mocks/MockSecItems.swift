import Foundation

final class MockSecItems: SecItemsProvider {
    // MARK: - copyMatching() State Config
     
    struct CopyMatchingStub {
        let status: OSStatus
        let resultObj: CFTypeRef?
    }

    /// The FIFO queue of stubs to return ONCE per call
    private(set) var copyMatchingStubQueue: [CopyMatchingStub] = []
        
    /// Queues a specific OSStatus and optional Result Object to return ONCE when `copyMatching` is called.
    /// Calling this multiple times in a row will queue the return value (FIFO).
    /// This takes precedence over the standard 'ToReturn' value.
    func copyMatchingStubOnce(status: OSStatus, resultObj: CFTypeRef) -> Void {
        copyMatchingStubQueue.append(CopyMatchingStub(status: status, resultObj: resultObj))
    }
    
    /// The OSStatus to return when `copyMatching` is called (default is errSecSuccess)
    var copyMatchingStatusToReturn: OSStatus = errSecSuccess

    /// The exact object you want `copyMatching` to populate into the pointer
    /// (e.g., Data("fake_key_bytes".utf8) or a CFDictionary of attributes)
    var copyMatchingResultObjectToReturn: CFTypeRef? = nil

    // MARK: - copyMatching() Spy
    
    /// The number of times `copyMatching` has been called
    private(set) var copyMatchingCallCount = 0

    /// Stores ALL query dictionaries passed into `copyMatching` in chronological order
    private(set) var copyMatchingQueries: [[String: Any]] = []
    
    /// Convenient accessor for the very last query in `copyMatchingQueries`
    var lastCopyMatchingQuery: [String: Any]? { copyMatchingQueries.last }

    // MARK: - copyMatching() Protocol Conformance
    
    func copyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        copyMatchingCallCount += 1
        lastCopyMatchingQuery = query as? [String: Any]

        if let queryDict = query as? [String: Any] {
          copyMatchingQueries.append(queryDict)
        }
        
        // Pop from the FIFO queue if available, otherwise fall back to defaults
        let stub: CopyMatchingStub
        if !copyMatchingQueue.isEmpty {
          stub = copyMatchingQueue.removeFirst()
        } else {
          stub = CopyMatchingStub(status: copyMatchingStatusToReturn, resultObject: copyMatchingResultObjectToReturn)
        }
        
        // Safely populate the pointer if the caller provided one AND we have an object
        if let resultPointer = result, let objectToReturn = stub.resultObject {
          resultPointer.pointee = objectToReturn
        }
        
        return stub.status
    }

    // MARK: - delete() State Config
    
    /// The OSStatus to return when `delete` is called (default is errSecSuccess)
    var deleteStatusToReturn: OSStatus = errSecSuccess
    
    // MARK: - delete() Spy
    
    /// The number of times `delete` has been called
    private(set) var deleteCallCount = 0

    /// Stores ALL query dictionaries passed into `delete` in chronological order
    private(set) var deleteQueries: [[String: Any]] = []
    
    /// Stores the last query dictionary passed into `delete` for inspection
    private(set) var lastDeleteQuery: { deleteQueries.last }
    
    // MARK: - delete() Protocol Conformance
    
    func delete(_ query: CFDictionary) -> OSStatus {
        deleteCallCount += 1
        deleteQueries.append(query)
        return deleteStatusToReturn
    }
}
