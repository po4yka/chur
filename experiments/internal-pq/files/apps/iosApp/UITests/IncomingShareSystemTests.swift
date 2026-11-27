import XCTest

@MainActor
final class IncomingShareSystemTests: XCTestCase {
    func testImportsFileFromSystemShareSheet() throws {
        continueAfterFailure = false
        let sender = XCUIApplication(bundleIdentifier: "dev.po4yka.chur.livephototesthost")
        sender.launchArguments = ["-ShareFixture"]
        sender.launch()
        sender.buttons["Share fixture"].tap()

        selectInternalExtension(in: sender)
        let save = sender.buttons["Save files"]
        XCTAssertTrue(save.waitForExistence(timeout: 15))
        save.tap()
        let done = sender.buttons["Done"].firstMatch
        XCTAssertTrue(done.waitForExistence(timeout: 20), "The extension must finish saving")
        done.tap()

        let app = XCUIApplication()
        app.activate()
        let notice = app.buttons["Continue"].firstMatch
        XCTAssertTrue(notice.waitForExistence(timeout: 20), "Main app must find the extension's batch")
        notice.tap()
        let password = app.descendants(matching: .any).matching(NSPredicate(
            format: "(label == %@ OR label BEGINSWITH %@) AND elementType IN %@",
            "Password", "Password, ",
            [XCUIElement.ElementType.textField, .secureTextField, .textView].map(\.rawValue)
        )).firstMatch
        XCTAssertTrue(password.waitForExistence(timeout: 15))
        password.tap()
        app.typeText("Chur simulator share test\n")
        let confirm = app.buttons["Import"].firstMatch
        XCTAssertTrue(confirm.waitForExistence(timeout: 20))
        confirm.tap()
        let file = app.buttons.matching(NSPredicate(format: "label == 'File' OR label BEGINSWITH 'File, '")).firstMatch
        XCTAssertTrue(file.waitForExistence(timeout: 30))
        file.tap()
        XCTAssertTrue(app.staticTexts["share-proof.txt"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["From the system share extension."].waitForExistence(timeout: 15))
    }

    private func selectInternalExtension(in sender: XCUIApplication) {
        let service = XCUIApplication(bundleIdentifier: "com.apple.SharingUIService")
        let hosts = [sender, service]
        let app = NSPredicate(format: "identifier == %@ OR label IN %@ OR (identifier == %@ AND label CONTAINS[c] %@)",
                              "dev.po4yka.chur.pqinternal.share", ["Save to Chur PQ", "Chur PQ"], "shareCell", "Chur PQ")
        let more = NSPredicate(format: "label IN[c] %@ OR identifier ENDSWITH[c] %@",
                               ["More", "More Apps", "More…", "More Apps…"], ".More")
        let tile = NSPredicate(format: "identifier == %@ OR identifier BEGINSWITH %@",
                               "shareCell", "com.apple.UIKit.activity.")
        func visible(_ predicate: NSPredicate) -> XCUIElement? {
            for host in hosts where host.state != .notRunning {
                let matches = host.descendants(matching: .any).matching(predicate)
                if let hit = matches.allElementsBoundByIndex.first(where: { $0.isHittable }) { return hit }
            }
            return nil
        }

        // The sheet loads app extensions asynchronously. Both the app tile and More
        // can be cells in a horizontal list in the sender or the sharing service.
        let initial = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            visible(NSCompoundPredicate(orPredicateWithSubpredicates: [app, more, tile])) != nil
        }, object: nil)
        _ = XCTWaiter.wait(for: [initial], timeout: 30)
        for _ in 0..<6 {
            if let activity = visible(app) { activity.tap(); return }
            if let allApps = visible(more) {
                allApps.tap()
                break
            }
            guard let cell = visible(tile) else { break }
            let y = cell.frame.midY - sender.frame.minY
            let origin = sender.coordinate(withNormalizedOffset: .zero)
            let start = origin.withOffset(CGVector(dx: sender.frame.width * 0.88, dy: y))
            let end = origin.withOffset(CGVector(dx: sender.frame.width * 0.12, dy: y))
            start.press(forDuration: 0.12, thenDragTo: end)
        }
        let available = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in visible(app) != nil }, object: nil)
        _ = XCTWaiter.wait(for: [available], timeout: 15)
        if let activity = visible(app) { activity.tap(); return }
        let trees = hosts.filter { $0.state != .notRunning }.map(\.debugDescription)
        XCTFail("Could not select Chur PQ in the system share sheet.\n" + trees.joined(separator: "\n"))
    }
}
