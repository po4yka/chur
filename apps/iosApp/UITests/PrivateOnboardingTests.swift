import XCTest

/// Run on a fresh synthetic simulator with one image in Photos. No app test hooks.
@MainActor
final class PrivateOnboardingTests: XCTestCase {
    private let app = XCUIApplication()
    private let password = "Onboarding-public-test-2026"

    func testFullPrivateOnboarding() throws {
        continueAfterFailure = false
        app.launchArguments = ["-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        app.launch()
        XCTAssertTrue(app.staticTexts["Meet Chur"].waitForExistence(timeout: 15), "Use a fresh disposable installation")
        tap("Chur")
        tap("Set up vault", guide: true)
        field("Password", password)
        dismissKeyboard()
        dismissKeyboard()
        field("Repeat password", password)
        dismissKeyboard()
        tap("Create vault")
        XCTAssertTrue(app.staticTexts["Your recovery phrase"].waitForExistence(timeout: 30))
        tap("Show words")
        // Only this disposable test vault is read. Never attach its phrase screen.
        var words: [Int: String] = [:]
        for _ in 0..<5 {
            for text in app.staticTexts.allElementsBoundByIndex {
                let parts = text.label.trimmingCharacters(in: .whitespaces).split(separator: ".", maxSplits: 1)
                if parts.count == 2, let index = Int(parts[0]), (1...24).contains(index) {
                    words[index] = parts[1].trimmingCharacters(in: .whitespaces)
                }
            }
            if words.count == 24 { break }
            scrollContent(up: true)
        }
        XCTAssertEqual(words.count, 24)
        tap("I have written them down")
        var requested = Set<Int>()
        for _ in 0..<5 {
            for entry in app.textViews.allElementsBoundByIndex where entry.label.hasPrefix("Word ") {
                if let index = Int(entry.label.dropFirst(5).split(separator: " ").first ?? "") { requested.insert(index) }
            }
            if requested.count == 3 { break }
            scrollContent(up: true)
        }
        XCTAssertEqual(requested.count, 3)
        for index in requested.sorted() {
            let label = "Word \(index)"
            reveal(app.textViews.matching(NSPredicate(format: "label == %@ OR label BEGINSWITH %@", label, label + ", ")).firstMatch, up: false)
            field(label, try XCTUnwrap(words[index]))
            dismissKeyboard()
        }
        tap("Continue")
        XCTAssertTrue(app.tabBars.buttons["Library"].waitForExistence(timeout: 30))
        lesson("In Library, use Import")
        // The guide stays on Import after cancel, then advances only after the saved image.
        tap("Import")
        tap("Photos and videos")
        tap("Cancel")
        lesson("In Library, use Import")
        tap("Import")
        tap("Photos and videos")
        XCTAssertTrue(app.buttons["Done"].waitForExistence(timeout: 10))
        let photo = app.images.matching(NSPredicate(format: "label BEGINSWITH[c] 'Photo,'")).firstMatch
        XCTAssertTrue(photo.waitForExistence(timeout: 10))
        photo.tap()
        tap(app.buttons["Add"].exists ? "Add" : "Done")
        XCTAssertTrue(app.buttons["Keep original"].waitForExistence(timeout: 30))
        tap("Keep original")
        lesson("Open an item in Library")
        // Pick the single imported library item, not a control or guide decoration.
        let item = app.buttons.matching(NSPredicate(format: "label == 'Photo'")).firstMatch
        XCTAssertTrue(item.waitForExistence(timeout: 10))
        item.tap()
        lesson("Return to Library and open Search")
        app.navigationBars.buttons.element(boundBy: 0).tap()
        let search = app.searchFields.firstMatch
        reveal(search)
        search.tap(); search.typeText("onboarding")
        dismissKeyboard()
        lesson("Tap Lock to close the vault")
        tap("Got it", guide: true)
        app.tabBars.buttons["Settings"].tap()
        reveal(app.staticTexts["Auto-lock"])
        tap("Got it", guide: true)
        reveal(app.staticTexts["Access"], up: false)
        tap("Got it", guide: true)
        reveal(app.staticTexts["Write a backup file"])
        tap("Got it", guide: true)
        reveal(app.buttons["Public applications"], up: false)
        tap("Public applications")
        field("New 8-digit transition code", "01234567")
        field("Try the code again", "01234567")
        dismissKeyboard()
        tap("Test entry and enable")
        XCTAssertTrue(app.buttons["Sleep"].waitForExistence(timeout: 20))
        XCTAssertFalse(app.buttons["Finish tutorial"].exists)
        app.buttons["Sleep"].press(forDuration: 0.8)
        field("8-digit code", "01234567")
        tap("Continue")
        XCTAssertTrue(app.buttons["Unlock"].waitForExistence(timeout: 15))
        field("Password", password)
        app.typeText("\n") // The Go key submits authentication.
        // The OS icon confirmation makes the scene inactive. Keep normal privacy
        // locking and authenticate again if it returned to the public app.
        let iconAlert = XCUIApplication(bundleIdentifier: "com.apple.springboard").alerts.firstMatch
        if iconAlert.waitForExistence(timeout: 5) {
            XCTAssertTrue(iconAlert.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] 'icon'")).firstMatch.exists)
            iconAlert.buttons["OK"].tap()
        }
        if app.buttons["Sleep"].waitForExistence(timeout: 5) {
            app.buttons["Sleep"].press(forDuration: 0.8)
            field("8-digit code", "01234567")
            tap("Continue")
            field("Password", password)
            app.typeText("\n") // The Go key submits authentication.
        }
        XCTAssertTrue(app.tabBars.buttons["Library"].waitForExistence(timeout: 30))
        XCTAssertFalse(app.buttons["Finish tutorial"].exists)
        app.tabBars.buttons["Settings"].tap()
        reveal(app.buttons["Public applications"], up: false)
        tap("Public applications")
        XCTAssertTrue(app.buttons["Disable discreet mode"].exists)
        // Manual replay is allowed only here; background revokes the private guide.
        reveal(app.buttons["Learn with Chur"], up: false)
        tap("Learn with Chur")
        lesson("In Library, use Import")
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertFalse(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'In Library, use Import'")).firstMatch.exists)
    }

    /// Seed the CLI-produced fixtures in Files / On My iPhone / Chur restore fixtures.
    func testRestoreArchiveOnboarding() throws {
        continueAfterFailure = false
        app.launchArguments = ["-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        app.launch()
        XCTAssertTrue(app.staticTexts["Meet Chur"].waitForExistence(timeout: 15), "Use a fresh disposable installation")
        tap("Chur")
        tap("Set up vault", guide: true)
        tap("Restore from a backup")
        lesson("Enter the archive password")
        tap("Back")
        lesson("Choose a strong password")
        tap("Restore from a backup")
        field("Backup password or recovery phrase", password)
        dismissKeyboard()
        tap("Choose backup file")
        // Files moves Cancel into More when it reopens a folder on iOS 27.
        let cancel = app.buttons["Cancel"].firstMatch
        if !cancel.waitForExistence(timeout: 3) { tap("More") }
        XCTAssertTrue(cancel.waitForExistence(timeout: 10))
        cancel.tap()
        XCTAssertTrue(app.buttons["Choose backup file"].waitForExistence(timeout: 15))
        lesson("Enter the archive password")
        XCTAssertFalse(app.buttons["Choose backup file"].isEnabled)
        chooseArchive("restore-onboarding", credential: "Wrong-public-fixture-password")
        restoreMessage("Unable to unlock. Try again or use recovery.")
        lesson("Enter the archive password")
        XCTAssertFalse(app.buttons["Choose backup file"].isEnabled)
        XCTAssertFalse(app.tabBars.buttons["Library"].exists)
        chooseArchive("truncated", credential: password)
        restoreMessage("The vault could not be verified. Restore it from a backup.")
        lesson("Enter the archive password")
        XCTAssertFalse(app.buttons["Choose backup file"].isEnabled)
        chooseArchive("restore-onboarding", credential: password)
        lesson("The archive is restored")
        XCTAssertTrue(app.buttons["Unlock"].exists)
        XCTAssertFalse(app.tabBars.buttons["Library"].exists)
        field("Password", password)
        app.typeText("\n")
        lesson("In Library, use Import")
        XCTAssertFalse(app.staticTexts["Your recovery phrase"].exists)
        tap("Skip step", guide: true)
        lesson("Open an item in Library")
        let item = app.buttons.matching(NSPredicate(format: "label == 'Photo'")).firstMatch
        XCTAssertTrue(item.waitForExistence(timeout: 15))
        item.tap()
        lesson("Return to Library and open Search")
        let decoded = app.descendants(matching: .any).matching(NSPredicate(format: "value CONTAINS 'Zoom 100%' OR label CONTAINS 'Zoom 100%'" )).firstMatch
        XCTAssertTrue(decoded.waitForExistence(timeout: 15), "Restored image pixels must be decoded")
        XCTAssertFalse(app.staticTexts["Preview unavailable"].exists)
        let evidence = XCTAttachment(screenshot: app.screenshot())
        evidence.name = "restored-fixture-viewer"; evidence.lifetime = .keepAlways; add(evidence)
        app.navigationBars.buttons.element(boundBy: 0).tap()
        let search = app.searchFields.firstMatch
        reveal(search); search.tap(); search.typeText("restored-onboarding")
        dismissKeyboard()
        lesson("Tap Lock to close the vault")
        tap("Lock now")
        XCTAssertFalse(app.buttons["Finish tutorial"].exists)
    }

    private func restoreMessage(_ text: String) {
        let message = app.descendants(matching: .any).matching(NSPredicate(format: "label == %@", text)).firstMatch
        XCTAssertTrue(message.waitForExistence(timeout: 30))
    }

    private func chooseArchive(_ name: String, credential: String) {
        field("Backup password or recovery phrase", credential)
        dismissKeyboard()
        tap("Choose backup file")
        let file = app.cells.matching(NSPredicate(format: "label BEGINSWITH %@", name)).firstMatch
        if !file.waitForExistence(timeout: 3) {
            if app.tabBars.buttons["Browse"].exists { app.tabBars.buttons["Browse"].tap() }
            if app.navigationBars.buttons["Browse"].exists { app.navigationBars.buttons["Browse"].tap() }
            let local = app.descendants(matching: .any).matching(NSPredicate(format: "label == 'On My iPhone'")).firstMatch
            if local.waitForExistence(timeout: 3) { local.tap() }
            let folder = app.cells.matching(NSPredicate(format: "label BEGINSWITH 'Chur restore fixtures'")).firstMatch
            if folder.waitForExistence(timeout: 3) { folder.tap() }
        }
        if !file.waitForExistence(timeout: 10) { print("RESTORE PICKER: " + app.debugDescription) }
        XCTAssertTrue(file.exists)
        file.tap()
        if app.buttons["Open"].waitForExistence(timeout: 2) { app.buttons["Open"].tap() }
    }

    private func lesson(_ prefix: String) {
        let text = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)).firstMatch
        let reached = text.waitForExistence(timeout: 30)
        if !reached {
            print("GUIDE FAILURE: " + app.debugDescription)
            let evidence = XCTAttachment(screenshot: app.screenshot()); evidence.name = "guide-failure"; evidence.lifetime = .keepAlways; add(evidence)
        }
        XCTAssertTrue(reached, "Missing guide step: \(prefix)")
        print("ONBOARDING STEP: \(prefix)")
    }
    private func scrollContent(up: Bool) {
        let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: up ? 0.30 : 0.16))
        let end = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: up ? 0.16 : 0.30))
        start.press(forDuration: 0.05, thenDragTo: end)
    }
    private func reveal(_ element: XCUIElement, up: Bool = true, guide: Bool = false) {
        for _ in 0..<14 {
            if element.exists && element.isHittable { return }
            if guide {
                app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.91))
                    .press(forDuration: 0.05, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.73)))
            } else { scrollContent(up: up) }
        }
        if !element.exists || !element.isHittable {
            print("MISSING CONTROL: " + app.debugDescription)
            let evidence = XCTAttachment(screenshot: app.screenshot())
            evidence.name = "missing-control"; evidence.lifetime = .keepAlways; add(evidence)
        }
        XCTAssertTrue(element.exists && element.isHittable, "Control not available: \(element)")
    }
    private func tap(_ label: String, guide: Bool = false) {
        let button = app.buttons[label].firstMatch
        reveal(button, guide: guide)
        settle(button)
        XCTAssertTrue(button.isEnabled, "Disabled control: \(label)")
        if label == "Create vault" {
            let evidence = XCTAttachment(screenshot: app.screenshot())
            evidence.name = "create-before-tap"; evidence.lifetime = .keepAlways; add(evidence)
        }
        button.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
    }
    private func field(_ label: String, _ value: String) {
        let query = app.descendants(matching: .any).matching(NSPredicate(format: "(label == %@ OR label BEGINSWITH %@) AND (elementType == %d OR elementType == %d OR elementType == %d)", label, label + ", ", XCUIElement.ElementType.textField.rawValue, XCUIElement.ElementType.secureTextField.rawValue, XCUIElement.ElementType.textView.rawValue))
        let target = query.firstMatch
        reveal(target)
        settle(target)
        let frame = target.frame
        app.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: frame.midX, dy: frame.midY)).tap()
        app.typeText(value)
    }
    private func settle(_ element: XCUIElement) {
        var previous = element.frame
        var changed = Date()
        let stable = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            guard element.exists && element.isHittable else {
                self.scrollContent(up: true)
                changed = Date()
                return false
            }
            let current = element.frame
            if current != previous { previous = current; changed = Date() }
            return Date().timeIntervalSince(changed) > 0.4
        }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [stable], timeout: 15), .completed)
    }
    private func dismissKeyboard() {
        // The simulator may use a hardware keyboard; its offscreen Return AX node is not tappable.
        app.typeText("\n")
    }
}
