import XCTest

@MainActor
final class ClassicalVaultTests: XCTestCase {
    func testReadsDocumentFromClassicalVault() throws {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        app.launch()

        let settings = app.buttons["Settings"].firstMatch
        XCTAssertTrue(settings.waitForExistence(timeout: 30))
        settings.tap()
        app.buttons["Private vault"].tap()
        let password = app.descendants(matching: .any).matching(NSPredicate(
            format: "(label == %@ OR label BEGINSWITH %@) AND elementType IN %@",
            "Password", "Password, ",
            [XCUIElement.ElementType.textField, .secureTextField, .textView].map(\.rawValue)
        )).firstMatch
        XCTAssertTrue(password.waitForExistence(timeout: 15))
        password.tap()
        password.typeText("Chur public compatibility fixture 2026")
        let unlock = app.buttons["Unlock"].firstMatch
        XCTAssertTrue(unlock.wait(for: \.isEnabled, toEqual: true, timeout: 15), screenState(app))
        if !unlock.isHittable {
            let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.4))
            let end = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.18))
            start.press(forDuration: 0.1, thenDragTo: end)
        }
        XCTAssertTrue(unlock.isHittable, screenState(app))
        unlock.tap()

        let library = app.tabBars.buttons["Library"].firstMatch
        XCTAssertTrue(library.waitForExistence(timeout: 60), "The Release app did not open the vault. " + screenState(app))
        if !library.isSelected { library.tap() }
        let file = app.buttons.matching(NSPredicate(format: "label == 'File' OR label BEGINSWITH 'File, '")).firstMatch
        XCTAssertTrue(file.waitForExistence(timeout: 30), "The classical vault contains one document. " + screenState(app))
        file.tap()
        XCTAssertTrue(app.staticTexts["proof.txt"].waitForExistence(timeout: 20))
        XCTAssertTrue(app.staticTexts["Chur classical vault compatibility fixture\n"].waitForExistence(timeout: 20))
    }

    private func screenState(_ app: XCUIApplication) -> String {
        // Report screen markers only. Text field values never enter the failure report.
        let markers = ["Meet Chur", "Private vault", "Return to public screen", "Password", "Unlock",
                       "Opening", "Use recovery phrase", "Unable to unlock. Try again or use recovery.",
                       "The vault locked. Unlock it to continue.", "Library", "Lock now", "File", "proof.txt"]
        let controls = app.descendants(matching: .any).matching(NSPredicate(format: "label IN %@", markers))
        let labels = Set(controls.allElementsBoundByIndex.map(\.label)).sorted()
        return "Screen markers \(labels), keyboard visible \(app.keyboards.firstMatch.exists)."
    }
}
