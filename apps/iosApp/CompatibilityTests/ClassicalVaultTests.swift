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
        app.typeText("Chur public compatibility fixture 2026\n")

        let file = app.buttons.matching(NSPredicate(format: "label == 'File' OR label BEGINSWITH 'File, '")).firstMatch
        XCTAssertTrue(file.waitForExistence(timeout: 30), "The classical vault contains one document")
        file.tap()
        XCTAssertTrue(app.staticTexts["proof.txt"].waitForExistence(timeout: 20))
        XCTAssertTrue(app.staticTexts["Chur classical vault compatibility fixture\n"].waitForExistence(timeout: 20))
    }
}
