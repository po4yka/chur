import XCTest

@MainActor
final class IncomingShareSystemTests: XCTestCase {
    func testImportsFileFromSystemShareSheet() throws {
        continueAfterFailure = false
        let sender = XCUIApplication(bundleIdentifier: "dev.po4yka.chur.livephototesthost")
        sender.launchArguments = ["-ShareFixture"]
        sender.launch()
        sender.buttons["Share fixture"].tap()

        let activity = sender.descendants(matching: .any).matching(NSPredicate(
            format: "label == %@ OR label == %@", "Save to Chur PQ", "Chur PQ"
        )).firstMatch
        if !activity.waitForExistence(timeout: 5) || !activity.isHittable {
            let more = sender.buttons["More"].firstMatch
            if !more.isHittable {
                let row = sender.cells.containing(.button, identifier: "AirDrop").firstMatch
                if row.exists { row.swipeLeft() }
            }
            XCTAssertTrue(more.waitForExistence(timeout: 10))
            more.tap()
        }
        XCTAssertTrue(activity.waitForExistence(timeout: 10))
        activity.tap()
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
}
