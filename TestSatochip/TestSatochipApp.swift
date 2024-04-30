//
//  SatochipTestApp.swift
//  SatochipTest
//
//  Created by Satochip on 22/04/2024.
//

import SwiftUI

@main
struct TestSatochipApp: App {
    //@UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
        
    @StateObject var cardState = CardState()
    
    var body: some Scene {
        WindowGroup {
            HomeView()
                .environmentObject(cardState)
        }
    }
}
