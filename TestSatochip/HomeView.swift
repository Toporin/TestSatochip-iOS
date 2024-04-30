//
//  HomeView.swift
//  SatochipTest
//
//  Created by Satochip on 22/04/2024.
//
import Foundation
import SwiftUI

struct HomeView: View {
    // MARK: - Properties
    @EnvironmentObject var cardState: CardState
    
    // MARK: - Literals
    let viewTitle: String = "Satochip Test App"
    
    // MARK: Body
    var body: some View {
        NavigationView {
            ZStack {
                VStack {
                    HStack {
                        // Title
                        Text(viewTitle)
                    } // end hstack
                    .frame(height: 48)
                    Spacer()
                } // end main vStack
            } // ZStack
            .overlay(
                VStack {
                    Spacer()
                    ScanButton {
                        Task {
                            await cardState.executeQuery()
                        }
                    }
                    Spacer()
                }
            ) //overlay
        }// NavigationView
    }// body
    
} // HomeView
