//
//  ContentView.swift
//  DeviceCheckApp
//
//  Created by Felipe Menezes on 23/03/25.
//

import SwiftUI

struct ContentView: View {
    @State private var publicKey = false
    var body: some View {
        VStack(spacing: 24.0) {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("App Attestation")
            List {
                Section("Attestation") {
                    Button("Register") {
                        Task {
                            do {
                                try await DeviceCheckManager.shared.registerDevice()
                                _ = try await  DeviceCheckManager.shared.getOTP()
                                let result = try await DeviceCheckManager.shared.attestationCheck()
                                print("Attestation Passed \(result)")
                                publicKey = result
                            } catch {
                                print("Error: \(error)")
                            }
                        }
                    }
                }
                if publicKey {
                    Section("Assertion Payload") {
                        Button("Request") {
                            Task {
                                do {
                                    _ = try await  DeviceCheckManager.shared.getOTP()
                                    let payload = ["transaction": "123"]
                                    let result = try await DeviceCheckManager.shared
                                        .assertionPayload(payload: payload)
                                    print("Assertion Passed \(result)")
                                    
                                } catch {
                                    print("Error: \(error)")
                                }
                            }
                        }
                    }
                }
            }
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
