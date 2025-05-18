//
//  DeviceCheckServer.swift
//  DeviceCheckApp
//
//  Created by Felipe Menezes on 23/03/25.
//

import Foundation
import CryptoKit

struct ChallengeResponse: Decodable {
    let challenge: String
    let expiration: String
}

struct AttestationResponse: Decodable {
    let publicKey: String
}

struct TransactionResponse: Decodable {
    let transaction: String
}

class DeviceCheckService {
    let domainLocal = "http://<YOU LOCAL MACHINE>.local"
    func fetchChallenge(keyID: String) async throws -> ChallengeResponse {
        guard let url = URL(string: "\(domainLocal):8200/attest/challenge") else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let payload = ["keyId": keyID]
        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse, 200..<300 ~= httpResponse.statusCode else {
            throw URLError(.badServerResponse)
        }

        return try JSONDecoder().decode(ChallengeResponse.self, from: data)
    }

    @discardableResult
    func validateAttestation(attestationObject: String,
                             keyID: String,
                             challenge: String) async throws -> AttestationResponse {
        guard let url = URL(string: "\(domainLocal):8200/attest") else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let payload = [
            "challenge": challenge,
            "keyId": keyID,
            "attestationObject": attestationObject
        ]
        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse, 200 ~= httpResponse.statusCode else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode(AttestationResponse.self, from: data)
    }

    @discardableResult
    func validateAssertion(attestationObject: String,
                           keyID: String,
                           challenge: String,
                           payload: Data,
                           publicKey: String) async throws -> TransactionResponse {
        guard let url = URL(string: "\(domainLocal):8200/attest/assertion") else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let payload = [
            "challenge": challenge,
            "keyId": keyID,
            "attestationObject": attestationObject,
            "publicKey": publicKey,
            "clientData": payload.base64EncodedString()
            
        ]
        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse, 200 ~= httpResponse.statusCode else {
            throw URLError(.badServerResponse)
        }
        print("JSON: \(String(data: data, encoding: .utf8))")
        return try JSONDecoder().decode(TransactionResponse.self, from: data)
    }
}
