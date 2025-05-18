//
//  DeviceCheckManager.swift
//  DeviceCheckApp
//
//  Created by Felipe Menezes on 23/03/25.
//

import DeviceCheck
import CryptoKit

enum DeviceCheckError: Error {
    case deviceUnsupported
    case deviceKeyError(Error)
    case deviceServiceError(Error)
    case deviceAttestError(Error)
}

/// DeviceCheck Manager ensure that instalition is from legitimaate app, using App Attest service
actor DeviceCheckManager {
    static let shared = DeviceCheckManager()
    private let deviceService = DeviceCheckService()
    private init() { }
    private var defaults = UserDefaults.standard
    private var keyIdContext = "com.fmmobile.devicecheckapp.keyid"
    private var publicKeyContext = "com.fmmobile.devicecheckapp.publicKey"
    private var otp: String = ""
    private var publicKey: String = ""
    
    func registerDevice() async throws(DeviceCheckError) {
        // check for compatibility
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw  .deviceUnsupported }
        print("Device is supported!")
        
        // check if has keyId
        guard defaults.string(forKey: keyIdContext) == nil else {
            let keyId = defaults.string(forKey: keyIdContext) ?? ""
            print("Key ID Already generated: \(keyId)")
            return
        }
        // generate unique instalattion key and receive this identifier
        do {
            let keyId = try await service.generateKey()
            // here we need to save our keyid
            defaults.set(keyId, forKey: keyIdContext)
            print("Key ID generated: \(keyId)")
            // challenge with service
        } catch {
            throw .deviceKeyError(error)
        }
    }

    func getOTP() async throws(DeviceCheckError) -> String {
        guard let keyId = defaults.string(forKey: keyIdContext) else {
            throw .deviceKeyError(NSError(domain: "DeviceCheckError", code: 1001))
        }
        do {
            let otp =  try await deviceService.fetchChallenge(keyID: keyId).challenge
            self.otp = otp
            return otp
        } catch {
            throw .deviceServiceError(error)
        }
    }

    func attestationCheck() async throws(DeviceCheckError) -> Bool {
        // check if has keyId
        guard defaults.string(forKey: publicKeyContext) == nil else {
            let publicKey = defaults.string(forKey: publicKeyContext) ?? ""
            self.publicKey = publicKey
            print("Public Key Already generated: \(publicKey)")
            return true
        }
        guard let keyId = defaults.string(forKey: keyIdContext) else { return false }
        if let otpData = otp.data(using: .utf8) {
            do {
                let hash = Data(SHA256.hash(data: otpData))
                print("challenge hash: \(hash)")
                let attestation = try await DCAppAttestService.shared.attestKey(keyId,
                                                                                clientDataHash: hash)
                print("Attestation Object Generated: \(attestation.base64EncodedString())")
                let result = try await deviceService.validateAttestation(attestationObject: attestation.base64EncodedString(),
                                                                         keyID: keyId,
                                                                         challenge: otp)
                self.publicKey = result.publicKey
                defaults.set(result.publicKey, forKey: publicKeyContext)
                return self.publicKey.isEmpty == false
            } catch let error as DCError {
                switch error {
                case DCError.serverUnavailable:
                    break
                default:
                    cleanUp()
                }
                throw .deviceAttestError(error)
            } catch {
                throw .deviceAttestError(error)
            }
        }
        return false
    }

    func assertionPayload(payload: [String: String]) async throws(DeviceCheckError) -> Bool {
        guard let keyId = defaults.string(forKey: keyIdContext) else { return false }
        do {
            let clientDataHash = Data(SHA256.hash(data:  try JSONEncoder().encode(payload)))
            let attestation = try await DCAppAttestService.shared.generateAssertion(keyId,
                                                                                    clientDataHash: clientDataHash)
            print("Assertion Object Generated: \(attestation.base64EncodedString())")
            let response = try await deviceService.validateAssertion(attestationObject: attestation.base64EncodedString(),
                                                                     keyID: keyId,
                                                                     challenge: otp,
                                                                     payload: try JSONEncoder().encode(payload),
                                                                     publicKey: publicKey)
            return response.transaction.isEmpty == false
        } catch let error as DCError {
            switch error {
            case DCError.serverUnavailable:
                break
            default:
                cleanUp()
            }
            throw .deviceAttestError(error)
        } catch {
            throw .deviceAttestError(error)
        }
    }

    private func cleanUp() {
        defaults.removeObject(forKey: keyIdContext)
        defaults.removeObject(forKey: publicKeyContext)
        otp=""
        publicKey=""
    }
    
}
