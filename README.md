# Apple App Attest iOS and Backend Validator

This project is a Kotlin-based backend API designed to validate **Apple App Attest** attestation and assertion objects from iOS devices. It ensures the authenticity of the device and cryptographic keys used in your mobile application.

## 🔐 Features

- Validates **attestation objects** from the Apple App Attest service.
- Extracts and stores public keys from attestation responses.
- Verifies **assertion objects** and their digital signatures.
- Supports OTP-based challenge verification.
- Built with Apple’s App Attest SDK + Kotlin + Spring Boot.

## 🧰 Tech Stack

- Kotlin + Spring Boot
- Java Security APIs (`ECPublicKey`, `X509Certificate`)
- Base64 encoding/decoding
- Jackson for JSON serialization
- Apple App Attest validation libraries
- XCode 16
- Swift 5

## 🚀 Getting Started

Make sure you have **Java 17+** and **Gradle** installed.

```bash
./gradlew bootRun
```
Include you Google config files for Firebase and also your own credetials of your Apple account. 

## Developed by Felipe Menezes
