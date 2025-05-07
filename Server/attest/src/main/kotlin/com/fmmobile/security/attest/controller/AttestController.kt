package com.fmmobile.security.attest.controller

import ch.veehait.devicecheck.appattest.AppleAppAttest
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import ch.veehait.devicecheck.appattest.assertion.*
import ch.veehait.devicecheck.appattest.common.App
import ch.veehait.devicecheck.appattest.common.AppleAppAttestEnvironment
import com.fmmobile.security.attest.controller.model.AssertionObject
import com.fmmobile.security.attest.controller.model.AttestationRequest
import com.fmmobile.security.attest.controller.model.ChallengeRequest
import com.fmmobile.security.attest.controller.model.ChallengeResponse
import com.fmmobile.security.attest.exception.ResourceNotFoundException
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*


@Tag(name = "Attest endpoint")
@RestController
@RequestMapping("attest")
class AttestController {
    val SECRET_KEY = "Y46Yi9pq3vrTNqBm2rA2LXurfEJNqC7R"

    val appleAppAttest = AppleAppAttest(
        app = App("<YOUT TEAM ID>", "com.fmmobile.DeviceCheckApp"),
        appleAppAttestEnvironment = AppleAppAttestEnvironment.DEVELOPMENT,
    )
    val generator = OtpGenerator()
    // Create an AttestationValidator instance

    @PostMapping("challenge", consumes = [MediaType.APPLICATION_JSON_VALUE],
        produces = [MediaType.APPLICATION_JSON_VALUE])
    fun challenge(@RequestBody attest: ChallengeRequest): ChallengeResponse {
        val otp = generator.generateOtp(attest.keyId)
        return ChallengeResponse(otp, generator.getOtpExpiration().toLocalDateTime())
    }

    @PostMapping(consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun validate(@RequestBody attest: AttestationRequest): ResponseEntity<*>? {
        val attestationValidator = appleAppAttest.createAttestationValidator()
        if (!generator.validateOtp(attest.keyId, attest.challenge)) {
            throw ResourceNotFoundException("Invalid request")
        }
        val result: ValidatedAttestation = attestationValidator.validate(
            attestationObject = Base64.getDecoder().decode(attest.attestationObject),
            keyIdBase64 = attest.keyId,
            serverChallenge = attest.challenge.toByteArray(),
        )

        // Extract public key
        val publicKey = result.certificate.publicKey as ECPublicKey
        val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.encoded)

        return ResponseEntity.ok(mapOf("publicKey" to publicKeyBase64))
    }

    @PostMapping("assertion",
        consumes = [MediaType.APPLICATION_JSON_VALUE],
        produces = [MediaType.APPLICATION_JSON_VALUE])
    fun assertion(@RequestBody attest: AssertionObject): ResponseEntity<*>? {
        if (!assertionValidation(attest)) {
            throw ResourceNotFoundException("Invalid request")
        }

        return respondJsonFromBase64(attest.clientData)
    }

    private fun assertionValidation(attest: AssertionObject): Boolean {
        val assertionChallengeValidator = object : AssertionChallengeValidator {
            override fun validate(
                assertionObj: Assertion,
                clientData: ByteArray,
                attestationPublicKey: ECPublicKey,
                challenge: ByteArray,
            ): Boolean {
                return generator.validateOtp(attest.keyId, attest.challenge)
            }
        }
        val assertionValidator = appleAppAttest.createAssertionValidator(assertionChallengeValidator)
        val publicKey = base64ToECPublicKey(attest.publicKey)
        val assertion = assertionValidator.validate(
            assertionObject = Base64.getDecoder().decode(attest.attestationObject),
            clientData = Base64.getDecoder().decode(attest.clientData),
            attestationPublicKey = publicKey,
            lastCounter = 0,
            challenge = attest.challenge.toByteArray(),
        )
        return true
    }

    fun base64ToECPublicKey(base64: String): ECPublicKey {
        val keyBytes = Base64.getDecoder().decode(base64)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(keySpec) as ECPublicKey
    }

    fun respondJsonFromBase64(base64: String): ResponseEntity<String> {
        val decodedBytes = Base64.getDecoder().decode(base64)
        val json = decodedBytes.toString(Charsets.UTF_8)
        return ResponseEntity.ok(json)
    }
}