package com.fmmobile.security.attest.controller


import com.bastiaanjansen.otp.HMACAlgorithm
import com.bastiaanjansen.otp.TOTP
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.Base64
import javax.crypto.KeyGenerator

class OtpGenerator {
    private val optLimit: Long = 30 // OTP changes every 30 seconds
    // Generate a new secret key
    fun generateSecret(): String {
        val keyGenerator = KeyGenerator.getInstance("HmacSHA1")
        keyGenerator.init(160) // 160-bit key for SHA1
        val secretKey = keyGenerator.generateKey()
        return Base64.getEncoder().encodeToString(secretKey.encoded)
    }

    // Create a TOTP generator
    private fun getTotpGenerator(secret: String): TOTP {
        val secretBytes = Base64.getDecoder().decode(secret)
        return TOTP.Builder(secretBytes)
            .withAlgorithm(HMACAlgorithm.SHA1) // SHA-1, SHA-256, SHA-512 supported
            .withPeriod(Duration.ofSeconds(this.optLimit))
            .withPasswordLength(6)
            .build()
    }

    // Generate OTP for the given secret
    fun generateOtp(secret: String): String {
        val totp = getTotpGenerator(secret)
        return totp.now()
    }

    // Validate OTP
    fun validateOtp(secret: String, otp: String): Boolean {
        val totp = getTotpGenerator(secret)
        return totp.verify(otp)
    }

    // Get OTP expiration time
    fun getOtpExpiration(): ZonedDateTime {
        val period = Duration.ofSeconds(this.optLimit)
        val currentTimestamp = Instant.now().epochSecond
        val validFrom = currentTimestamp - (currentTimestamp % period.seconds)
        val expiresAt = Instant.ofEpochSecond(validFrom + period.seconds)
        return ZonedDateTime.ofInstant(expiresAt, ZoneId.systemDefault())
    }
}