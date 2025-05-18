package com.fmmobile.security.attest.controller.model

import java.time.LocalDateTime

data class ChallengeResponse(
    var challenge: String,
    var expiration: LocalDateTime
)
