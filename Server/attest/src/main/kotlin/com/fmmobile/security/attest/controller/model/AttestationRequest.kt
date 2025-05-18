package com.fmmobile.security.attest.controller.model

data class AttestationRequest(
    var attestationObject: String,
    var keyId: String,
    var challenge: String
)
