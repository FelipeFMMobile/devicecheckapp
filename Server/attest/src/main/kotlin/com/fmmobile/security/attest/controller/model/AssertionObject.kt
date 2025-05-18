package com.fmmobile.security.attest.controller.model

data class AssertionObject(
    var attestationObject: String,
    var keyId: String,
    var challenge: String,
    var publicKey: String,
    var clientData: String
)
