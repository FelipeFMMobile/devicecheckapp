package com.fmmobile.security.attest.exception

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ResponseStatus

@ResponseStatus(HttpStatus.NOT_FOUND)
class ResourceNotFoundException : RuntimeException {
    private val serialVersionUID: Long = 1L
    constructor(exception: String) : super(exception)
}