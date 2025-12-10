package com.nfcpassportreader.dto

data class NfcResult(
  var firstName: String = "",
  var lastName: String = "",
  var dateOfBirth: String = "",
  var gender: String = "",
  var nationality: String = "",
  var personalNumber: String = "",
  var placeOfBirth: String = "",
  var documentNumber: String = "",
  var dateOfExpiry: String = "",
  var issuingAuthority: String = "",
  var documentType: String = "",
  var mrz: String = "",
  var photo: String? = null,
  var authentication: AuthenticationStatus = AuthenticationStatus()
)

data class AuthenticationStatus(
  var method: String = "BAC",
  var chipAuthenticationPassed: Boolean? = null,
  var activeAuthenticationPassed: Boolean? = null
)
