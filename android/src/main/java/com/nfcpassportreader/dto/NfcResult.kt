package com.nfcpassportreader.dto

data class NfcResult(
  var authentication: AuthenticationStatus = AuthenticationStatus(),
  var dataGroups: Map<String, String> = emptyMap()
)

data class AuthenticationStatus(
  var method: String = "BAC",
  var chipAuthenticationPassed: Boolean? = null,
  var activeAuthenticationPassed: Boolean? = null,
  var aaSignature: String? = null,
  var aaChallenge: String? = null
)
