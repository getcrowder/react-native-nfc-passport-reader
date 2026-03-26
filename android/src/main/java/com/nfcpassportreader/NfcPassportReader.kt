package com.nfcpassportreader

import android.nfc.tech.IsoDep
import android.util.Base64
import android.util.Log
import com.nfcpassportreader.dto.AuthenticationStatus
import com.nfcpassportreader.dto.NfcResult
import net.sf.scuba.smartcards.CardService
import net.sf.scuba.smartcards.CardServiceException
import org.jmrtd.BACKeySpec
import org.jmrtd.PassportService
import org.jmrtd.lds.CardSecurityFile
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG15File
import java.io.ByteArrayInputStream
import java.security.SecureRandom

class NfcReadException(val errorCode: String, message: String, cause: Throwable? = null) : Exception(message, cause)

class NfcPassportReader {
  fun readPassport(
    isoDep: IsoDep,
    bacKey: BACKeySpec,
    skipPACE: Boolean = true,
    skipCA: Boolean = false,
    skipAA: Boolean = false,
    aaChallengeBase64: String? = null
  ): NfcResult {
    try {
      // Passport BAC/DG reads can take longer than typical tag scans; a low timeout
      // can surface as "Tag was lost" even when the device is held still.
      isoDep.timeout = 30000

      val cardService = CardService.getInstance(isoDep)
      cardService.open()

      // Create PassportService with conservative settings to avoid file enumeration issues
      val service = PassportService(
        cardService,
        PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        false, // shouldCheckSecurity - set to false to avoid security checks that might fail
        false  // shouldUseSFI - set to false to avoid SFI issues
      )
      service.open()

      var paceSucceeded = false

      if (!skipPACE) {
        try {
          val cardSecurityFile =
            CardSecurityFile(service.getInputStream(PassportService.EF_CARD_SECURITY))
          val securityInfoCollection = cardSecurityFile.securityInfos

          for (securityInfo in securityInfoCollection) {
            if (securityInfo is PACEInfo) {
              Log.d("NFC_DEBUG", "Attempting PACE authentication...")
              service.doPACE(
                bacKey,
                securityInfo.objectIdentifier,
                PACEInfo.toParameterSpec(securityInfo.parameterId),
                null
              )
              paceSucceeded = true
              Log.d("NFC_DEBUG", "PACE authentication succeeded")
            }
          }
        } catch (e: Exception) {
          Log.d("NFC_DEBUG", "PACE authentication failed: ${e.message}")
          e.printStackTrace()
        }
      } else {
        Log.d("NFC_DEBUG", "PACE skipped - will use BAC authentication")
      }

      service.sendSelectApplet(paceSucceeded)

      if (!paceSucceeded) {
        try {
          Log.d("NFC_DEBUG", "Trying to read EF_COM without BAC...")
          service.getInputStream(PassportService.EF_COM).read()
          Log.d("NFC_DEBUG", "EF_COM readable without BAC - passport doesn't require BAC")
        } catch (e: Exception) {
          Log.d("NFC_DEBUG", "EF_COM not readable - performing BAC authentication")
          e.printStackTrace()
          service.doBAC(bacKey)
          Log.d("NFC_DEBUG", "BAC Authentication SUCCESSFUL!")
        }
      } else {
        Log.d("NFC_DEBUG", "PACE succeeded - skipping BAC")
      }

      val nfcResult = NfcResult()
      val rawDataGroups = HashMap<String, String>()
      nfcResult.dataGroups = rawDataGroups

      // --- Chip Authentication (CA) ---
      // Must run BEFORE reading data groups: CA re-keys the session with stronger keys.
      var chipAuthPassed: Boolean? = null
      if (!skipCA) {
        try {
          Log.d("NFC_DEBUG", "Attempting Chip Authentication...")
          val dg14Bytes = service.getInputStream(PassportService.EF_DG14).readBytes()
          rawDataGroups["DG14"] = Base64.encodeToString(dg14Bytes, Base64.NO_WRAP)
          Log.d("NFC_DEBUG", "DG14 read successfully (${dg14Bytes.size} bytes)")

          val dg14File = DG14File(ByteArrayInputStream(dg14Bytes))
          val chipAuthPublicKeyInfos = dg14File.chipAuthenticationPublicKeyInfos

          if (chipAuthPublicKeyInfos.isNotEmpty()) {
            try {
              val chipAuthInfos = dg14File.chipAuthenticationInfos
              val publicKeyInfo = chipAuthPublicKeyInfos.first()
              val keyId = publicKeyInfo.keyId
              val oid = if (chipAuthInfos.isNotEmpty()) {
                chipAuthInfos.first().objectIdentifier
              } else {
                publicKeyInfo.objectIdentifier
              }
              service.doEACCA(keyId, oid, publicKeyInfo.objectIdentifier, publicKeyInfo.subjectPublicKey)
              chipAuthPassed = true
              Log.d("NFC_DEBUG", "Chip Authentication SUCCEEDED")
            } catch (e: Exception) {
              Log.d("NFC_DEBUG", "Chip Authentication FAILED: ${e.message}")
              chipAuthPassed = false
              // Re-establish BAC to continue reading
              try {
                service.doBAC(bacKey)
                Log.d("NFC_DEBUG", "BAC re-established after CA failure")
              } catch (bacE: Exception) {
                Log.w("NFC_DEBUG", "BAC re-establishment failed: ${bacE.message}")
              }
            }
          } else {
            Log.d("NFC_DEBUG", "DG14 present but no ChipAuthenticationPublicKeyInfo found")
          }
        } catch (e: Exception) {
          Log.d("NFC_DEBUG", "DG14 not available: ${e.message}")
          // chipAuthPassed remains null — CA not evaluable
        }
      }

      // Read DG1 (mandatory - contains MRZ data)
      val dg1Bytes = service.getInputStream(PassportService.EF_DG1).readBytes()
      rawDataGroups["DG1"] = Base64.encodeToString(dg1Bytes, Base64.NO_WRAP)

      // Try to read DG11 (optional)
      try {
        val dg11Bytes = service.getInputStream(PassportService.EF_DG11).readBytes()
        rawDataGroups["DG11"] = Base64.encodeToString(dg11Bytes, Base64.NO_WRAP)
        Log.d("NFC_DEBUG", "DG11 read successfully")
      } catch (e: Exception) {
        Log.d("NFC_DEBUG", "DG11 not available or failed to read: ${e.message}")
      }

      // Read SOD (mandatory - contains signed hashes for integrity verification)
      val sodBytes = service.getInputStream(PassportService.EF_SOD).readBytes()
      rawDataGroups["SOD"] = Base64.encodeToString(sodBytes, Base64.NO_WRAP)
      Log.d("NFC_DEBUG", "SOD read successfully (${sodBytes.size} bytes)")

      // Read DG2 (mandatory - contains facial image)
      val dg2Bytes = service.getInputStream(PassportService.EF_DG2).readBytes()
      rawDataGroups["DG2"] = Base64.encodeToString(dg2Bytes, Base64.NO_WRAP)
      Log.d("NFC_DEBUG", "DG2 read successfully (${dg2Bytes.size} bytes)")

      // --- Active Authentication (AA) ---
      // Runs AFTER all DGs are read (AA is read-only, doesn't affect session).
      var activeAuthPassed: Boolean? = null
      var aaSignatureBase64: String? = null
      var aaChallengeUsedBase64: String? = null

      if (!skipAA) {
        try {
          Log.d("NFC_DEBUG", "Attempting Active Authentication...")
          val dg15Bytes = service.getInputStream(PassportService.EF_DG15).readBytes()
          rawDataGroups["DG15"] = Base64.encodeToString(dg15Bytes, Base64.NO_WRAP)
          Log.d("NFC_DEBUG", "DG15 read successfully (${dg15Bytes.size} bytes)")

          val dg15File = DG15File(ByteArrayInputStream(dg15Bytes))
          val aaPublicKey = dg15File.publicKey

          if (aaPublicKey != null && aaChallengeBase64 != null) {
            // Only attempt AA with backend-provided challenge
            val challenge = Base64.decode(aaChallengeBase64, Base64.NO_WRAP)
            aaChallengeUsedBase64 = Base64.encodeToString(challenge, Base64.NO_WRAP)

            try {
              val response = service.doAA(aaPublicKey, null, "SHA-256", challenge)
              aaSignatureBase64 = Base64.encodeToString(response.response, Base64.NO_WRAP)
              activeAuthPassed = true
              Log.d("NFC_DEBUG", "Active Authentication SUCCEEDED")
            } catch (e: Exception) {
              Log.d("NFC_DEBUG", "Active Authentication FAILED: ${e.message}")
              activeAuthPassed = false
            }
          } else {
            Log.d("NFC_DEBUG", "DG15 present but no AA challenge found")
          }
        } catch (e: Exception) {
          Log.d("NFC_DEBUG", "DG15 not available: ${e.message}")
          // activeAuthPassed remains null — AA not evaluable
        }
      }

      nfcResult.authentication = AuthenticationStatus(
        method = if (paceSucceeded) "PACE" else "BAC",
        chipAuthenticationPassed = chipAuthPassed,
        activeAuthenticationPassed = activeAuthPassed,
        aaSignature = aaSignatureBase64,
        aaChallenge = aaChallengeUsedBase64
      )

      Log.d(
        "NFC_DEBUG",
        "🔐 Authentication Status: method=${nfcResult.authentication.method}, " +
          "CA=${chipAuthPassed}, AA=${activeAuthPassed}, skipCA=$skipCA, skipAA=$skipAA"
      )

      return nfcResult
    } catch (e: CardServiceException) {
      Log.d("NFC_DEBUG", "CardServiceException during NFC reading: ${e.message}")
      e.printStackTrace()

      val msg = e.message ?: ""
      val errorCode = when {
        // BAC/PACE mutual authentication failure
        msg.contains("Mutual authentication failed", ignoreCase = true) ||
        msg.contains("6300") ||
        msg.contains("6985") -> "INVALID_MRZ_KEY"
        // Tag lost / connection error
        msg.contains("Tag was lost", ignoreCase = true) ||
        msg.contains("IOException", ignoreCase = true) ||
        msg.contains("transceive", ignoreCase = true) -> "TAG_LOST"
        else -> "READ_FAILED"
      }

      throw NfcReadException(errorCode, "Card service error during passport reading: $msg", e)
    } catch (e: NfcReadException) {
      throw e
    } catch (e: java.io.IOException) {
      Log.d("NFC_DEBUG", "IOException during NFC reading: ${e.message}")
      e.printStackTrace()
      throw NfcReadException("TAG_LOST", "Connection lost during passport reading: ${e.message}", e)
    } catch (e: Exception) {
      Log.d("NFC_DEBUG", "General exception during NFC reading: ${e.message}")
      e.printStackTrace()
      throw NfcReadException("READ_FAILED", "Failed to read passport data: ${e.message}", e)
    }
  }
}
