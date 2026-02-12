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

class NfcPassportReader {
  fun readPassport(
    isoDep: IsoDep,
    bacKey: BACKeySpec,
    skipPACE: Boolean = true,
    skipCA: Boolean = false,
    skipAA: Boolean = false
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

      // Note: CA/AA are not implemented on Android yet; null means not attempted.
      nfcResult.authentication = AuthenticationStatus(
        method = if (paceSucceeded) "PACE" else "BAC",
        chipAuthenticationPassed = null,
        activeAuthenticationPassed = null
      )

      Log.d(
        "NFC_DEBUG",
        "🔐 Authentication Status: method=${nfcResult.authentication.method}, skipCA=$skipCA, skipAA=$skipAA (CA/AA not implemented on Android)"
      )

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

      // Try to read SOD (optional)
      try {
        val sodBytes = service.getInputStream(PassportService.EF_SOD).readBytes()
        rawDataGroups["SOD"] = Base64.encodeToString(sodBytes, Base64.NO_WRAP)
        Log.d("NFC_DEBUG", "SOD read successfully (${sodBytes.size} bytes)")
      } catch (e: Exception) {
        Log.d("NFC_DEBUG", "SOD not available or failed to read: ${e.message}")
      }

      // Try to read DG2 (optional)
      try {
        val dg2Bytes = service.getInputStream(PassportService.EF_DG2).readBytes()
        rawDataGroups["DG2"] = Base64.encodeToString(dg2Bytes, Base64.NO_WRAP)
        Log.d("NFC_DEBUG", "DG2 read successfully (${dg2Bytes.size} bytes)")
      } catch (e: Exception) {
        Log.d("NFC_DEBUG", "DG2 not available or failed to read: ${e.message}")
      }

      return nfcResult
    } catch (e: CardServiceException) {
      Log.d("NFC_DEBUG", "CardServiceException during NFC reading: ${e.message}")
      e.printStackTrace()

      // Handle specific APDU errors
      when {
        e.message?.contains("6A82") == true -> {
          Log.d("NFC_DEBUG", "FILE NOT FOUND error - some data groups may not exist on this passport")
          throw Exception("Passport reading failed: Some data groups listed in passport are not accessible or do not exist. This is common with certain passport types. Error: ${e.message}")
        }
        e.message?.contains("6982") == true -> {
          Log.d("NFC_DEBUG", "SECURITY STATUS NOT SATISFIED error - access denied to some data groups")
          throw Exception("Passport reading failed: Access denied to some data groups. This passport may require special security access for certain files. Error: ${e.message}")
        }
        else -> {
          throw Exception("Card service error during passport reading: ${e.message}")
        }
      }
    } catch (e: Exception) {
      Log.d("NFC_DEBUG", "General exception during NFC reading: ${e.message}")
      e.printStackTrace()
      throw Exception("Failed to read passport data: ${e.message}")
    }
  }
}
