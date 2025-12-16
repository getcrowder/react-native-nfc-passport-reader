package com.nfcpassportreader

import android.content.Context
import android.graphics.Bitmap
import android.nfc.tech.IsoDep
import android.util.Base64
import android.util.Log
import com.nfcpassportreader.dto.*
import com.nfcpassportreader.utils.*
import net.sf.scuba.smartcards.CardService
import net.sf.scuba.smartcards.CardServiceException
import org.jmrtd.BACKeySpec
import org.jmrtd.PassportService
import org.jmrtd.lds.CardSecurityFile
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.icao.DG11File
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.iso19794.FaceImageInfo
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream

class NfcPassportReader(context: Context) {
  private val bitmapUtil = BitmapUtil(context)
  private val dateUtil = DateUtil()

  fun readPassport(
    isoDep: IsoDep,
    bacKey: BACKeySpec,
    includeImages: Boolean,
    skipPACE: Boolean = true,
    skipCA: Boolean = false,
    skipAA: Boolean = false
  ): NfcResult {
    try {
      isoDep.timeout = 10000

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

      // Set authentication status
      // Note: Chip Authentication is not currently implemented on Android
      // chipAuthenticationPassed = null means CA was not attempted
      nfcResult.authentication = AuthenticationStatus(
        method = if (paceSucceeded) "PACE" else "BAC",
        chipAuthenticationPassed = null, // CA not implemented on Android yet
        activeAuthenticationPassed = null // AA not implemented on Android yet (skipAA is accepted for API parity)
      )

      Log.d(
        "NFC_DEBUG",
        "🔐 Authentication Status: method=${nfcResult.authentication.method}, skipCA=$skipCA, skipAA=$skipAA (CA/AA not implemented on Android)"
      )

      // Read DG1 (mandatory - contains MRZ data)
      val dg1In = service.getInputStream(PassportService.EF_DG1)
      val dg1Bytes = dg1In.readBytes()
      rawDataGroups["DG1"] = Base64.encodeToString(dg1Bytes, Base64.NO_WRAP)
      val dg1File = DG1File(ByteArrayInputStream(dg1Bytes))
      val mrzInfo = dg1File.mrzInfo

      // Extract data from MRZ first (as fallback)
      mrzInfo.let {
        // Date of expiry
        if (!it.dateOfExpiry.isNullOrEmpty()) {
          nfcResult.dateOfExpiry = dateUtil.convertFromMrzDate(it.dateOfExpiry) ?: ""
        }
        
        if (!it.dateOfBirth.isNullOrEmpty()) {
          nfcResult.dateOfBirth = dateUtil.convertFromMrzDate(it.dateOfBirth) ?: ""
        }

        nfcResult.lastName = it.primaryIdentifier?.replace("<", " ")?.trim() ?: ""
        nfcResult.firstName = it.secondaryIdentifier?.replace("<", " ")?.trim() ?: ""

        nfcResult.personalNumber = it.personalNumber?.replace("<", "")?.trim() ?: ""
        nfcResult.gender = it.gender?.toString() ?: ""
        nfcResult.documentNumber = it.documentNumber?.replace("<", "")?.trim() ?: ""
        nfcResult.nationality = it.nationality ?: ""
        nfcResult.issuingAuthority = it.issuingState ?: ""
        nfcResult.documentType = it.documentCode?.replace("<", "")?.trim() ?: ""
        nfcResult.mrz = it.toString()
      }

      // Try to read DG11 (optional data group that may contain additional info)
      try {
        val dg11In = service.getInputStream(PassportService.EF_DG11)
        val dg11Bytes = dg11In.readBytes()
        rawDataGroups["DG11"] = Base64.encodeToString(dg11Bytes, Base64.NO_WRAP)
        val dg11File = DG11File(ByteArrayInputStream(dg11Bytes))
        Log.d("NFC_DEBUG", "DG11 read successfully")

        if (!dg11File.nameOfHolder.isNullOrEmpty()) {
          val fullName = dg11File.nameOfHolder
          if (fullName.contains("<<")) {
            nfcResult.lastName = fullName.substringBefore("<<").replace("<", " ").trim()
            nfcResult.firstName = fullName.substringAfter("<<").replace("<", " ").trim()
          }
        }

        if (!dg11File.placeOfBirth.isNullOrEmpty()) {
          nfcResult.placeOfBirth = dg11File.placeOfBirth.joinToString(separator = " ")
        }

        if (!dg11File.fullDateOfBirth.isNullOrEmpty()) {
          nfcResult.dateOfBirth = dateUtil.convertFromFullDate(dg11File.fullDateOfBirth) ?: nfcResult.dateOfBirth
        }
      } catch (e: Exception) {
        Log.d("NFC_DEBUG", "DG11 not available or failed to read: ${e.message}")
      }

      // Try to read SOD
      try {
        val sodIn = service.getInputStream(PassportService.EF_SOD)
        // Read the full stream
        val buffer = ByteArrayOutputStream()
        val data = ByteArray(16384)
        var nRead: Int
        while (sodIn.read(data, 0, data.size).also { nRead = it } != -1) {
            buffer.write(data, 0, nRead)
        }
        buffer.flush()
        val sodBytes = buffer.toByteArray()
        
        nfcResult.sod = Base64.encodeToString(sodBytes, Base64.NO_WRAP)
        rawDataGroups["SOD"] = nfcResult.sod!!
        Log.d("NFC_DEBUG", "SOD read successfully (\${sodBytes.size} bytes)")
      } catch (e: Exception) {
        Log.d("NFC_DEBUG", "SOD not available or failed to read: \${e.message}")
      }
      Log.d("NFC_DEBUG", "Including images: $includeImages")
      if (includeImages) {
        try {
          val dg2In = service.getInputStream(PassportService.EF_DG2)
          val dg2Bytes = dg2In.readBytes()
          rawDataGroups["DG2"] = Base64.encodeToString(dg2Bytes, Base64.NO_WRAP)
          val dg2File = DG2File(ByteArrayInputStream(dg2Bytes))
          val faceInfos = dg2File.faceInfos
          val allFaceImageInfos: MutableList<FaceImageInfo> = ArrayList()
          for (faceInfo in faceInfos) {
            allFaceImageInfos.addAll(faceInfo.faceImageInfos)
          }
          if (allFaceImageInfos.isNotEmpty()) {
            val faceImageInfo = allFaceImageInfos.iterator().next()
            val image = bitmapUtil.getImage(faceImageInfo)
            
            // Convert bitmap to base64 JPEG for consistency with iOS
            image.bitmap?.let { bitmap ->
              nfcResult.photo = bitmapToBase64Jpeg(bitmap)
            }
          }
          else {
            Log.d("NFC_DEBUG", "No face images found")
          }
        } catch (e: Exception) {
          // DG2 (face image) is optional and may not be present or readable
          Log.d("NFC_DEBUG", "DG2 not available or failed to read: ${e.message}")
        }
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

  /**
   * Convert a Bitmap to a base64-encoded JPEG string
   * This ensures consistency with iOS which also returns base64 JPEG
   */
  private fun bitmapToBase64Jpeg(bitmap: Bitmap, quality: Int = 80): String {
    val byteArrayOutputStream = ByteArrayOutputStream()
    bitmap.compress(Bitmap.CompressFormat.JPEG, quality, byteArrayOutputStream)
    val byteArray = byteArrayOutputStream.toByteArray()
    return Base64.encodeToString(byteArray, Base64.NO_WRAP)
  }
}
