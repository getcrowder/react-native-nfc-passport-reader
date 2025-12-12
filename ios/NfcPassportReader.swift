import CoreNFC
import Foundation
import OpenSSL
import React
import UIKit

@objc(NfcPassportReader)
class NfcPassportReader: NSObject {
  private let passportReader = PassportReader()
  private let passportUtil = PassportUtil()

  @objc
  static func requiresMainQueueSetup() -> Bool {
    return true
  }

  @objc func isNfcSupported(
    _ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    if #available(iOS 13.0, *) {
      resolve(NFCNDEFReaderSession.readingAvailable)
    } else {
      resolve(false)
    }
  }

  @objc func startReading(
    _ options: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    let bacKey = options["bacKey"] as? NSDictionary
    let includeImages = options["includeImages"] as? Bool ?? true
    let skipPACE = options["skipPACE"] as? Bool ?? true
    let skipCA = options["skipCA"] as? Bool ?? false

    let documentNo = bacKey?["documentNo"] as? String
    let expiryDate = bacKey?["expiryDate"] as? String
    let birthDate = bacKey?["birthDate"] as? String

    guard let documentNo = documentNo, let expiryDate = expiryDate, let birthDate = birthDate else {
      reject("ERROR_INVALID_BAC_KEY", "Invalid BAC key: documentNo, expiryDate, and birthDate are required", nil)
      return
    }

    guard let birthDateFormatted = birthDate.convertToYYMMDD() else {
      reject("ERROR_INVALID_BIRTH_DATE", "Invalid birth date format. Expected YYYY-MM-DD", nil)
      return
    }

    guard let expiryDateFormatted = expiryDate.convertToYYMMDD() else {
      reject("ERROR_INVALID_EXPIRY_DATE", "Invalid expiry date format. Expected YYYY-MM-DD", nil)
      return
    }

    passportUtil.passportNumber = documentNo
    passportUtil.dateOfBirth = birthDateFormatted
    passportUtil.expiryDate = expiryDateFormatted

    let mrzKey = passportUtil.getMRZKey()

    // Pass empty array to let the library auto-detect available data groups
    // This is more robust - the library will:
    // 1. Read COM to see what data groups are available
    // 2. Automatically read all available data groups
    // 3. Skip data groups that don't exist (like DG11 on Portuguese passports)
    // 4. Skip secure elements (DG3/DG4) by default
    let finalTags: [DataGroupId] = []

    let customMessageHandler: (NFCViewDisplayMessage) -> String? = { displayMessage in
      switch displayMessage {
      case .requestPresentPassport:
        return "Hold your iPhone near an NFC-enabled ID Card / Passport."
      case .successfulRead:
        return "ID Card / Passport Successfully Read."
      case .readingDataGroupProgress(let dataGroup, let progress):
        let progressString = self.handleProgress(percentualProgress: progress)
        let readingDataString = "Reading"
        return "\(readingDataString) \(dataGroup)...\n\(progressString)"
      case .authenticatingWithPassport(let progress):
        return "Authenticating... \(progress)%"
      case .activeAuthentication:
        return "Performing Active Authentication..."
      case .error(let error):
        return error.errorDescription
      default:
        return displayMessage.description
      }
    }

    Task {
      do {
        let passport = try await self.passportReader.readPassport(
          mrzKey: mrzKey,
          tags: finalTags,
          skipCA: skipCA,
          skipPACE: skipPACE,
          customDisplayMessage: customMessageHandler
        )
        
        // Log authentication status for debugging
        print("🔐 Authentication Status Debug:")
        print("   - PACE Status: \(passport.PACEStatus)")
        print("   - BAC Status: \(passport.BACStatus)")
        print("   - Chip Auth (CA) Status: \(passport.chipAuthenticationStatus)")
        print("   - Is CA Supported (DG14): \(passport.isChipAuthenticationSupported)")
        print("   - Active Auth (AA) Passed: \(passport.activeAuthenticationPassed)")
        print("   - Is AA Supported (DG15): \(passport.activeAuthenticationSupported)")
        print("   - skipCA param: \(skipCA)")
        
        let authMethod: String
        if passport.PACEStatus == .success {
          authMethod = "PACE"
        } else {
          authMethod = "BAC"
        }
        
        let authStatus: NSMutableDictionary = [
          "method": authMethod
        ]
        
        switch passport.chipAuthenticationStatus {
        case .success:
          authStatus["chipAuthenticationPassed"] = true
        case .failed:
          authStatus["chipAuthenticationPassed"] = false
        case .notDone:
          // CA was not attempted (not supported by this passport or skipped)
          break
        }
        
        if passport.activeAuthenticationSupported {
          authStatus["activeAuthenticationPassed"] = passport.activeAuthenticationPassed
        }

        let result: NSMutableDictionary = [
          "firstName": passport.firstName,
          "lastName": passport.lastName,
          "dateOfBirth": passport.dateOfBirth.convertToYYYYMMDD() ?? "",
          "gender": passport.gender,
          "nationality": passport.nationality,
          "personalNumber": passport.personalNumber ?? "",
          "placeOfBirth": passport.placeOfBirth ?? "",
          "documentNumber": passport.documentNumber,
          "dateOfExpiry": passport.documentExpiryDate.convertToYYYYMMDD() ?? "",
          "issuingAuthority": passport.issuingAuthority,
          "documentType": passport.documentType,
          "mrz": passport.passportMRZ,
          "photo": NSNull(),
          "sod": NSNull(),
          "authentication": authStatus
        ]

        // Include photo if requested and available
        if includeImages {
          if let passportImage = passport.passportImage,
             let imageData = passportImage.jpegData(compressionQuality: 0.8)
          {
            result["photo"] = imageData.base64EncodedString()
          }
        }
        
        // Include SOD if available
        if let sod = passport.getDataGroup(.SOD) {
            let sodData = Data(sod.data)
            result["sod"] = sodData.base64EncodedString()
        }

        // Include all raw DataGroups
        let dataGroups = NSMutableDictionary()
        for (id, dg) in passport.dataGroupsRead {
             let dgData = Data(dg.data)
             dataGroups[id.getName()] = dgData.base64EncodedString()
        }
        result["dataGroups"] = dataGroups

        resolve(result)
      } catch let error as NFCPassportReaderError {
        reject("ERROR_READ_PASSPORT", "Error reading passport: \(error.errorDescription ?? error.localizedDescription)", error)
      } catch {
        reject("ERROR_READ_PASSPORT", "Error reading passport: \(error.localizedDescription)", error)
      }
    }
  }

  func handleProgress(percentualProgress: Int) -> String {
    let barWidth = 10
    let completedWidth = Int(Double(barWidth) * Double(percentualProgress) / 100.0)
    let remainingWidth = barWidth - completedWidth

    let completedBar = String(repeating: "🔵", count: completedWidth)
    let remainingBar = String(repeating: "⚪️", count: remainingWidth)

    return "[\(completedBar)\(remainingBar)] \(percentualProgress)%"
  }
}
