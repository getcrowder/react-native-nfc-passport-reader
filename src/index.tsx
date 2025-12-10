import { DeviceEventEmitter, NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-nfc-passport-reader' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const NfcPassportReaderNativeModule = NativeModules.NfcPassportReader
  ? NativeModules.NfcPassportReader
  : new Proxy({} as any, {
      get() {
        throw new Error(LINKING_ERROR);
      },
    });

enum NfcPassportReaderEvent {
  TAG_DISCOVERED = 'onTagDiscovered',
  NFC_STATE_CHANGED = 'onNfcStateChanged',
}

/**
 * BAC Keys from the MRZ
 * All dates should be in YYYY-MM-DD format
 */
export type BACKey = {
  documentNo: string;
  expiryDate: string;
  birthDate: string;
};

export type NfcPassportReaderConfig = {
  bacKey: BACKey;
  /** Whether to include face photo from DG2 (default: false) */
  includeImages?: boolean;
  /** Skip PACE authentication and use BAC instead (default: true) */
  skipPACE?: boolean;
  /** Skip Chip Authentication - only applicable if PACE succeeds (default: false) */
  skipCA?: boolean;
};

export type AuthenticationStatus = {
  method: 'PACE' | 'BAC';
  /** 
   * Chip Authentication (CA) - uses DG14
   * Establishes an encrypted channel with stronger keys
   * undefined = not supported/attempted, true = passed, false = failed
   */
  chipAuthenticationPassed?: boolean;
  /**
   * Active Authentication (AA) - uses DG15  
   * Proves the chip is genuine (not cloned) via challenge-response
   * undefined = not supported/attempted, true = passed, false = failed
   */
  activeAuthenticationPassed?: boolean;
};

export type NfcPassportResult = {
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  gender: string;
  nationality: string;
  personalNumber: string;
  placeOfBirth: string;
  documentNumber: string;
  dateOfExpiry: string;
  issuingAuthority: string;
  documentType: string;
  mrz: string;
  photo: string | null;
  authentication: AuthenticationStatus;
};

// Legacy type alias for backwards compatibility
export type StartReadingParams = NfcPassportReaderConfig;
export type NfcResult = NfcPassportResult;
export default class NfcPassportReader {
  /**
   * Start reading the passport chip via NFC
   * @param config Configuration options including BAC key
   * @returns Promise that resolves with passport data
   */
  static async startReading(
    config: NfcPassportReaderConfig
  ): Promise<NfcPassportResult> {
    const result = await NfcPassportReaderNativeModule.startReading(config);
    return result as NfcPassportResult;
  }

  /**
   * Stop an in-progress NFC reading session (Android only)
   * On iOS, the system NFC sheet handles cancellation
   */
  static stopReading(): void {
    if (Platform.OS === 'android') {
      NfcPassportReaderNativeModule.stopReading();
    }
    // iOS handles cancellation through the system NFC sheet
  }

  /**
   * Add listener for when an NFC tag is discovered (Android only)
   * On iOS, tag discovery is handled by the system NFC sheet
   */
  static addOnTagDiscoveredListener(callback: () => void): void {
    if (Platform.OS === 'android') {
      this.addListener(NfcPassportReaderEvent.TAG_DISCOVERED, callback);
    }
  }

  /**
   * Add listener for NFC adapter state changes (Android only)
   * Useful for detecting when user enables/disables NFC
   */
  static addOnNfcStateChangedListener(
    callback: (state: 'off' | 'on') => void
  ): void {
    if (Platform.OS === 'android') {
      this.addListener(NfcPassportReaderEvent.NFC_STATE_CHANGED, callback);
    }
  }

  /**
   * Check if NFC is currently enabled on the device
   * On iOS, this checks if NFC reading is available (always true if supported)
   */
  static isNfcEnabled(): Promise<boolean> {
    if (Platform.OS === 'android') {
      return NfcPassportReaderNativeModule.isNfcEnabled();
    } else if (Platform.OS === 'ios') {
      // iOS doesn't have a separate enable/disable - if supported, it's enabled
      return NfcPassportReaderNativeModule.isNfcSupported();
    } else {
      return Promise.resolve(false);
    }
  }

  /**
   * Check if NFC is supported on this device
   */
  static isNfcSupported(): Promise<boolean> {
    return NfcPassportReaderNativeModule.isNfcSupported();
  }

  /**
   * Open the system NFC settings (Android only)
   * On iOS, NFC cannot be toggled by the user
   */
  static openNfcSettings(): Promise<boolean> {
    if (Platform.OS === 'android') {
      return NfcPassportReaderNativeModule.openNfcSettings();
    } else {
      // iOS doesn't have NFC settings that users can toggle
      return Promise.resolve(false);
    }
  }

  private static addListener(
    event: NfcPassportReaderEvent,
    callback: (data: any) => void
  ): void {
    DeviceEventEmitter.addListener(event, callback);
  }

  /**
   * Remove all NFC event listeners (Android only)
   */
  static removeListeners(): void {
    if (Platform.OS === 'android') {
      DeviceEventEmitter.removeAllListeners(
        NfcPassportReaderEvent.TAG_DISCOVERED
      );
      DeviceEventEmitter.removeAllListeners(
        NfcPassportReaderEvent.NFC_STATE_CHANGED
      );
    }
  }
}
