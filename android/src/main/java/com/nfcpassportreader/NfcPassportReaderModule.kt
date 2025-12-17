package com.nfcpassportreader

import android.annotation.SuppressLint
import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import android.provider.Settings
import android.util.Log
import com.facebook.react.bridge.ActivityEventListener
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.modules.core.DeviceEventManagerModule
import com.nfcpassportreader.utils.JsonToReactMap
import com.nfcpassportreader.utils.serializeToMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.jmrtd.BACKey
import org.jmrtd.BACKeySpec
import org.jmrtd.lds.icao.MRZInfo
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Locale

class NfcPassportReaderModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext), LifecycleEventListener, ActivityEventListener {

  private val nfcPassportReader = NfcPassportReader(reactContext)
  private var adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(reactContext)
  private var bacKey: BACKeySpec? = null
  private var includeImages = true
  private var skipPACE = true
  private var skipCA = false
  private var skipAA = false
  private var isReading = false
  private var isProcessingTag = false
  private var isForegroundDispatchEnabled = false
  private val jsonToReactMap = JsonToReactMap()
  private var _promise: Promise? = null
  private val inputDateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
  private val outputDateFormat = SimpleDateFormat("yyMMdd", Locale.getDefault())

  init {
    reactApplicationContext.addLifecycleEventListener(this)
    reactApplicationContext.addActivityEventListener(this)

    val filter = IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED)
    reactApplicationContext.registerReceiver(NfcStatusReceiver(), filter)
  }

  private fun ensureAdapter() {
    if (adapter == null) {
      adapter = NfcAdapter.getDefaultAdapter(reactApplicationContext)
    }
  }

  private fun enableForegroundDispatchIfNeeded() {
    if (!isReading) return
    if (isForegroundDispatchEnabled) return

    ensureAdapter()
    val activity = currentActivity ?: return
    val nfcAdapter = adapter ?: return
    if (!nfcAdapter.isEnabled) return

    try {
      val intent = Intent(activity, activity.javaClass).apply {
        addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
      }

      val pendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        PendingIntent.getActivity(activity, 0, intent, PendingIntent.FLAG_MUTABLE)
      } else {
        PendingIntent.getActivity(activity, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)
      }

      val techList = arrayOf(arrayOf("android.nfc.tech.IsoDep"))
      nfcAdapter.enableForegroundDispatch(activity, pendingIntent, null, techList)
      isForegroundDispatchEnabled = true
    } catch (e: Exception) {
      Log.e("NfcPassportReader", e.message ?: "Unknown Error")
    }
  }

  private fun disableForegroundDispatchIfNeeded() {
    if (!isForegroundDispatchEnabled) return

    ensureAdapter()
    val activity = currentActivity ?: return
    try {
      adapter?.disableForegroundDispatch(activity)
    } catch (e: Exception) {
      Log.e("NfcPassportReader", e.message ?: "Unknown Error")
    } finally {
      isForegroundDispatchEnabled = false
    }
  }

  inner class NfcStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
      if (NfcAdapter.ACTION_ADAPTER_STATE_CHANGED == intent?.action) {
        val state = intent.getIntExtra(NfcAdapter.EXTRA_ADAPTER_STATE, NfcAdapter.STATE_OFF)
        when (state) {
          NfcAdapter.STATE_OFF -> {
            sendEvent("onNfcStateChanged", "off")
            if (isReading) {
              reject(Exception("NFC disabled"))
            }
          }

          NfcAdapter.STATE_ON -> {
            sendEvent("onNfcStateChanged", "on")
            ensureAdapter()
            enableForegroundDispatchIfNeeded()
          }

          NfcAdapter.STATE_TURNING_OFF -> {
            // NFC kapanıyor
          }

          NfcAdapter.STATE_TURNING_ON -> {
            // NFC açılıyor
          }
        }
      }
    }
  }

  override fun getName(): String {
    return NAME
  }

  override fun onHostResume() {
    ensureAdapter()
    if (isReading) {
      enableForegroundDispatchIfNeeded()
    } else {
      disableForegroundDispatchIfNeeded()
    }
  }

  override fun onHostPause() {
    disableForegroundDispatchIfNeeded()
  }

  override fun onHostDestroy() {
    disableForegroundDispatchIfNeeded()
  }

  override fun onActivityResult(p0: Activity?, p1: Int, p2: Int, p3: Intent?) {
  }

  override fun onNewIntent(p0: Intent?) {
    p0?.let { intent ->
      if (!isReading) return
      if (isProcessingTag) return
      isProcessingTag = true

      sendEvent("onTagDiscovered", null)

      if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
        val tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
          intent.extras?.getParcelable(NfcAdapter.EXTRA_TAG, Tag::class.java)
        } else {
          @Suppress("DEPRECATION")
          intent.extras?.getParcelable(NfcAdapter.EXTRA_TAG) as? Tag
        }

        if (tag == null) {
          reject(Exception("NFC tag is null"))
          return
        }

        if (listOf(*tag.techList).contains("android.nfc.tech.IsoDep")) {
          CoroutineScope(Dispatchers.IO).launch {
            try {
              val result = nfcPassportReader.readPassport(
                IsoDep.get(tag),
                bacKey!!,
                includeImages,
                skipPACE,
                skipCA,
                skipAA
              )

              val map = result.serializeToMap()
              val reactMap = jsonToReactMap.convertJsonToMap(JSONObject(map))

              _promise?.resolve(reactMap)
              _promise = null
              isReading = false
              isProcessingTag = false
              bacKey = null
              disableForegroundDispatchIfNeeded()
            } catch (e: Exception) {
              reject(e)
            }
          }
        } else {
          reject(Exception("Tag tech is not IsoDep"))
        }
      }
    }
  }

  private fun sendEvent(eventName: String, params: Any?) {
    reactApplicationContext.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
      .emit(eventName, params)
  }

  private fun reject(e: Exception) {
    isReading = false
    bacKey = null
    _promise?.reject(e)
    _promise = null
    isProcessingTag = false
    disableForegroundDispatchIfNeeded()
  }

  @ReactMethod
  fun startReading(readableMap: ReadableMap?, promise: Promise) {
    readableMap?.let {
      _promise = promise
      val bacKey = readableMap.getMap("bacKey")

      // Read configuration options with defaults matching iOS behavior
      includeImages = (readableMap.hasKey("includeImages") && readableMap.getBoolean("includeImages")) || true
      skipPACE = !readableMap.hasKey("skipPACE") || readableMap.getBoolean("skipPACE")
      skipCA = readableMap.hasKey("skipCA") && readableMap.getBoolean("skipCA")
      skipAA = readableMap.hasKey("skipAA") && readableMap.getBoolean("skipAA")

      bacKey?.let {
        val documentNo = it.getString("documentNo")
        val expiryDate = it.getString("expiryDate")?.let { date ->
          try {
            outputDateFormat.format(inputDateFormat.parse(date)!!)
          } catch (e: Exception) {
            null
          }
        }
        val birthDate = it.getString("birthDate")?.let { date ->
          try {
            outputDateFormat.format(inputDateFormat.parse(date)!!)
          } catch (e: Exception) {
            null
          }
        }

        if (documentNo == null || expiryDate == null || birthDate == null) {
          reject(Exception("BAC key is not valid: documentNo, expiryDate, and birthDate are required"))
          return
        }

        this.bacKey = BACKey(
          documentNo, birthDate, expiryDate
        )

        isReading = true
        isProcessingTag = false
        currentActivity?.runOnUiThread {
          enableForegroundDispatchIfNeeded()
        }
      } ?: run {
        reject(Exception("BAC key is null"))
      }
    } ?: run {
      reject(Exception("ReadableMap is null"))
    }
  }

  @ReactMethod
  fun stopReading() {
    if (isReading) {
      _promise?.reject("UserCanceled", "Reading stopped")
      _promise = null
    }
    isReading = false
    bacKey = null
    isProcessingTag = false
    currentActivity?.runOnUiThread {
      disableForegroundDispatchIfNeeded()
    }
  }

  @ReactMethod
  fun isNfcEnabled(promise: Promise) {
    promise.resolve(NfcAdapter.getDefaultAdapter(reactApplicationContext)?.isEnabled ?: false)
  }

  @ReactMethod
  fun isNfcSupported(promise: Promise) {
    promise.resolve(reactApplicationContext.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC))
  }

  @SuppressLint("QueryPermissionsNeeded")
  @ReactMethod
  fun openNfcSettings(promise: Promise) {
    val intent = Intent(Settings.ACTION_NFC_SETTINGS)
    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    if (intent.resolveActivity(reactApplicationContext.packageManager) != null) {
      reactApplicationContext.startActivity(intent)
      promise.resolve(true)
    } else {
      promise.reject(Exception("Activity not found"))
    }
  }

  companion object {
    const val NAME = "NfcPassportReader"
  }
}
