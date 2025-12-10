package com.nfcpassportreader.utils

import android.annotation.SuppressLint
import android.graphics.Bitmap
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import com.google.gson.reflect.TypeToken
import com.nfcpassportreader.dto.AuthenticationStatus
import com.nfcpassportreader.dto.NfcImage
import java.lang.reflect.Type
import java.time.LocalDateTime

fun <T> T.serializeToMap(): Map<String, Any> {
  return convert()
}

@SuppressLint("NewApi")
inline fun <I, reified O> I.convert(): O {
  val gson = GsonBuilder()
    .registerTypeHierarchyAdapter(Bitmap::class.java, BitmapSerializer())
    .registerTypeHierarchyAdapter(LocalDateTime::class.java, LocalDateTimeSerializer())
    .registerTypeAdapter(NfcImage::class.java, NfcImageSerializer())
    .registerTypeAdapter(AuthenticationStatus::class.java, AuthenticationStatusSerializer())
    .serializeNulls() // Ensure null values are serialized (for photo field)
    .create()
  val json = gson.toJson(this)
  return gson.fromJson(json, object : TypeToken<O>() {}.type)
}

class LocalDateTimeSerializer : JsonSerializer<LocalDateTime> {
  override fun serialize(
    src: LocalDateTime?,
    typeOfSrc: Type?,
    context: JsonSerializationContext?
  ): JsonElement {
    if (src == null) return JsonNull.INSTANCE
    return JsonPrimitive(src.toString())
  }
}

class BitmapSerializer : JsonSerializer<Bitmap> {
  override fun serialize(
    src: Bitmap?,
    typeOfSrc: Type?,
    context: JsonSerializationContext?
  ): JsonElement {
    if (src == null) return JsonNull.INSTANCE
    return JsonPrimitive(src.toBase64())
  }
}

class NfcImageSerializer : JsonSerializer<NfcImage> {
  override fun serialize(
    src: NfcImage?,
    typeOfSrc: Type?,
    context: JsonSerializationContext?
  ): JsonElement {
    if (src == null) return JsonNull.INSTANCE
    return JsonPrimitive(src.base64)
  }
}

class AuthenticationStatusSerializer : JsonSerializer<AuthenticationStatus> {
  override fun serialize(
    src: AuthenticationStatus?,
    typeOfSrc: Type?,
    context: JsonSerializationContext?
  ): JsonElement {
    if (src == null) return JsonNull.INSTANCE
    
    val jsonObject = JsonObject()
    jsonObject.addProperty("method", src.method)
    
    // Only include authentication fields if they're not null (i.e., if they were attempted)
    src.chipAuthenticationPassed?.let {
      jsonObject.addProperty("chipAuthenticationPassed", it)
    }
    src.activeAuthenticationPassed?.let {
      jsonObject.addProperty("activeAuthenticationPassed", it)
    }
    
    return jsonObject
  }
}
