package com.nfcpassportreader.utils

import android.annotation.SuppressLint
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@SuppressLint("SimpleDateFormat")
class DateUtil {
  private val outputFormat = SimpleDateFormat("yyyy-MM-dd", Locale.US)
  private val mrzFormat = SimpleDateFormat("yyMMdd", Locale.US)
  private val fullFormat = SimpleDateFormat("yyyyMMdd", Locale.US)

  private fun stringToDate(dateStr: String, dateFormat: DateFormat): Date? {
    return try {
      dateFormat.parse(dateStr)
    } catch (e: Exception) {
      null
    }
  }

  private fun dateToString(date: Date?, dateFormat: DateFormat): String? {
    return date?.let { dateFormat.format(it) }
  }

  /**
   * Convert MRZ date format (YYMMDD) to standard format (YYYY-MM-DD)
   */
  fun convertFromMrzDate(mrzDate: String): String? {
    val date = stringToDate(mrzDate, mrzFormat)
    return dateToString(date, outputFormat)
  }

  /**
   * Convert full date format (YYYYMMDD) from DG11 to standard format (YYYY-MM-DD)
   */
  fun convertFromFullDate(fullDate: String): String? {
    val date = stringToDate(fullDate, fullFormat)
    return dateToString(date, outputFormat)
  }

  /**
   * Alias for convertFromMrzDate for backwards compatibility
   */
  fun convertFromNfcDate(nfcDate: String): String? {
    return convertFromMrzDate(nfcDate)
  }
}
