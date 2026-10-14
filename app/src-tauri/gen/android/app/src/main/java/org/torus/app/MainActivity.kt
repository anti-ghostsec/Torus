package org.torus.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.View
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)

    // Recent Android versions draw every app underneath the status bar at
    // the top and the navigation buttons at the bottom. Without this the
    // editor's top row and its last lines sit under them, out of reach. The
    // on-screen keyboard is counted too, so it never covers what is typed.
    val content = findViewById<View>(android.R.id.content)
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val covered = insets.getInsets(
        WindowInsetsCompat.Type.systemBars() or
          WindowInsetsCompat.Type.displayCutout() or
          WindowInsetsCompat.Type.ime()
      )
      view.setPadding(covered.left, covered.top, covered.right, covered.bottom)
      WindowInsetsCompat.CONSUMED
    }

    // Keeps the app out of screenshots, screen recordings and the picture
    // Android shows of it in the list of recent apps.
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
      checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) {
      requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }
    ContextCompat.startForegroundService(this, Intent(this, KeepAliveService::class.java))
    askToRunUnrestricted()
  }

  /**
   * Battery optimisation suspends network access for apps in the background
   * after a while, which would take sites offline. Android lets the user
   * exempt an app; this opens that question once.
   */
  @SuppressLint("BatteryLife")
  private fun askToRunUnrestricted() {
    val settings = getPreferences(MODE_PRIVATE)
    val power = getSystemService(PowerManager::class.java)
    if (settings.getBoolean(ASKED, false) || power.isIgnoringBatteryOptimizations(packageName)) return
    settings.edit().putBoolean(ASKED, true).apply()
    try {
      startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
    } catch (_: Exception) {
      // Some devices have no such screen; the foreground service still helps.
    }
  }

  companion object {
    private const val ASKED = "asked_battery"
  }
}
