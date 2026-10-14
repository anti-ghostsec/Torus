package org.torus.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

/**
 * Keeps the app's process alive and the processor awake while sites are
 * online. Android stops background apps and lets the processor sleep when
 * the screen is off; a foreground service with a wake lock is the way an
 * app says it is doing ongoing work the user asked for.
 *
 * The service does no work itself. Hosting runs in the app's own process,
 * which this keeps from being stopped.
 */
class KeepAliveService : Service() {
  private var wakeLock: PowerManager.WakeLock? = null

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onCreate() {
    super.onCreate()
    val manager = getSystemService(NotificationManager::class.java)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      // Low importance: no sound, no pop-up.
      manager.createNotificationChannel(
        NotificationChannel(CHANNEL, "Sites online", NotificationManager.IMPORTANCE_LOW)
      )
    }
    val notification = NotificationCompat.Builder(this, CHANNEL)
      .setContentTitle("Running")
      .setContentText("Open the app to take your sites offline.")
      .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
      .setOngoing(true)
      // Not shown on the lock screen at all.
      .setVisibility(NotificationCompat.VISIBILITY_SECRET)
      .build()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
    } else {
      startForeground(NOTIFICATION, notification)
    }
    val power = getSystemService(POWER_SERVICE) as PowerManager
    wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "torus:hosting").apply { acquire() }
  }

  // Restarted by the system if it ever has to stop it.
  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

  override fun onDestroy() {
    wakeLock?.let { if (it.isHeld) it.release() }
    super.onDestroy()
  }

  companion object {
    private const val CHANNEL = "hosting"
    private const val NOTIFICATION = 1
  }
}
