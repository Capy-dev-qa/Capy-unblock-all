package dev.capy.torification

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri

object TorApps {
    const val TOR_VPN = "org.torproject.vpn"
    const val ORBOT = "org.torproject.android"

    fun installed(context: Context, pkg: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(pkg, 0)
            true
        } catch (_: Exception) {
            false
        }
    }

    fun copy(context: Context, text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("tor-bridge", text))
    }

    fun openAppOrPlay(context: Context, pkg: String) {
        val launch = context.packageManager.getLaunchIntentForPackage(pkg)
        if (launch != null) {
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(launch)
            return
        }
        try {
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$pkg"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        } catch (_: ActivityNotFoundException) {
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$pkg"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }

    fun startOrbot(context: Context) {
        val i = Intent("org.torproject.android.intent.action.START")
        i.setPackage(ORBOT)
        i.putExtra("org.torproject.android.intent.extra.PACKAGE_NAME", context.packageName)
        try {
            context.sendBroadcast(i)
        } catch (_: Exception) {
            openAppOrPlay(context, ORBOT)
        }
        openAppOrPlay(context, ORBOT)
    }
}
