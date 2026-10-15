package com.example.hesn

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// جسر بسيط فقط: يقرأ قائمة التطبيقات من نظام أندرويد ويرسلها إلى Dart.
// كل منطق الفحص والواجهة موجود في lib/main.dart بلغة Dart.
class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "com.example.hesn/scanner")
            .setMethodCallHandler { call, result ->
                if (call.method == "getInstalledApps") {
                    Thread {
                        try {
                            val data = readInstalledApps()
                            runOnUiThread { result.success(data) }
                        } catch (e: Exception) {
                            runOnUiThread { result.error("SCAN_FAILED", e.message, null) }
                        }
                    }.start()
                } else {
                    result.notImplemented()
                }
            }
    }

    @Suppress("DEPRECATION")
    private fun readInstalledApps(): List<Map<String, Any?>> {
        val pm = packageManager
        val apps: List<ApplicationInfo> = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            pm.getInstalledApplications(0)
        }

        return apps.map { info ->
            val packageInfo = try {
                if (Build.VERSION.SDK_INT >= 33) {
                    pm.getPackageInfo(
                        info.packageName,
                        PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                    )
                } else {
                    pm.getPackageInfo(info.packageName, PackageManager.GET_PERMISSIONS)
                }
            } catch (_: Exception) {
                null
            }

            val label = try {
                pm.getApplicationLabel(info).toString()
            } catch (_: Exception) {
                info.packageName
            }

            mapOf(
                "label" to label,
                "packageName" to info.packageName,
                "flags" to info.flags,
                "permissions" to (packageInfo?.requestedPermissions?.toList() ?: emptyList<String>()),
                "sourceDir" to info.sourceDir
            )
        }
    }
}
