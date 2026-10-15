import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const HesnApp());
}

// =========================================================
// النماذج
// =========================================================

class Finding {
  final String title;
  final String detail;
  final String severity;

  const Finding(this.title, this.detail, this.severity);
}

class AppReport {
  final String label;
  final String packageName;
  final bool isSystem;
  final List<Finding> findings;
  final String? apkPath;

  const AppReport({
    required this.label,
    required this.packageName,
    required this.isSystem,
    required this.findings,
    required this.apkPath,
  });
}

// =========================================================
// الفحص (المنطق كله بلغة Dart)
// القراءة من النظام تتم عبر MethodChannel (راجع MainActivity.kt)
// =========================================================

const MethodChannel _channel = MethodChannel('com.example.hesn/scanner');

const int _flagSystem = 1; // ApplicationInfo.FLAG_SYSTEM
const int _flagDebuggable = 2; // ApplicationInfo.FLAG_DEBUGGABLE

Future<List<AppReport>> scanInstalledApps() async {
  final raw = await _channel.invokeListMethod<Map>('getInstalledApps') ?? [];

  final reports = raw.map((item) {
    final map = Map<String, dynamic>.from(item);
    final flags = (map['flags'] as num?)?.toInt() ?? 0;
    final permissions =
        (map['permissions'] as List?)?.map((e) => e.toString()).toSet() ??
            <String>{};
    final isSystem = (flags & _flagSystem) != 0;
    final packageName = map['packageName']?.toString() ?? '';

    return AppReport(
      label: map['label']?.toString() ?? packageName,
      packageName: packageName,
      isSystem: isSystem,
      findings: analyzePackage(
        permissions: permissions,
        flags: flags,
        isSystem: isSystem,
      ),
      apkPath: map['sourceDir']?.toString(),
    );
  }).toList();

  reports.sort((a, b) => a.label.toLowerCase().compareTo(b.label.toLowerCase()));
  return reports;
}

List<Finding> analyzePackage({
  required Set<String> permissions,
  required int flags,
  required bool isSystem,
}) {
  final findings = <Finding>[];

  if (permissions.contains('android.permission.REQUEST_INSTALL_PACKAGES')) {
    findings.add(const Finding(
      'السماح بطلب تثبيت تطبيقات',
      'قد تحتاج بعض المتاجر ومديري الملفات إلى هذا الإذن. راجع سبب طلبه إذا لم تكن الوظيفة متوقعة.',
      'متوسط',
    ));
  }
  if (permissions.contains('android.permission.SYSTEM_ALERT_WINDOW')) {
    findings.add(const Finding(
      'إمكانية الظهور فوق التطبيقات',
      'قد تُستخدم هذه الإمكانية لأغراض مشروعة أو للتضليل. تحقق من حاجة التطبيق إليها.',
      'متوسط',
    ));
  }
  if (permissions.contains('android.permission.READ_SMS') ||
      permissions.contains('android.permission.RECEIVE_SMS')) {
    findings.add(const Finding(
      'صلاحيات الرسائل النصية',
      'هذه صلاحيات حساسة. راجعها إذا لم تكن وظيفة التطبيق تبرر الوصول إلى الرسائل.',
      'متوسط',
    ));
  }
  if (permissions.contains('android.permission.RECORD_AUDIO')) {
    findings.add(const Finding(
      'إمكانية استخدام الميكروفون',
      'تحقق من أن وظيفة التطبيق تبرر طلب الميكروفون. وجود الإذن وحده لا يثبت التسجيل أو التجسس.',
      'منخفض',
    ));
  }
  if (permissions.contains('android.permission.READ_CONTACTS')) {
    findings.add(const Finding(
      'إمكانية قراءة جهات الاتصال',
      'راجع حاجة التطبيق إلى جهات الاتصال وسياسة الخصوصية الخاصة به.',
      'منخفض',
    ));
  }
  if (!isSystem && (flags & _flagDebuggable) != 0) {
    findings.add(const Finding(
      'تطبيق قابل للتصحيح',
      'قد تظهر هذه العلامة في نسخ التطوير. لا تُعد دليلًا كافيًا على وجود برمجية ضارة.',
      'منخفض',
    ));
  }
  return findings;
}

Future<String> sha256File(String path) async {
  final digest = await sha256.bind(File(path).openRead()).first;
  return digest.toString();
}

Future<String> queryVirusTotal(String hash, String apiKey) async {
  final response = await http
      .get(
        Uri.parse('https://www.virustotal.com/api/v3/files/$hash'),
        headers: {'x-apikey': apiKey},
      )
      .timeout(const Duration(seconds: 15));

  switch (response.statusCode) {
    case 200:
      final body = jsonDecode(utf8.decode(response.bodyBytes));
      final stats = body['data']['attributes']['last_analysis_stats'] as Map;
      return 'نتيجة الفحص: ضار = ${stats['malicious'] ?? 0}، '
          'مشتبه به = ${stats['suspicious'] ?? 0}، '
          'سليم وفق المحركات = ${stats['harmless'] ?? 0}. '
          'النتيجة ليست إثباتًا قاطعًا.';
    case 404:
      return 'لا يوجد سجل لهذه البصمة في الخدمة. هذا لا يعني أن التطبيق آمن.';
    case 401:
    case 403:
      return 'رفضت الخدمة الطلب. تحقق من مفتاح الخدمة وصلاحياته.';
    case 429:
      return 'تم تجاوز الحد المسموح للطلبات. حاول لاحقًا.';
    default:
      return 'أعادت الخدمة رمز الاستجابة ${response.statusCode}. تحقق من المفتاح أو حالة الخدمة.';
  }
}

// =========================================================
// التطبيق
// =========================================================

class HesnApp extends StatelessWidget {
  const HesnApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'حِصن',
      debugShowCheckedModeBanner: false,
      locale: const Locale('ar'),
      builder: (context, child) =>
          Directionality(textDirection: TextDirection.rtl, child: child!),
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF176B5B),
          primary: const Color(0xFF176B5B),
          secondary: const Color(0xFF2D8876),
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: const Color(0xFFF5F8F7),
        inputDecorationTheme: InputDecorationTheme(
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
        ),
      ),
      home: const HesnHome(),
    );
  }
}

class HesnHome extends StatefulWidget {
  const HesnHome({super.key});

  @override
  State<HesnHome> createState() => _HesnHomeState();
}

class _HesnHomeState extends State<HesnHome> {
  final apiKeyController = TextEditingController();

  List<AppReport> reports = [];
  bool scanning = false;
  String status = 'لم يبدأ الفحص بعد';
  AppReport? selected;
  String onlineResult = '';
  bool onlineBusy = false;

  @override
  void dispose() {
    apiKeyController.dispose();
    super.dispose();
  }

  int get flaggedCount => reports.where((r) => r.findings.isNotEmpty).length;

  Future<void> startScan() async {
    setState(() {
      scanning = true;
      status = 'جارٍ فحص التطبيقات...';
    });
    try {
      final result = await scanInstalledApps();
      setState(() {
        reports = result;
        status =
            'اكتمل الفحص: ${result.length} تطبيقًا، ${result.where((r) => r.findings.isNotEmpty).length} تطبيقًا يحتاج إلى مراجعة';
      });
    } catch (e) {
      setState(() => status = 'تعذر إكمال الفحص: $e');
    } finally {
      setState(() => scanning = false);
    }
  }

  Future<void> checkOnline(AppReport app) async {
    setState(() {
      onlineBusy = true;
      onlineResult = 'جارٍ حساب البصمة والتحقق...';
    });
    try {
      final hash = await sha256File(app.apkPath!);
      final result = await queryVirusTotal(hash, apiKeyController.text.trim());
      setState(() => onlineResult = result);
    } catch (e) {
      setState(() => onlineResult = 'تعذر إكمال الفحص: $e');
    } finally {
      setState(() => onlineBusy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;

    return PopScope(
      canPop: selected == null,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop && selected != null) {
          setState(() {
            selected = null;
            onlineResult = '';
          });
        }
      },
      child: Scaffold(
        appBar: AppBar(
          title: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('حِصن', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('حماية الهاتف وفحص الأمان', style: text.labelSmall),
            ],
          ),
        ),
        bottomNavigationBar: SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Divider(),
                const SizedBox(height: 8),
                Text('جميع الحقوق محفوظة © 2026', style: text.bodySmall),
                Text('بلال - البوب',
                    style: text.bodyMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
              ],
            ),
          ),
        ),
        body: selected != null ? buildDetails(selected!) : buildList(),
      ),
    );
  }

  // ---------------------------------------------------------
  // شاشة النتائج
  // ---------------------------------------------------------

  Widget buildList() {
    final text = Theme.of(context).textTheme;

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('فحص التطبيقات المثبتة',
                      style: text.titleLarge
                          ?.copyWith(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 8),
                  const Text(
                      'يفحص حِصن مجموعة من المؤشرات والأذونات المتاحة للنظام.'),
                  const SizedBox(height: 8),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton(
                      onPressed: scanning ? null : startScan,
                      child: Text(scanning ? 'جارٍ الفحص...' : 'ابدأ الفحص الآن'),
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(status, style: text.bodyMedium),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                  child: summaryCard('عدد التطبيقات', reports.length.toString())),
              const SizedBox(width: 8),
              Expanded(
                  child: summaryCard(
                      'تحتاج إلى مراجعة', flaggedCount.toString())),
            ],
          ),
          const SizedBox(height: 12),
          Text('نتائج الفحص',
              style: text.titleLarge?.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Expanded(
            child: reports.isEmpty
                ? const Text(
                    'اضغط على «ابدأ الفحص الآن» لعرض التطبيقات ونتائج التحليل.')
                : ListView.separated(
                    itemCount: reports.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 8),
                    itemBuilder: (context, i) => appTile(reports[i]),
                  ),
          ),
          const SizedBox(height: 8),
          Text(
            'تنبيه: حِصن إصدار أولي، ولا يغني عن Google Play Protect أو حلول الحماية المتخصصة.',
            style: text.bodySmall,
          ),
        ],
      ),
    );
  }

  Widget summaryCard(String title, String value) {
    final text = Theme.of(context).textTheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: text.bodySmall),
            Text(value,
                style: text.headlineMedium
                    ?.copyWith(fontWeight: FontWeight.bold)),
          ],
        ),
      ),
    );
  }

  Widget appTile(AppReport app) {
    final text = Theme.of(context).textTheme;
    final badge = app.findings.any((f) => f.severity == 'مرتفع')
        ? 'مرتفع'
        : app.findings.isNotEmpty
            ? 'مراجعة'
            : '—';

    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () => setState(() => selected = app),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(app.label,
                        style: const TextStyle(fontWeight: FontWeight.w600)),
                    Text(app.packageName, style: text.bodySmall),
                    Text(
                      app.findings.isEmpty
                          ? 'لا توجد مؤشرات وفق القواعد الحالية'
                          : '${app.findings.length} ملاحظة تستحق المراجعة',
                      style: text.bodySmall,
                    ),
                  ],
                ),
              ),
              Text(badge, style: const TextStyle(fontWeight: FontWeight.bold)),
            ],
          ),
        ),
      ),
    );
  }

  // ---------------------------------------------------------
  // شاشة تفاصيل التطبيق
  // ---------------------------------------------------------

  Widget buildDetails(AppReport app) {
    final text = Theme.of(context).textTheme;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Align(
          alignment: AlignmentDirectional.centerStart,
          child: TextButton(
            onPressed: () => setState(() {
              selected = null;
              onlineResult = '';
            }),
            child: const Text('→ العودة إلى النتائج'),
          ),
        ),
        Text(app.label,
            style:
                text.headlineSmall?.copyWith(fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        Text(app.packageName, style: text.bodySmall),
        const SizedBox(height: 12),
        Text(app.isSystem ? 'تطبيق من تطبيقات النظام' : 'تطبيق مثبت'),
        const SizedBox(height: 12),
        const Text('نتيجة الفحص المحلي',
            style: TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        if (app.findings.isEmpty)
          const Text(
              'لم تُكتشف مؤشرات ضمن قواعد الفحص الحالية. هذا لا يثبت أن التطبيق آمن.')
        else
          ...app.findings.map(
            (f) => Card(
              margin: const EdgeInsets.only(bottom: 12),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('${f.severity}: ${f.title}',
                        style: const TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 4),
                    Text(f.detail),
                  ],
                ),
              ),
            ),
          ),
        const Divider(),
        const SizedBox(height: 12),
        const Text('فحص إضافي عبر الإنترنت (اختياري)',
            style: TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        const Text(
            'يمكن إرسال بصمة الملف الرقمية SHA-256 إلى خدمة VirusTotal. لن يُرفع ملف التطبيق نفسه من خلال هذا الخيار.'),
        const SizedBox(height: 12),
        TextField(
          controller: apiKeyController,
          onChanged: (_) => setState(() {}),
          decoration: const InputDecoration(labelText: 'مفتاح خدمة VirusTotal'),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: FilledButton(
            onPressed: (!onlineBusy &&
                    apiKeyController.text.trim().isNotEmpty &&
                    app.apkPath != null)
                ? () => checkOnline(app)
                : null,
            child:
                Text(onlineBusy ? 'جارٍ الفحص...' : 'افحص البصمة عبر الإنترنت'),
          ),
        ),
        if (onlineResult.isNotEmpty) ...[
          const SizedBox(height: 12),
          Text(onlineResult),
        ],
        const SizedBox(height: 12),
        Text(
          'قد لا تكون البصمة معروفة للخدمة، والنتائج ليست حكمًا قطعيًا على سلامة التطبيق.',
          style: text.bodySmall,
        ),
      ],
    );
  }
}
