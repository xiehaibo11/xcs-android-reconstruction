#!/usr/bin/env python3
"""Reproduce Android-side static protocol extraction from this APK's decoded files.

Only consumes JADX Java and Apktool XML/Smali. Does not launch apps or contact hosts.
The manually annotated schemas describe the Android handler, not Dart call sites.
"""

from _paths import app_root, workspace_root
from pathlib import Path
import hashlib
import json
import re
import xml.etree.ElementTree as ET

APP = app_root()
OUT = APP / 'analysis' / 'deep_android'
OUT.mkdir(parents=True, exist_ok=True)
JAVA = APP / 'jadx' / 'sources'
DECODED = APP / 'apktool' / 'decoded'
ANDROID = '{http://schemas.android.com/apk/res/android}'


def write_json(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def source(relative, needle=None):
    path = JAVA / relative
    text = path.read_text(encoding='utf-8')
    line = None if needle is None else text[:text.index(needle)].count('\n') + 1
    return {'file': str(path), 'line': line, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def method(name, args, result, **extra):
    return {'method': name, 'arguments': args, 'result': result, **extra}


def attrs(element):
    return {k.replace(ANDROID, ''): v for k, v in element.attrib.items()}


manifest = ET.parse(DECODED / 'AndroidManifest.xml').getroot()
application = manifest.find('application')
components = []
for tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
    for entry in application.findall(tag):
        components.append({
            'type': tag, **attrs(entry),
            'intent_filters': [
                {kind: [attrs(v) for v in f.findall(kind)] for kind in ('action', 'category', 'data')}
                for f in entry.findall('intent-filter')
            ],
            'metadata': [attrs(v) for v in entry.findall('meta-data')],
        })
manifest_surface = {
    'manifest_file': str(DECODED / 'AndroidManifest.xml'),
    'manifest_sha256': hashlib.sha256((DECODED / 'AndroidManifest.xml').read_bytes()).hexdigest(),
    'manifest_attributes': attrs(manifest),
    'application_attributes': attrs(application),
    'permissions': [attrs(v) for v in manifest.findall('uses-permission')],
    'custom_permissions': [attrs(v) for v in manifest.findall('permission')],
    'components': components,
    'network_security_config': {
        'file': str(DECODED / 'res/xml/network_security_config.xml'),
        'base_config': [attrs(v) for v in ET.parse(DECODED / 'res/xml/network_security_config.xml').getroot().findall('base-config')],
        'domain_config_count': len(ET.parse(DECODED / 'res/xml/network_security_config.xml').getroot().findall('domain-config')),
    },
    'ota_file_provider': {
        'authority': 'com.re.xcs.ota_update_provider', 'exported': False,
        'grant_uri_permissions': True,
        'paths': [{'element': v.tag, **attrs(v)} for v in ET.parse(DECODED / 'res/xml/filepaths.xml').getroot()],
    },
    'scope_note': 'Manifest 组件暴露范围是静态配置；未执行外部组件调用或动态授权验证。Flutter 平台通道不是外部应用可直接调用的 IPC 接口。',
}
write_json('component_surface.json', manifest_surface)

registrant = (JAVA / 'io/flutter/plugins/GeneratedPluginRegistrant.java').read_text()
plugin_pattern = re.compile(r'new ([\w.]+)\(\).*?Error registering plugin ([\w]+), ([\w.]+)', re.S)
plugins = [{'obfuscated_class': match[0], 'plugin': match[1], 'original_class': match[2]} for match in plugin_pattern.findall(registrant)]
write_json('registered_plugins.json', {
    'source': source('io/flutter/plugins/GeneratedPluginRegistrant.java'),
    'plugins': plugins,
    'scope_note': 'registerWith 含逐个插件注册 try/catch；静态注册不证明插件在当前设备注册成功或 Dart 业务调用了所有方法。',
})

wifi_fields = {
    'ssid': 'String', 'bssid': 'String', 'capabilities': 'String',
    'frequency': 'int', 'level': 'int', 'timestamp': 'int64',
    'standard': 'int|null (API>=30)',
    'centerFrequency0': 'int|null (API>=23)', 'centerFrequency1': 'int|null (API>=23)',
    'channelWidth': 'int|null (API>=23)', 'isPasspoint': 'bool|null (API>=23)',
    'operatorFriendlyName': 'Android CharSequence|null (API>=23)',
    'venueName': 'Android CharSequence|null (API>=23)',
    'is80211mcResponder': 'bool|null (API>=23)',
}
channels = [{
    'name': 'android/back/desktop', 'kind': 'MethodChannel', 'origin': '应用自定义',
    'source': source('com/example/distinguish/MainActivity.java', 'backDesktop'),
    'methods': [method('backDesktop', {}, 'bool true', side_effect='先 success(true)，然后 moveTaskToBack(false)。参数未读取。')],
    'unknown_method': '处理器无 else，未知方法没有返回 success/error/notImplemented。',
}, {
    'name': 'sk.fourq.ota_update/method', 'kind': 'MethodChannel', 'origin': 'ota_update 插件',
    'source': source('o7/b.java', 'onMethodCall'),
    'methods': [
        method('getAbi', {}, 'String: Build.SUPPORTED_ABIS[0]'),
        method('cancel', {}, 'null', side_effect='如下载进行中则 cancel、清空 call，并发送 CANCELED 错误事件。'),
    ],
    'unknown_method': 'notImplemented',
}, {
    'name': 'sk.fourq.ota_update/stream', 'kind': 'EventChannel', 'origin': 'ota_update 插件',
    'source': source('o7/b.java', 'STREAM OPENED'),
    'listen_arguments': {
        'url': {'type': 'String', 'required': True},
        'headers': {'type': 'String (JSON object)', 'required_in_handler': True, 'notes': 'map.get("headers").toString()；空字符串不解析。JSON 值逐个 getString 后作为 HTTP header。'},
        'filename': {'type': 'String|null', 'default': 'ota_update.apk'},
        'checksum': {'type': 'String|null', 'meaning': 'SHA-256 十六进制，忽略大小写；传 null/缺失时不校验。'},
        'androidProviderAuthority': {'type': 'String|null', 'default': 'com.re.xcs.ota_update_provider'},
    },
    'download': {'transport': 'HTTP request built from url plus headers', 'method': 'GET default; Java handler does not set body or override method', 'storage': '<application dataDir>/files/ota_update/<filename>', 'checksum_source': [source('o7/e.java'), source('l7/a.java', 'SHA-256')]},
    'event_success_payload': '[String(status ordinal), String(value)]',
    'success_examples': [['0', '<integer percent>'], ['1', '']],
    'status_ordinals': {'0': 'DOWNLOADING', '1': 'INSTALLING', '2': 'ALREADY_RUNNING_ERROR', '3': 'PERMISSION_NOT_GRANTED_ERROR', '4': 'INTERNAL_ERROR', '5': 'DOWNLOAD_ERROR', '6': 'CHECKSUM_ERROR', '7': 'CANCELED'},
    'error_payload': 'EventSink.error(String(status ordinal), String message, null)',
    'installation': {'API>=24': 'INSTALL_PACKAGE + FileProvider content URI + FLAG_GRANT_READ_URI_PERMISSION + FLAG_ACTIVITY_NEW_TASK', 'API<24': 'VIEW + file URI + application/vnd.android.package-archive + FLAG_ACTIVITY_NEW_TASK'},
    'cancellation': 'EventChannel onCancel 仅清空 event sink；MethodChannel cancel 才取消 HTTP call。',
    'state_caveats': 'headers、checksum 字段未在每次 listen 前重置；缺失或空值可能保留之前值。此为 Android 层行为，未验证 Dart 是否复用此调用模式。',
}, {
    'name': 'wifi_scan', 'kind': 'MethodChannel', 'origin': 'wifi_scan 插件',
    'source': source('v4/d.java', 'canStartScan'),
    'methods': [
        method('canStartScan', {'askPermissions': 'bool required'}, 'int status', notes='API<28 直接返回 1；其它版本检查定位权限和定位开关。'),
        method('canGetScannedResults', {'askPermissions': 'bool required'}, 'int status'),
        method('startScan', {}, 'bool: WifiManager.startScan()'),
        method('getScannedResults', {}, 'List<Map>: wifi_scan_result'),
    ],
    'result_schemas': {'wifi_scan_result': wifi_fields},
    'status_codes': {'1': '允许', '2': '权限未授权且 askPermissions=false', '3': '本次申请被拒绝', '4': '只获粗定位，需要精确定位', '5': '权限已获但系统定位服务关闭'},
    'internal_only_status': '-1 仅触发异步申请权限分支，Smali 确认不返回给 Dart。',
    'errors': [{'code': 'InvalidArgs', 'message': 'askPermissions argument is null', 'details': None}, {'code': 'NullActivity', 'message': 'Cannot ask for location permission.', 'details': 'Looks like called from non-Activity.'}],
    'unknown_method': 'notImplemented; Smali 确认 JADX 在 switch 控制流上有误。',
    'smali_verified_sources': [str(DECODED / 'smali/v4/d.smali'), str(DECODED / 'smali/v4/d$d.smali'), str(DECODED / 'smali/v4/d$e.smali')],
    'permission_rule': '系统 SDK>=29 且 targetSdk>=29 要求精确定位；SDK>30 请求粗定位+精确定位，其它情况下请求一个定位权限组。',
    'scope_note': '这里只注册扫描/扫描结果能力，没有连接 WiFi、修改网络密码或配置设备的 Android 方法。',
}, {
    'name': 'wifi_scan/onScannedResultsAvailable', 'kind': 'EventChannel', 'origin': 'wifi_scan 插件',
    'source': source('v4/d.java', 'resultsUpdated'),
    'listen_arguments': 'ignored', 'event_payload': 'List<Map>: wifi_scan_result (same 14 fields)',
    'behavior': 'onListen 立即推送一次已有结果；收到 android.net.wifi.SCAN_RESULTS 且 resultsUpdated=true 再推送。onCancel 结束 sink。',
}]

asset = {'id': 'String', 'duration': 'int64 seconds (entity duration /1000)', 'type': 'int', 'createDt': 'int64', 'width': 'int', 'height': 'int', 'orientation': 'int', 'modifiedDt': 'int64', 'lat': 'number|null', 'lng': 'number|null', 'title': 'String', 'relativePath': 'String', 'mimeType': 'String optional'}
album = {'id': 'String', 'name': 'String', 'assetCount': 'int', 'isAll': 'bool', 'modified': 'int64 optional'}
photo_methods = [
    method('saveImageWithPath', {'path': 'String required', 'title': 'String|null -> empty', 'desc': 'String|null -> empty', 'relativePath': 'String|null -> empty', 'orientation': 'int|null'}, 'asset'),
    method('saveImage', {'image': 'Uint8List required', 'filename': 'String|null -> empty', 'title': 'String|null -> empty', 'desc': 'String|null -> empty', 'relativePath': 'String|null -> empty', 'orientation': 'int|null'}, 'asset'),
    method('saveVideo', {'path': 'String required', 'title': 'String required', 'desc': 'String|null -> empty', 'relativePath': 'String|null -> empty', 'orientation': 'int|null'}, 'asset'),
    method('getAssetPathList', {'type': 'int required', 'hasAll': 'bool required', 'onlyAll': 'bool required', 'option': 'filter_option required'}, '{data: List<album>}; excludes albums with assetCount=0'),
    method('fetchPathProperties', {'id': 'String required', 'type': 'int required', 'option': 'filter_option required'}, '{data: List<album>} or null'),
    method('getAssetListPaged', {'id': 'String required', 'type': 'int required', 'page': 'int required', 'size': 'int required', 'option': 'filter_option required'}, '{data: List<asset>}'),
    method('getAssetListRange', {'id': 'String required', 'type': 'int required', 'start': 'int required', 'end': 'int required', 'option': 'filter_option required'}, '{data: List<asset>}'),
    method('getAssetCountFromPath', {'id': 'String required', 'type': 'int required', 'option': 'filter_option required'}, 'int'),
    method('getAssetCount', {'type': 'int required', 'option': 'filter_option required'}, 'int'),
    method('getAssetsByRange', {'type': 'int required', 'start': 'int required', 'end': 'int required', 'option': 'filter_option required'}, '{data: List<asset>}'),
    method('fetchEntityProperties', {'id': 'String required'}, 'asset|null'),
    method('getThumb', {'id': 'String required', 'option': 'thumb_option required'}, 'Uint8List'),
    method('requestCacheAssetsThumb', {'ids': 'List<String> required', 'option': 'thumb_option required'}, 'int 1; returned before background thumbnail caching finishes'),
    method('cancelCacheRequests', {}, 'null'),
    method('getFullFile', {'id': 'String required', 'isOrigin': 'bool read only when media-location permission granted'}, 'String file path'),
    method('getOriginBytes', {'id': 'String required'}, 'Uint8List; downstream handler'),
    method('getLatLngAndroidQ', {'id': 'String required'}, '{lat:double,lng:double}; defaults to {lat:0.0,lng:0.0} if no EXIF GPS'),
    method('getMediaUrl', {'id': 'String required; parsed as long', 'type': 'int required'}, 'String'),
    method('assetExists', {'id': 'String required'}, 'bool'),
    method('notify', {'notify': 'bool; true enables, other/null disables'}, 'null'),
    method('moveAssetToPath', {'assetId': 'String required', 'albumId': 'String required'}, 'asset|null on exception'),
    method('copyAsset', {'assetId': 'String required', 'galleryId': 'String required'}, 'asset|null on exception'),
    method('deleteWithIds', {'ids': 'List<String> required'}, 'List<String>; API>=30 system consent success returns supplied ids, canceled returns []; API29 tracks accepted/direct deletion IDs; API<29 returns supplied ids'),
    method('moveToTrash', {'ids': 'List<String> required'}, 'List<String>; API>=30 system consent success returns supplied ids, canceled returns []; API<=29 error'),
    method('removeNoExistsAssets', {}, 'bool'),
    method('getColumnNames', {}, 'List<String>'),
    method('getPermissionState', {'androidPermission': {'type': 'int required', 'mediaLocation': 'bool required'}}, 'permission_state int'),
    method('requestPermissionExtend', {'androidPermission': {'type': 'int required', 'mediaLocation': 'bool required'}}, 'permission_state int'),
    method('presentLimited', {'type': 'int required'}, 'API<34: null (base logs not implemented); API>=34: requests image/video/visual-selection permissions, callback returns int 1'),
    method('systemVersion', {}, 'String: Build.VERSION.SDK_INT'),
    method('forceOldApi', {}, 'int 1'),
    method('log', 'bool directly as arguments, not Map; null -> false', 'int 1'),
    method('ignorePermissionCheck', {'ignore': 'bool required'}, 'bool same as ignore'),
    method('clearFileCache', {}, 'int 1; asynchronous cache removal'),
    method('openSetting', {}, 'int 1; launches app settings'),
    method('releaseMemoryCache', {}, 'int 1; handler does not perform explicit cache removal'),
]
channels += [{
    'name': 'com.fluttercandies/photo_manager', 'kind': 'MethodChannel', 'origin': 'photo_manager 插件',
    'source': source('c4/g.java'), 'methods': photo_methods,
    'result_schemas': {'asset': asset, 'album': album, 'permission_state': {'0': 'NotDetermined', '2': 'Denied', '3': 'Authorized', '4': 'Limited'}, 'thumb_option': {'width': 'int', 'height': 'int', 'format': 'int: 0 JPEG; other PNG', 'quality': 'int', 'frame': 'int'}, 'filter_option': {'type': 'int: 0 normal; 1 custom; others throw', 'child': 'Map; see filter_schema.json'}},
    'query_type_bitmask': {'1': 'Image', '2': 'Video', '4': 'Audio', 'note': 'query argument combines bits; distinct from Android MediaStore media_type values 1=image,2=audio,3=video'},
    'result_schema_source': [source('g4/c.java'), source('e4/d.java'), source('e4/e.java'), source('c4/b.java'), source('c4/e.java'), source('g4/e.java'), source('g4/g.java'), source('h4/a.java'), source('i4/e.java')],
    'unknown_method': 'notImplemented for media worker dispatch; other routes classified by b4.b',
    'scope_note': '36 个可辨识方法为插件提供的能力；不能从插件注册直接认定业务实际调用了保存、删除、音频访问等功能。',
}, {
    'name': 'com.fluttercandies/photo_manager/notify', 'kind': 'MethodChannel Android->Dart callback',
    'source': source('c4/f.java', 'public final void d(Uri uri'),
    'methods': [method('change', {'platform': 'android', 'uri': 'String', 'type': 'insert|update|delete', 'mediaType': 'int', 'id': 'int64 optional', 'galleryId': 'int64 optional'}, 'not inspected (callback)')],
}]

path_methods = [
    ('getTemporaryPath', '[]', 'String', 'Context.getCacheDir().getPath()'),
    ('getApplicationSupportPath', '[]', 'String', 'Context.getFilesDir().getPath()'),
    ('getApplicationDocumentsPath', '[]', 'String', 'Context.getDir("flutter",0).getPath()'),
    ('getApplicationCachePath', '[]', 'String', 'Context.getCacheDir().getPath()'),
    ('getExternalStoragePath', '[]', 'String|null', 'Context.getExternalFilesDir(null).getAbsolutePath()'),
    ('getExternalCachePaths', '[]', 'List<String>', 'Context.getExternalCacheDirs(); nonnull only'),
    ('getExternalStoragePaths', '[int enum index]', 'List<String>', 'Context.getExternalFilesDirs(directory enum string); nonnull only'),
]
for name, args, result, behavior in path_methods:
    channels.append({'name': 'dev.flutter.pigeon.PathProviderApi.' + name, 'kind': 'BasicMessageChannel (Pigeon)', 'origin': 'path_provider_android 插件', 'source': source('n5/i.java', 'PathProviderApi.' + name), 'arguments': args, 'success_envelope': '[' + result + ']', 'error_envelope': '[code, message, details]', 'behavior': behavior})

prefs_methods = [
    ('remove', '[String key]', 'bool commit()'),
    ('setBool', '[String key, bool value]', 'bool commit()'),
    ('setString', '[String key, String value]', 'bool commit(); rejects special encoding prefixes'),
    ('setInt', '[String key, int value]', 'bool commit(); stores long'),
    ('setDouble', '[String key, double value]', 'bool commit(); stores prefixed Double.toString'),
    ('setStringList', '[String key, List<String> value]', 'bool commit(); stores prefix plus Java serialization Base64'),
    ('clear', '[String prefix, List<String>|null allowList]', 'bool commit(); removes only keys matching prefix and allowList'),
    ('getAll', '[String prefix, List<String>|null allowList]', 'Map<String,Object> matching prefix and allowList; decodes special types'),
]
for name, args, result in prefs_methods:
    channels.append({'name': 'dev.flutter.pigeon.SharedPreferencesApi.' + name, 'kind': 'BasicMessageChannel (Pigeon)', 'origin': 'shared_preferences_android 插件', 'source': source('o5/j.java', 'SharedPreferencesApi.' + name), 'arguments': args, 'success_envelope': '[' + result + ']', 'error_envelope': '[code, message, details]'})

write_json('android_channels.json', {'scope': 'Selected Android handlers (backDesktop, OTA, WiFi scan, PhotoManager, PathProvider, SharedPreferences); other registered plugin methods not enumerated here; actual Dart invocation unverified', 'codec': 'Method/EventChannel use default StandardMethodCodec; Pigeon uses j5.q StandardMessageCodec', 'channels': channels})
write_json('storage_schema.json', {
    'shared_preferences_file': '<app dataDir>/shared_prefs/FlutterSharedPreferences.xml',
    'java_source': source('o5/l.java'),
    'storage_mode': 'Context.MODE_PRIVATE (0)',
    'java_layer_key_policy': 'Keys accepted as supplied; no hardcoded flutter. prefix imposed by Android layer. clear/getAll take prefix and optional allowList.',
    'encoding': {
        'list': {'prefix': 'VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIGxpc3Qu', 'payload': 'ObjectOutputStream.writeObject(List<String>), Base64.DEFAULT'},
        'double': {'prefix': 'VGhpcyBpcyB0aGUgcHJlZml4IGZvciBEb3VibGUu', 'payload': 'Double.toString decimal'},
        'legacy_big_integer': {'prefix': 'VGhpcyBpcyB0aGUgcHJlZml4IGZvciBCaWdJbnRlZ2Vy', 'payload': 'base36; read support only'},
        'legacy_string_set': 'read converts Set to list and rewrites to prefixed Java serialization',
    },
    'path_provider_directory_enum': dict(enumerate(['ROOT', 'MUSIC', 'PODCASTS', 'RINGTONES', 'ALARMS', 'NOTIFICATIONS', 'PICTURES', 'MOVIES', 'DOWNLOADS', 'DCIM', 'DOCUMENTS'])),
    'evidence_note': 'APK 本身不含用户设备上的运行时 shared_prefs、已下载 APK、相册内容或配置值；这里只恢复存储路径和编码规则。',
})
write_json('filter_schema.json', {
    'sources': [source('g4/c.java'), source('f4/a.java'), source('f4/b.java')],
    'wrapper': {'type': 'int required: 0 normal /1 custom', 'child': 'Map required'},
    'type_0_child': {
        'image|video|audio': {'required': False, 'default': 'new f4.d()', 'when_present': {'title': 'bool', 'size': {'minWidth': 'int', 'maxWidth': 'int', 'minHeight': 'int', 'maxHeight': 'int', 'ignoreSize': 'bool'}, 'duration': {'min': 'int', 'max': 'int', 'allowNullable': 'bool'}}},
        'createDate': {'min': 'numeric convertible to long, milliseconds', 'max': 'numeric convertible to long, milliseconds', 'ignore': 'bool/string convertible to Boolean'},
        'updateDate': {'min': 'numeric convertible to long, milliseconds', 'max': 'numeric convertible to long, milliseconds', 'ignore': 'bool/string convertible to Boolean'},
        'containsPathModified': 'bool',
        'orders': 'List<{type:int(0 date_added /1 date_modified), asc:bool}>; empty defaults _id DESC',
    },
    'type_1_child': {'containsPathModified': 'bool', 'where': 'String', 'orderBy': 'List<{column:String, isAsc:bool}>|null'},
})

# Automatic inventory retains each precise source branch with direct and helper-read args.
photo_text = (JAVA / 'c4/g.java').read_text()
branch_pattern = re.compile(r'(?:str2|str)\.equals\("([^"]+)"\)')
branch_inventory = []
for match in branch_pattern.finditer(photo_text):
    tail = photo_text[match.end():]
    next_case = re.search(r'\n\s*(?:case |default:)', tail)
    branch_end = match.end() + (next_case.start() if next_case else len(tail))
    snippet = photo_text[match.start():branch_end]
    keys = set(re.findall(r'jVarD\.a\("([^"]+)"\)', snippet))
    keys.update(re.findall(r'[ik]\(jVarD, "([^"]+)"\)', snippet))
    if re.search(r'\bj\(jVarD\)', snippet):
        keys.add('option')
    branch_inventory.append({'method': match.group(1), 'line': photo_text[:match.start()].count('\n') + 1, 'argument_keys': sorted(keys), 'source_file': str(JAVA / 'c4/g.java'), 'source_excerpt': snippet.rstrip()})
write_json('photo_source_branches.json', {'source': source('c4/g.java'), 'branches': branch_inventory})

smali_sections = []
for relative, signature in [
    ('smali/v4/d.smali', '.method public a(Lj5/j;Lj5/k$d;)V'),
    ('smali/v4/d$d.smali', '.method public final a(Lv4/d$a;)V'),
    ('smali/v4/d$e.smali', '.method public final a(Lv4/d$a;)V'),
]:
    smali_path = DECODED / relative
    text = smali_path.read_text()
    start = text.index(signature)
    end = text.index('.end method', start) + len('.end method')
    smali_sections.append('// Source: ' + str(smali_path) + '\n' + text[start:end])
(OUT / 'wifi_smali_control_flow.txt').write_text('\n\n'.join(smali_sections) + '\n', encoding='utf-8')

report = f'''Android 平台接口深提取（APK 静态证据）

目录：{OUT}
分析范围：JADX Java / Apktool Manifest、XML、Smali。不安装 APK、不调用服务器、不输出密钥。
结论边界：下面给出 Android 端处理器的协议。插件静态注册和接口存在，均不等于 Dart 当前业务实际调用这些能力。

1. 应用入口及外部组件
Manifest 包名 com.re.xcs，启动类 com.example.distinguish.MainActivity。它注册 14 个插件，另加一个应用自定义通道。
MainActivity exported=true，MAIN/LAUNCHER；singleTop，taskAffinity 为空。没有声明业务 deep-link、Service 或自定义广播接收器。
两个 Provider 都不导出：OTA FileProvider 和 AndroidX Startup。URL Launcher WebViewActivity 不导出。
ProfileInstallReceiver exported=true，但要求 android.permission.DUMP。它是 AndroidX 性能配置接收器，不能当作未受限的业务入口。
OTA Provider authority=com.re.xcs.ota_update_provider；只覆盖内部 files/ota_update/；grantUriPermissions=true。
application usesCleartextTraffic=true，network_security_config 的 base-config cleartextTrafficPermitted=true，没有 domain-config。
声明互联网、外部存储、图片/视频读取、安装包、WiFi 状态/扫描和定位权限；Manifest 未声明 CAMERA、蓝牙权限或 Android Service。

2. 应用自定义 MethodChannel
名称 android/back/desktop；方法 backDesktop；未读取参数。
Android 先返回 true，再 moveTaskToBack(false)，将当前任务移到后台。
处理器对未知方法没有显式返回，因此未知调用可能一直等待；静态代码不能证明界面触发方式。

3. OTA 下载/更新协议
MethodChannel sk.fourq.ota_update/method 只有 getAbi 与 cancel。
getAbi 返回首个支持 ABI；cancel 取消进行中的 HTTP call，返回 null，并发送 CANCELED 错误事件。
下载实际从 EventChannel sk.fourq.ota_update/stream 的 listen 参数开始：
  url: 必填字符串；headers: Java 直接 .toString()，预期为 JSON 对象字符串，空字符串跳过解析。
  filename: 可空，默认 ota_update.apk；checksum: 可空，SHA-256 十六进制且大小写不敏感。
  androidProviderAuthority: 可空，默认 com.re.xcs.ota_update_provider。
HTTP 请求将 headers 逐项加入；保存到 <dataDir>/files/ota_update/<filename>。
成功事件是两个字符串组成的数组：["0", "进度整数"]、["1", ""]。
状态 ordinal：0 下载中，1 安装中，2 已有任务，3 权限未获，4 内部错误，5 下载错误，6 校验错误，7 取消。
错误通过 EventSink.error(状态字符串, message, null) 发出。
API>=24 使用 content URI + INSTALL_PACKAGE 启动系统安装界面；低版本使用 file URI + VIEW。
onCancel 只是清空 sink，真正取消下载需要调用 cancel。
headers/checksum 没有在每次 listen 前重置；空值可能复用旧值。Dart 是否存在这种复用尚未验证。
本层能够验证可选 SHA-256 文件校验；没有读到它执行应用自身的 APK 签名比较。系统安装阶段的检查另属 Android。

4. WiFi 扫描协议
MethodChannel wifi_scan 提供 canStartScan、canGetScannedResults、startScan、getScannedResults。
前两个方法必须传 askPermissions:boolean，缺失时报 InvalidArgs。
canStartScan 在 API<28 直接允许；其它版本检查定位权限、定位开关；canGetScannedResults 检查相同前置状态。
状态码：1 允许，2 尚未授权，3 本次授权被拒，4 需要精确定位，5 系统定位关闭。
内部 -1 表示申请权限，Smali 确认不会返回给 Dart，且异步分支只完成一次回复。JADX switch 输出的重复回复不是实际字节码行为。
无 Activity 时申请返回 NullActivity 错误；未知方法返回 notImplemented。
startScan 返回 WifiManager.startScan() 的布尔值；getScannedResults 返回扫描项数组。
扫描项共 14 个字段：ssid、bssid、capabilities、frequency、level、timestamp、standard、centerFrequency0、centerFrequency1、channelWidth、isPasspoint、operatorFriendlyName、venueName、is80211mcResponder。
standard 仅 API>=30 有值；其余扩展字段大多 API>=23 有值；低版本值为 null。
EventChannel wifi_scan/onScannedResultsAvailable 在订阅时立刻推送缓存结果；SCAN_RESULTS 广播且 resultsUpdated=true 时再推送。
这里没有连接 WiFi/设置密码方法；业务设备配网可能使用其它网络协议，不能归于这个扫描插件。

5. 相册与图片协议
MethodChannel com.fluttercandies/photo_manager 恢复 {len(photo_methods)} 个方法；详见 android_channels.json。
关键保存方法：saveImage 的 image 是 Uint8List；saveImageWithPath 的 path 是字符串；saveVideo 的 path/title 必填。
它们还接受 desc、relativePath、orientation 等字段。title/desc/relativePath 多数可空并转为空字符串。
保存返回 asset Map；字段 id、duration、type、createDt、width、height、orientation、modifiedDt、lat、lng、title、relativePath，mimeType 可选。
资源数组返回 {{data:[asset...]}}；相册数组返回 {{data:[{{id,name,assetCount,isAll,modified?}}...]}}。
getThumb 和 requestCacheAssetsThumb 的 option 包括 width、height、format、quality、frame；format=0 JPEG，其余 PNG。
过滤 option 是 {{type, child}}：type=0 常规过滤，type=1 自定义 where/orderBy；完整子字段见 filter_schema.json。
权限状态码：0 未决定，2 拒绝，3 授权，4 有限授权；requestPermissionExtend/getPermissionState 使用 androidPermission={{type,mediaLocation}}。
notify 启用 MediaStore ContentObserver；通过 com.fluttercandies/photo_manager/notify 发起 change 回调，字段 platform=android、uri、type、mediaType，以及可选 id/galleryId。
插件提供删除/移动等通用能力不等于业务界面使用了它们。本次未执行任何相册读取或修改。

6. 本地路径与偏好存储
PathProvider 为 7 个 Pigeon BasicMessageChannel：临时目录、应用支持目录、文档目录、缓存、外部 files、外部 cache、多外部 files。
请求为列表，回复成功包为 [结果]；异常包为 [code,message,details]。
应用支持目录是 Context.getFilesDir()，文档目录是 Context.getDir("flutter",0)，两个缓存 API 都返回 getCacheDir()。
SharedPreferences 为 8 个 Pigeon 通道：remove、setBool、setString、setInt、setDouble、setStringList、clear、getAll。
存储文件 <dataDir>/shared_prefs/FlutterSharedPreferences.xml。Android 接受传入 key，不强加 flutter. 前缀；clear/getAll 接受 prefix 和可空 allowList。
double 使用特殊前缀+十进制字符串；字符串列表用特殊前缀+Java ObjectOutputStream 序列化的 Base64；也兼容读取 BigInteger/旧 Set。编码见 storage_schema.json。
APK 静态内容没有运行时用户配置、实际保存的 token、偏好 XML 或下载包；此处恢复的是路径与编码规则。

7. 复核与可重现
脚本：{APP / 'scripts/android_extract_surface.py'}
可用 Python 3 重新执行。JSON 记录源文件绝对路径、行号、SHA-256，photo_source_branches.json 保留分支与直接读取参数。
wifi_smali_control_flow.txt 保存三个关键 Smali 方法，以修正 JADX 控制流误差。
未做动态调用，未接触用户设备数据，未把本地 MethodChannel 当作远程 API。
'''
(OUT / 'Android平台接口提取说明.txt').write_text(report, encoding='utf-8')

assert len({c['name'] for c in channels}) == len(channels)
assert len(plugins) == 14
for channel in channels:
    evidence = channel['source']
    evidence_path = Path(evidence['file'])
    assert evidence_path.exists()
    assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == evidence['sha256']
    if evidence['line'] is not None:
        assert 1 <= evidence['line'] <= len(evidence_path.read_text().splitlines())
method_names = {m['method'] for m in photo_methods}
branch_names = {b['method'] for b in branch_inventory}
extra_dispatch_names = set(re.findall(r'e6\.k\.a\(str, "(presentLimited|requestPermissionExtend)"\)', photo_text))
assert method_names == branch_names | extra_dispatch_names
for branch in branch_inventory:
    schema = next(m for m in photo_methods if m['method'] == branch['method'])
    if isinstance(schema['arguments'], dict):
        assert set(branch['argument_keys']) <= set(schema['arguments']), branch['method']
write_json('verification.json', {
    'script': str(Path(__file__).resolve()),
    'checks': ['channel names unique', '14 registered plugin mappings', 'channel source files / hashes / line references valid', '36 PhotoManager dispatch methods covered by manually annotated schemas', 'all direct Java argument keys covered by corresponding schema', 'all JSON outputs parse'],
    'counts': {'target_channels': len(channels), 'registered_plugins': len(plugins), 'photo_methods': len(photo_methods), 'photo_switch_branches': len(branch_inventory), 'photo_additional_permission_dispatches': len(extra_dispatch_names), 'manifest_components': len(components)},
    'status': 'passed',
})
for json_path in OUT.glob('*.json'):
    json.loads(json_path.read_text(encoding='utf-8'))
print(json.dumps({'output_dir': str(OUT), 'plugins': len(plugins), 'channels': len(channels), 'photo_methods': len(photo_methods), 'components': len(components)}, ensure_ascii=False))
