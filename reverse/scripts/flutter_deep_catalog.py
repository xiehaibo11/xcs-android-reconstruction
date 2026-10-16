#!/usr/bin/env python3
"""Build an evidence catalog from this APK's previously decoded Dart strings.

This catalogs constants and symbol names; it does not reconstruct call graphs,
class layouts, HTTP methods, JSON schemas, or executable Dart source.
"""

from _paths import app_root, workspace_root
import argparse
import collections
import hashlib
import json
import re
from pathlib import Path


MODEL_NAMES = {
    "AppUpdate", "Channel", "ChannelResult", "ConfigNumber", "DataConfig",
    "Devices", "LightingConfig", "Log", "Message", "MessageUpImg", "MjChangeItem",
    "MjConfig", "OnlineConfig", "User", "ViewSetting", "WifiConfig", "WifiListItem",
    "WsEvent", "HttpResponse", "HttpException", "BadServiceException",
}
APPLICATION_CLASSES = MODEL_NAMES | {
    "AccountService", "AppService", "ConfigService", "GamesService", "LogService",
    "LoginService", "MainService", "PreviewService", "ViewSettingService",
    "MainPage", "LoginPage", "EditPwdPage", "FramePreviewPage", "KeyFormPage",
    "OnlineSettingPage", "OnlineSettingWifiPage", "UpdateAppPage", "MjItem",
    "MjChangePopover", "ChangeItem", "ContentLeftSide", "ContentRightSide",
    "RequestInterceptors", "ResponseInterceptors", "AppDio", "KeyHelper",
}
NAMESPACE_ANCHORS = {
    "AccountService", "AppService", "ConfigService", "GamesService", "LogService",
    "LoginService", "MainService", "PreviewService", "ViewSettingService",
    "HttpClient", "MainPage", "LoginPage", "EditPwdPage", "FramePreviewPage",
    "KeyFormPage", "OnlineSettingPage", "OnlineSettingWifiPage", "UpdateAppPage",
    "MjItem", "MjChangePopover", "ChangeItem", "ContentLeftSide", "ContentRightSide",
    "AppDio",
}
METHOD_GROUPS = {
    "账号、入口与本地记录": [
        "onLogin", "renderLoginUser", "loginUser", "loginConfDbRead",
        "loginConfDbWrite", "inletPwdDbWrite", "backDeskTop", "backDesktop",
        "initApp", "initConfig", "getServerAddr", "rememberPassword",
    ],
    "设备与开局控制": [
        "sendStartGamesReq", "startGamesReq", "onStartGames", "endGamesReq",
        "onEndGames", "resetGames", "onResetGames", "restartDevice",
        "onRestartDevice", "updateAllDevices", "onSelectDeviceStatusAll",
        "onShowDeviceInfo", "deviceStatusAll", "getDeviceDirection",
    ],
    "配置和 WiFi": [
        "getMjConfig", "getMjConfigReq", "getConfig", "getConfigReq", "updateConfig",
        "setNumberConfigReq", "onSaveNumber", "setDataConfigReq", "onSaveDataConfig",
        "setWifiReq", "onSaveWifiConfig", "getWifiDefault", "wifiDeviceWifiList",
        "wifiDeviceUp",
    ],
    "预览与图像": [
        "endPreview", "startPreview", "showFramePreview", "onPreviewImg",
        "savePreviewParams", "setPreviewImgType", "getImageFromJpeg",
        "onValidDataAndSendData", "onValidData",
    ],
    "麻将结果与界面": [
        "updateChangeMjList", "onSelectMj", "removeChannelMjLogic",
        "removeChannelMj", "changeMj", "removeMj", "onOpenChangePage",
        "onCloseChangePage", "onViewShowType", "mjChangeItemBut",
        "buildManualPosition", "buildAutoPosition",
    ],
    "Rust 桥接公共符号": [
        "initWs", "isContentWs", "wsLogin", "wsLogout", "createEventStream",
        "crateApiSimpleInitApp", "crateApiSimpleInitWs", "crateApiSimpleIsContentWs",
        "crateApiSimpleWsLogin", "crateApiSimpleWsLogout",
        "crateApiSimpleCreateEventStream",
    ],
}
FIELD_GROUPS = {
    "设备、会话与账号候选": [
        "serial_number", "serial_no", "client_type", "clienttype", "devicetype",
        "clientversion", "deviceId", "device", "devices", "server_id", "client_ip",
        "last_ip", "user_id", "agent_id", "create_id", "create_time", "connected_at",
        "first_time", "last_time", "run_time", "working_time", "up_time", "token",
        "nonToken", "password", "old_password", "ssid", "client_wifi",
    ],
    "图像、采集与识别配置候选": [
        "cap_exposure", "cap_saturation", "cap_hue", "cap_brightness", "cap_contrast",
        "cap_gain", "cap_fps", "img_min_threshold", "img_add_num", "img_rotation",
        "upload_img_clarity", "del_cache_img", "gk_min", "gk_max", "ai_precision",
        "ai_val", "lighting_switch", "lighting_config", "data_config",
        "orientationMjHeight", "orientationMjWidth", "validMjWidth", "validMjHeight",
        "editMjWidth", "editMjHeight", "orientationHeight",
    ],
    "牌数、通道与显示候选": [
        "config_number", "mahjong_number", "mj_count", "count_type", "wifi_config",
        "viewSetting", "select_item", "select_view", "hand_view", "selectPosition",
        "changeList", "dragDevices", "sequenceNumber",
    ],
    "消息和结果候选": [
        "msg_content", "msg_type", "data_send", "decode_data", "error_text",
        "resultImg", "result180JD", "resultJD", "result180", "result180Img",
        "uploadImg", "shiBie", "mahjongNumber", "logMessage", "waring",
    ],
    "更新与持久化候选": [
        "update_url", "ota_url", "app_name", "save_config", "read_config",
    ],
}
HTTP_TERMS = {
    "baseUrl", "Authorization", "authorization", "Bearer ", "nonToken", "token",
    "RequestInterceptors", "ResponseInterceptors", "HttpClient._internal@612307927",
    "_dio@612307927", "AppDio", "getServerAddr", "FormData", "MultipartFile",
    "application/json", "application/x-www-form-urlencoded", "Content-Type",
    "content-type", "queryParameters", "sendTimeout", "receiveTimeout",
    "connectTimeout", "badResponse", "connectionTimeout", "HttpResponse",
    "HttpException", "BadServiceException", "getConfigReq",
}
CRYPTO_TERMS = {
    "RSA", "RSA.", "AbstractRSA", "AbstractRSA.", "RSAKeyParser", "RSAPrivateKey",
    "RSAPublicKey", "RSAAsymmetricKey", "RSAEngine", "PKCS1Encoding", "OAEPEncoding",
    "Encrypted", "Encrypted.fromBase64", "Encrypter", "encrypt", "decrypt",
    "decryptBytes", "SHA1Digest", "SHA256Digest", "AESEngine", "key/private_key.pem",
    "key/pub_key.pem", "PrivateKeyParameter", "KeyParameter",
    "impl.asymmetric_block_cipher.rsa", "impl.digest.sha256", "impl.digest.sha1",
}
RESULT_LABELS = {
    "ChannelResult{result: ", ", resultImg: ", ", result180JD: ", ", resultJD: ",
    ", result180: ", ", result180Img: ", ", uploadImg: ", ", shiBie: ",
    ", mahjongNumber: ", ", logMessage: ", ", waring: ", ", select: ",
}
UI_KEYWORDS = [
    "设备", "WIFI", "WiFi", "wifi", "麻将", "牌数", "配置", "预览", "识别", "电机",
    "灯光", "密码", "升级", "清晰", "色调", "饱和", "曝光", "亮度", "对比", "增益",
    "张数", "序号", "编号", "开局", "重启", "角度", "图像", "方位", "财神",
    "发送", "放送", "服务器", "在线", "离线", "固件", "相机", "采集", "光控",
    "背景", "顺序", "正序", "倒序", "倒叙", "遥控", "锁定", "重置", "引擎",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, default=app_root())
    args = parser.parse_args()
    app = args.app.resolve()
    strings = json.loads((app / "analysis/flutter/snapshot_strings.json").read_text())
    packages = json.loads((app / "analysis/flutter/application_packages.json").read_text())
    library = app / "unpacked/lib/arm64-v8a/libapp.so"
    binary = library.read_bytes()
    output = app / "analysis/deep_flutter"
    output.mkdir(parents=True, exist_ok=True)

    # Verify every input string against the exact binary bytes, without assuming
    # any semantic relationship from neighboring offsets.
    for item in strings:
        encoded = item["text"].encode(item["encoding"])
        if binary[item["offset"]:item["offset"] + len(encoded)] != encoded:
            raise ValueError(f"Binary string mismatch at {item['offset']:#x}")

    by_text = collections.defaultdict(list)
    for item in strings:
        by_text[item["text"]].append(item)

    def evidence(item):
        return {
            **item,
            "file": str(library),
            "offset_hex": f"0x{item['offset']:x}",
            "evidence_level": "exact_snapshot_string",
        }

    def matching_terms(terms):
        return [evidence(item) for item in strings if item["text"] in terms]

    def save(filename, content):
        (output / filename).write_text(
            json.dumps(content, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    source_groups = collections.defaultdict(list)
    for item in packages:
        name = item["text"].removeprefix("package:distinguish/")
        top = name.split("/")[0] if "/" in name else "入口"
        source_groups[top].append(evidence(item))
    save("source_modules.json", dict(source_groups))

    classes = []
    for item in strings:
        text = item["text"]
        base = text.split(".")[0]
        if base in APPLICATION_CLASSES and re.fullmatch(
            r"[A-Z][A-Za-z0-9]*(?:\.(?:fromJson|_internal@\d+))?\.?", text
        ):
            classes.append(evidence(item))
    save("application_class_symbols.json", {
        "limits": "类和构造函数名称的存在证据；未恢复类字段布局、继承图或方法体。",
        "symbols": classes,
    })

    namespaces = collections.defaultdict(lambda: {"anchors": [], "symbols": []})
    for item in strings:
        text = item["text"]
        match = re.search(r"@(\d+)", text)
        if not match:
            continue
        anchors = [name for name in NAMESPACE_ANCHORS if
                   text.startswith(name + "._internal@") or
                   text.startswith("_" + name + "State@") or
                   text.startswith("_" + name + "&") or
                   text.startswith("__" + name + "&")]
        if anchors:
            namespaces[match.group(1)]["anchors"].append(evidence(item))
    for identity, namespace in namespaces.items():
        namespace["symbols"] = [evidence(item) for item in strings
                                if re.search("@" + identity + r"(?!\d)", item["text"])]
    save("private_library_namespaces.json", {
        "evidence": "具有相同 @数字 后缀的 Dart 私有名称共享库身份标记。",
        "limits": "仅按完整符号后缀分组；未将字符串地址相邻关系作为归属或调用关系。"
                  "类名与 source_modules 中源码路径的对应仍需对象元数据或代码验证。",
        "namespaces": dict(namespaces),
    })

    methods = {}
    for category, terms in METHOD_GROUPS.items():
        methods[category] = matching_terms(set(terms))
    save("business_method_candidates.json", {
        "evidence": "Dart 快照中的符号名称；分类基于名称语义。",
        "limits": "不等于已确认的应用方法表；没有恢复方法参数、返回类型、所属类或调用关系。",
        "groups": methods,
    })

    fields = {}
    for category, terms in FIELD_GROUPS.items():
        fields[category] = matching_terms(set(terms))
    save("model_field_candidates.json", {
        "evidence": "快照中的独立字符串常量或名称；未与模型对象建立直接引用。",
        "limits": "候选包括 JSON 键、字段名、参数名和 UI 状态名。"
                  "不得由此直接生成模型定义或接口请求参数。",
        "groups": fields,
    })
    labels = matching_terms(RESULT_LABELS)
    save("result_print_labels.json", {
        "evidence": "字符串本身带有格式化输出标签。",
        "limits": "只确认输出标签存在；只有 ChannelResult{result: 明确带类名，"
                  "其余标签的所属模型尚未确认。",
        "labels": labels,
    })

    http_terms = matching_terms(HTTP_TERMS)
    crypto_terms = matching_terms(CRYPTO_TERMS)
    dependency_packages = [evidence(item) for item in strings
                           if item["text"].startswith(("package:dio/", "package:encrypt/",
                                                       "package:pointycastle/"))]
    api_terms = [evidence(item) for item in strings if item["text"].startswith("/api/")]
    full_urls = []
    for item in strings:
        text = item["text"]
        if re.fullmatch(r"https?://[^\s]+", text):
            category = "documentation" if ("flutter.dev/" in text or "dart-lang/" in text) \
                else "asset_reference" if "bing.net/" in text else "application_url_constant"
            full_urls.append({**evidence(item), "category_by_hostname": category,
                              "actual_use_verified": False})
    save("http_crypto_evidence.json", {
        "http_symbol_constants": http_terms,
        "api_path_constants": api_terms,
        "full_url_constants": full_urls,
        "crypto_symbols": crypto_terms,
        "dependency_paths": dependency_packages,
        "limits": "HTTP 动词、完整业务 baseUrl、端点参数结构、加密调用位置、"
                  "RSA 填充算法和 AES 是否用于业务均未由这些名称单独证实。",
    })

    ui = [evidence(item) for item in strings if re.search(r"[\u4e00-\u9fff]", item["text"])
          and any(term in item["text"] for term in UI_KEYWORDS)
          and all(c.isprintable() or c in "\r\n\t" for c in item["text"])]
    save("business_ui_texts.json", {
        "evidence": "原始快照中文常量；业务筛选基于关键词，包含通用 UI 文案的可能性。",
        "texts": ui,
    })

    package_map = collections.defaultdict(list)
    for item in strings:
        match = re.match(r"package:([^/]+)/", item["text"])
        if match:
            package_map[match.group(1)].append(evidence(item))
    save("package_namespace_inventory.json", {
        "limits": "包路径表示相关库已进入快照；不证明每个包功能均在应用中被使用。",
        "packages": dict(sorted(package_map.items())),
    })

    artifact_names = sorted(path.name for path in output.glob("*.json"))
    stats = {
        "source": str(library),
        "source_sha256": hashlib.sha256(binary).hexdigest(),
        "input_string_count": len(strings),
        "binary_bytes_verified_string_count": len(strings),
        "new_raw_strings": 0,
        "source_module_paths": len(packages),
        "source_module_groups": {key: len(items) for key, items in source_groups.items()},
        "application_class_symbols": len(classes),
        "private_library_namespace_groups": len(namespaces),
        "private_library_symbols": len({i["text"] for n in namespaces.values() for i in n["symbols"]}),
        "business_method_candidates": sum(len(items) for items in methods.values()),
        "model_field_candidates": sum(len(items) for items in fields.values()),
        "result_print_labels": len(labels),
        "http_constants": len(http_terms),
        "crypto_symbols": len(crypto_terms),
        "api_path_constants": len(api_terms),
        "full_url_constants": len(full_urls),
        "business_ui_texts": len(ui),
        "package_namespaces": len(package_map),
        "artifacts": artifact_names,
    }
    save("extraction_summary.json", stats)

    lines = [
        "Flutter / Dart 快照深度提取证据目录",
        "",
        "本次对既有 23,484 条快照字符串进行逐条二进制复核和结构化筛选；新增原始字符串为 0。",
        "新增的是业务符号、候选字段、库身份分组与证据索引，而不是完整 Dart 源码。",
        f"库文件：{library}",
        f"库 SHA-256：{stats['source_sha256']}",
        "",
        f"应用源码路径：{len(packages)}；按路径分组：" +
        "、".join(f"{name} {len(items)}" for name, items in source_groups.items()),
        f"应用类/构造符号：{len(classes)}；私有库身份分组：{len(namespaces)}；"
        f"私有名称：{stats['private_library_symbols']}。",
        f"业务方法名称候选：{stats['business_method_candidates']}；"
        f"模型/参数名称候选：{stats['model_field_candidates']}；结果打印标签：{len(labels)}。",
        f"HTTP 符号常量：{len(http_terms)}；加密符号：{len(crypto_terms)}；"
        f"接口路径：{len(api_terms)}；完整 HTTP URL：{len(full_urls)}。",
        f"筛选后的业务中文文案：{len(ui)}；整体快照包命名空间：{len(package_map)}。",
        "",
        "可以确认的原始证据：",
        "1. 应用自身 source_modules 包含 service、model、pages、widgets、common/http、src/rust。",
        "2. 同一 Dart 私有名称 @ 后缀提供库身份分组，例如：",
    ]
    for identity, namespace in namespaces.items():
        lines.append(f"   @{identity}：" + "、".join(i["text"] for i in namespace["symbols"]))
    lines += [
        "3. ViewSettingService 同库组中存在 _dbRead；loginConfDbRead/loginConfDbWrite 和"
        "inletPwdDbWrite 为独立业务持久化符号线索。不能由名称确定存储文件或内容。",
        "4. HTTP 层出现自有 HttpClient 的 _dio、Dio 路径、请求/响应拦截器、"
        "Authorization 和 Bearer 字符串。接口方法和请求结构仍需代码或运行时确认。",
        "5. 快照同时包含 RSAEngine、PKCS1Encoding、OAEPEncoding、AESEngine、"
        "SHA1Digest、SHA256Digest，以及 key/private_key.pem 和 key/pub_key.pem 的资源路径。"
        "这些类名的存在不能单独确定业务使用的算法或填充模式。",
        "6. ChannelResult{result: 是明确含类名的结果打印文本；其他 result180JD、resultJD、"
        "result180Img、uploadImg、shiBie、mahjongNumber 等标签未直接归入该类。",
        "",
        "方法名称候选（名称分类，不表示调用关系）：",
    ]
    for category, items in methods.items():
        lines.append(category + "：" + "、".join(i["text"] for i in items))
    lines += ["", "模型/参数名称候选（尚未确认所属类或端点）："]
    for category, items in fields.items():
        lines.append(category + "：" + "、".join(i["text"] for i in items))
    lines += ["", "完整 URL 常量（未访问）："]
    for item in full_urls:
        lines.append(f"{item['offset_hex']} {item['text']} [{item['category_by_hostname']}]")
    lines += [
        "",
        "验证边界：",
        "全部条目带原始文件绝对路径、文件偏移、编码和文本，可独立复核。",
        "未通过相邻字符串推断类字段、调用链或请求参数；未连接服务器；未输出密钥材料。",
        "现有字符串目录不足以恢复完整可运行源码。后续若具备与 VM 快照格式匹配的 AOT 解析器，"
        "可用本目录作为对象池/函数输出的名称交叉核对来源。",
        "",
        "主要文件：" + "、".join(artifact_names),
    ]
    (output / "Flutter深度提取说明.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
