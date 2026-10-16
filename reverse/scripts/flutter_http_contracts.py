#!/usr/bin/env python3
"""Publish manually reviewed HTTP contracts, tied to exact Blutter method evidence.

This script reads a local AOT dump only. It neither invokes the APK/libraries nor
issues requests. Constants are not interpreted by string adjacency; the contract
annotations below were reviewed against register/array stores and direct calls.
"""

from _paths import app_root, workspace_root
from pathlib import Path
import hashlib
import json
import re

ROOT = app_root()
ASM = ROOT / "analysis/aot_dump/asm"
OUT = ROOT / "analysis/http_contract"
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "evidence").mkdir(exist_ok=True)


def dump(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


METHODS = {}
for p in (ASM / "distinguish").rglob("*.dart"):
    ls = p.read_text().splitlines()
    for i, line in enumerate(ls):
        m = re.match(r"    // \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)", line)
        if not m:
            continue
        j = next(j for j in range(i + 1, len(ls)) if ls[j] == "  }")
        METHODS[m[1]] = dict(file=p, start_line=i, end_line=j + 1,
                              header=ls[i - 1], size=m[2], lines=ls[i - 1:j + 1])


def add_external_method(relative, address):
    p = ASM / relative
    ls = p.read_text().splitlines()
    i = next(i for i, s in enumerate(ls) if "// ** addr: " + address + "," in s)
    j = next(j for j in range(i + 1, len(ls)) if ls[j] == "  }")
    METHODS[address] = dict(file=p, start_line=i, end_line=j + 1,
                            header=ls[i - 1], lines=ls[i - 1:j + 1])


EVIDENCE = {}


def evidence(address, needles=()):
    m = METHODS[address]
    body = "\n".join(m["lines"]) + "\n"
    for needle in needles:
        assert needle in body, (address, needle)
    path = OUT / "evidence" / (address[2:] + ".asm.txt")
    path.write_text("Source: " + str(m["file"]) + "\nLines: " + str(m["start_line"]) +
                    "-" + str(m["end_line"]) + "\n\n" + body)
    info = dict(address=address, source=str(m["file"]),
                source_start_line=m["start_line"], source_end_line=m["end_line"],
                method_header=m["header"].strip(),
                snippet=str(path), snippet_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    EVIDENCE[address] = info
    return info


def field(name, kind, origin, addr, fallback=None, fallback_reason=None):
    value = dict(name=name, dart_type=kind, origin=origin,
                 evidence_address=addr, inclusion="always inserted by reviewed client caller",
                 server_required="unknown", server_default="unknown")
    if fallback_reason is not None:
        value["client_fallback"] = fallback
        value["client_fallback_condition"] = fallback_reason
    else:
        value["client_fallback"] = "none in reviewed request-construction method"
    return value


WIFI = [field("ssid", "String", "Wi-Fi SSID controller.text", "0x4afb30"),
        field("pwd", "String", "Wi-Fi password controller.text", "0x4afb30")]
DATA = [field("data_send", "int", "_OnlineSettingPageState unboxed field_2b", "0x4aff98"),
        field("timeout", "int", "int.parse(controller field_43.text)", "0x4aff98"),
        field("delay", "int", "int.parse(controller field_47.text)", "0x4aff98"),
        field("count_type", "int", "state unboxed field_33", "0x4aff98"),
        field("upload_img_clarity", "int", "state unboxed field_3b", "0x4aff98")]
NUMBER = [field(n, "int", "int.parse(direction count controller.text)", "0x4b0db0")
          for n in ["east", "south", "west", "north"]]
PREVIEW = [field(n, "double" if n == "brightness" else "int",
                 ("UI double, retained as boxed Double" if n == "brightness" else
                  "UI double.toInt() (fcvtzs + Smi/Mint)" if n in ["left", "top", "right", "bottom", "motor"] else
                  "UI state unboxed int, boxed as Smi/Mint"), "0x45fcb4")
           for n in ["left", "top", "right", "bottom", "brightness", "motor",
                     "cap_brightness", "cap_exposure", "cap_hue", "cap_saturation", "cap_contrast",
                     "cap_gain", "img_rotation", "img_min_hreshold", "cap_fps", "bate", "img_add_num",
                     "gk_min", "gk_max"]]
ADD = [field("mahjong_number", "int", "row result item unboxed field_27", "0x4a2164"),
       field("serial_number", "num", "num.tryParse(Devices.serial_no ?? '0'); null parse throws FormatException",
             "0x4a2164", 0, "Devices.serial_no is null, then parse literal '0'"),
       field("direction", "int?", "channel Devices.direction (compressed field_4b)", "0x4a2164"),
       field("result", "int", "int.parse(result item's String field_7)", "0x4a2164")]
PWD = [field("old_password", "String", "old-password controller.text", "0x42c004"),
       field("password", "String", "new-password controller.text", "0x42c004")]
QUERY = [field("type", "int", "constant 1; raw stored Smi is 2", "0x492be0", 1, "constant in request literal"),
         field("version", "String (normal caller)", "syncCheckUpdateApp -> await Utils.getVersion -> PackageInfo.version",
               "0x492b80"),
         field("app_name", "String", "LoadStaticField(0xb28); snapshot default 'xcs'; no business StoreStaticField found",
               "0x492be0", "xcs", "snapshot static field default, corroborated by root Blutter isolate field-table export")]

BODY_SCHEMAS = {"wifi": WIFI, "data_config": DATA, "number_config": NUMBER,
                "preview_params": PREVIEW, "zhuo_add_item": ADD, "edit_password": PWD,
                "check_update_query": QUERY}
BODY_EVIDENCE = {"wifi": ["0x4afb30", "0x4b42d0"], "data_config": ["0x4aff98"],
                 "number_config": ["0x4b0db0"], "preview_params": ["0x45fcb4"],
                 "zhuo_add_item": ["0x4a2164"], "edit_password": ["0x42c004"],
                 "check_update_query": ["0x492be0", "0x492b80", "0x492ca8"]}

RAW_ENDPOINTS = [
    ("ConfigService", "setWifiReq", "0x4afc3c", "POST", "/api/config/set_wifi", "wifi"),
    ("ConfigService", "setDataConfigReq", "0x4b02b0", "POST", "/api/config/set_data_config", "data_config"),
    ("ConfigService", "setNumberConfigReq", "0x4b103c", "POST", "/api/config/set_number", "number_config"),
    ("ConfigService", "getWifiDefault", "0x4b2c14", "POST", "/api/config/get_default_wifi", None),
    ("ConfigService", "wifiDeviceUp", "0x4b2f5c", "GET", "/api/config/wifi_device_up", None),
    ("ConfigService", "wifiDeviceWifiList", "0x4b309c", "GET", "/api/config/get_device_wifi_list", None),
    ("ConfigService", "getMjConfigReq", "0x5245d8", "GET", "/api/mj/get_config", None),
    ("ConfigService", "getConfigReq", "0x52b0b4", "GET", "/api/config/get_config", None),
    ("PreviewService", "startPreview", "0x457dc4", "GET", "/api/preview/start_preview/{device_id}", None),
    ("PreviewService", "savePreviewParams", "0x460ab4", "POST", "/api/preview/set_params_v2/{device_id}", "preview_params"),
    ("PreviewService", "endPreview", "0x461014", "POST", "/api/preview/end_preview/{device_id}", None),
    ("_FramePreviewPageState", "_onSetPreviewImg (inlined service logic)", "0x4636b4", "POST",
     "/api/preview/set_preview_img_type/{device_id}/{img_type}", None),
    ("GamesService", "addReq", "0x4a25ac", "POST", "/api/zhuo/add", "zhuo_add_item"),
    ("GamesService", "resetGames", "0x4aa8e4", "GET", "/api/zhuo/zhuo_reset_games", None),
    ("GamesService", "endGamesReq", "0x4aaacc", "GET", "/api/zhuo/end_games", None),
    ("GamesService", "startGamesReq", "0x4abe90", "GET", "/api/zhuo/start_games", None),
    ("GamesService", "restartDevice", "0x4af6e0", "GET", "/api/zhuo/restart_device", None),
    ("MainService", "deviceStatusAll", "0x52106c", "GET", "/api/zhuo/device_status_all", None),
    ("AppService", "checkUpdateHttp / syncCheckUpdateApp", "0x492be0", "GET", "/api/app/check_update", "check_update_query"),
    ("AccountService", "editPwdReq", "0x42c1c8", "POST", "/account/edit/pwd", "edit_password"),
]

RESPONSES = {
    "setWifiReq": [("0x4afd30", "success == false selects business-error branch; msg cast to String"),
                   ("0x4b447c", "second Wi-Fi page uses same success/msg response convention")],
    "setDataConfigReq": [("0x4b0318", "success == false selects business-error branch; msg cast to String")],
    "setNumberConfigReq": [("0x4b10a4", "success == false selects business-error branch; msg cast to String")],
    "getWifiDefault": [("0x4b2c70", "on HTTP ok, checks body.success, reads body.data.ssid/pwd into text controllers")],
    "wifiDeviceUp": [("0x4b2fb8", "logs HttpResponse then invokes Wi-Fi-list request; no inspected response JSON validation")],
    "wifiDeviceWifiList": [("0x4b30f8", "reads body.data as textual Wi-Fi scan output; splits and parses platform-specific scan lines")],
    "getMjConfigReq": [("0x52a76c", "checks HTTP ok and success; iterates body.list; reads id/number/name/images/url")],
    "getConfigReq": [("0x52b110", "HTTP ok then success == false error + msg; successful body.data passed to OnlineConfig.fromJson")],
    "startPreview": [("0x45911c", "reads HTTP ok and updates UI/log; no JSON fields read in reviewed handler")],
    "savePreviewParams": [("0x460b60", "reads body.success; when truthy and caller flag enabled, calls endPreview(Devices.id)")],
    "addReq": [("0x4a2ea8", "HTTP ok then success == false error + msg; otherwise sent-success toast")],
    "resetGames": [("0x4aa940", "uses body.success to determine success toast")],
    "endGamesReq": [("0x4aab28", "uses body.success to determine success toast")],
    "startGamesReq": [("0x4abeec", "uses body.success to determine success toast")],
    "restartDevice": [("0x4af7f8", "HTTP ok then success == false error + msg; otherwise restart-success toast")],
    "deviceStatusAll": [("0x5210c8", "HTTP ok then success, iterates body.data entries, reads serial_no and online")],
    "editPwdReq": [("0x455208", "HTTP ok then success == false error + msg; otherwise password-change-success toast")],
}

ENDPOINTS = []
for owner, name, address, verb, path, schema in RAW_ENDPOINTS:
    prefix = path.split("{")[0]
    ev = evidence(address, [prefix, "HttpClient::" + verb.lower()])
    row = dict(owner=owner, method=name, address=address, http_method=verb,
               path_template=path, certainty="confirmed direct AOT call + local register/array construction",
               service_evidence=ev, path_parameters=[], query_parameters=[], request_body=None,
               backend_response_schema="not fully recovered; client observations below are not an exhaustive server schema")
    if "{device_id}" in path:
        row["path_parameters"].append(dict(name="device_id", client_dart_type="int? (Devices.id)",
                                            serialization="value.toString() then plain String concatenation",
                                            default="none; null would stringify to 'null'", backend_constraints="unknown",
                                            model_mapping_evidence=evidence("0x459f08", ['"id"']),
                                            caller_evidence=[evidence(a) for a in
                                                             (["0x457b58"] if name == "startPreview" else
                                                              ["0x45fcb4"] if name == "savePreviewParams" else
                                                              ["0x460b60", "0x4ac0b8"] if name == "endPreview" else [address])]))
    if "{img_type}" in path:
        row["path_parameters"].append(dict(name="img_type", client_dart_type="int? input; sent as integer string",
                                            serialization="(input ?? 1).toString()", client_default=1,
                                            enum_meanings="not assigned without caller-control evidence", evidence=ev))
        row["implementation_note"] = "service URL construction survived in the page method after AOT inlining"
    if schema == "check_update_query":
        row["query_parameters"] = QUERY
        row["query_schema"] = "check_update_query"
        row["parameter_evidence"] = [evidence(a) for a in BODY_EVIDENCE[schema]]
    elif schema:
        row["request_body"] = dict(location="Dio data", service_behavior="passes caller argument unchanged",
                                    dart_container_type=("List<Map<String,num?>>" if schema == "zhuo_add_item" else
                                                         "Map<String,num>" if schema == "preview_params" else
                                                         "Map<String,String>" if schema in ["wifi", "edit_password"] else
                                                         "Map<String,int>"),
                                    schema="zhuo_add_body" if schema == "zhuo_add_item" else schema,
                                    properties=BODY_SCHEMAS[schema],
                                    evidence=[evidence(a) for a in BODY_EVIDENCE[schema]])
    else:
        row["request_body"] = dict(dio_data_value=None, client_default="HttpClient.post data default null" if verb == "POST" else None,
                                    meaning="no named data/query supplied by this reviewed service method")
    response_key = name.split(" /")[0]
    row["response_client_observations"] = [dict(observation=text, evidence=evidence(a))
                                           for a, text in RESPONSES.get(response_key, [])]
    ENDPOINTS.append(row)

for schema, addresses in BODY_EVIDENCE.items():
    key_addresses = [addresses[0]]
    if schema == "check_update_query":
        key_addresses = ["0x492be0"]
    for a in key_addresses:
        evidence(a, ['"' + f["name"] + '"' for f in BODY_SCHEMAS[schema]])

for p, a in [("dio/src/options.dart", "0x453270"), ("dio/src/options.dart", "0x452344"),
             ("dio/src/options.dart", "0x44f0e8"), ("dio/src/transformer.dart", "0x4513e4")]:
    add_external_method(p, a)

TRANSPORT = dict(
    wrapper=dict(get=dict(address="0x457e8c", signature="Future<HttpResponse> get(path, {queryParameters = null})",
                          evidence=evidence("0x457e8c")),
                 post=dict(address="0x42c230", signature="Future<HttpResponse> post(path, {data = null})",
                           evidence=evidence("0x42c230")),
                 behavior="await Dio request -> handleResponse; caught Exception -> handleException; other thrown values rethrow"),
    base_url=dict(source="LoadStaticField(0xb94) captured by AppDio constructor into BaseOptions.baseUrl",
                  snapshot_default="token", value="runtime URL assigned by login chain; see root login analysis", evidence=evidence("0x45280c"),
                  uri_resolution=dict(behavior="Dio RequestOptions.uri: non-absolute path is concatenated with baseUrl; then Uri parsing/normalization and query encoding",
                                      evidence=evidence("0x44f0e8"))),
    base_options=dict(content_type="application/json", response_type="json", send_timeout=0, receive_timeout=0,
                      list_format="multi", follow_redirects=True, max_redirects=5, receive_data_when_status_error=True,
                      evidence=[evidence("0x453270"), evidence("0x452344")],
                      enum_object_evidence=dict(source=str(ROOT / "analysis/aot_dump/objs.txt"),
                                                response_type_object="Obj!ResponseType@7551e1 / enum name json",
                                                list_format_object="Obj!ListFormat@755161 / enum name multi")),
    serialization=dict(body="non-String Map/List data with JSON MIME calls JsonCodec.encode; no-body null -> empty String in default transformer",
                       evidence=evidence("0x4513e4"), application_layer_encryption="no crypto transform in reviewed HttpClient, request interceptor or parameter-building callers"),
    headers=[dict(name="clienttype", value="android", source="constant", evidence=evidence("0x68d200")),
             dict(name="Authorization", value="Bearer ${LoadStaticField(0xba4)}", snapshot_token_default="", initial_header_value="Bearer ", source="token slot; no empty-token guard in onRequest",
                  evidence=evidence("0x68d200")),
             dict(name="deviceId", value="LoadStaticField(0xbcc)", snapshot_default="", business_assignment_search="no StoreStaticField(0xbcc) found in distinguish assembly", source="empty String snapshot default; do not infer an actual unique device identifier",
                  evidence=evidence("0x68d200")),
             dict(name="clientversion", value="Utils.version at AppDio construction", default="2.0.6",
                  usual_initialization="LoginPage.read_config writes await Utils.getVersion result (root evidence 0x51daf4), so default may be overwritten before construction",
                  evidence=[evidence("0x45280c"), evidence("0x4534e8"), evidence("0x492ca8")])],
    cookies=dict(behavior="AppDio.setCookie awaits getTemporaryDirectory; FileStorage(directory.path) + PersistCookieJar + CookieManager interceptor",
                 setup="constructor calls async setCookie without awaiting", evidence=evidence("0x4529c0")),
    response_wrapper=dict(class_name="HttpResponse", recovered_member_name="ok", data_role="compressed field_b (physical offset 0x0c)",
                          exception_role="compressed field_f (physical offset 0x10)", field_name_limitation="data/exception semantic roles confirmed by assignments; original member names not present in this dump",
                          success="HTTP status >=200 and <300 -> ok=true; retain Dio Response.data unchanged",
                          unauthorized="HTTP 401 -> UnauthorisedException('没有权限'), ok=false",
                          other_status="BadRequestException(statusMessage, statusCode), ok=false",
                          json_business_success="not evaluated by handleResponse; page handlers perform endpoint-specific checks such as success == false",
                          evidence=evidence("0x42cc54")),
    response_interceptor=dict(method="ResponseInterceptors.onError", condition_operator="AND", conditions=["DioError.response.statusCode == 401", "DioError.response.data['code'] == 401"],
                              action="clear runtime token slot 0xba4; GetNavigation.offAll(LoginPage)",
                              nonmatching_action="handler.next(error)",
                              matching_branch_note="no next/resolve/reject call observed in matching redirect branch; no runtime behavior tested",
                              evidence=evidence("0x67f850")),
    exception_conversion=dict(method="HttpClient._parseException", evidence=evidence("0x42c428"),
                              confirmed_http_status_mapping={400: "BadRequestException / 请求语法错误",401: "UnauthorisedException / 没有权限",
                                                             403: "BadRequestException / 服务器拒绝执行",404: "BadRequestException / 无法连接服务器",
                                                             405: "BadRequestException / 请求方法被禁止",500: "BadServiceException / 服务器内部错误",
                                                             502: "BadServiceException / 无效的请求",503: "BadServiceException / 服务器挂了",
                                                             505: "UnauthorisedException / 不支持HTTP协议请求"})
)

STATIC_DEFAULTS_PATH = ROOT / "analysis/aot_static_defaults/static_field_defaults.txt"
static_text = STATIC_DEFAULTS_PATH.read_text()
assert 'slot=0xb28, field_id=714, class_id=93, value=String: "xcs"' in static_text
assert 'slot=0xbcc, field_id=755, class_id=93, value=String: ""' in static_text
TRANSPORT["static_defaults_evidence"] = dict(source=str(STATIC_DEFAULTS_PATH),
                                             sha256=hashlib.sha256(STATIC_DEFAULTS_PATH.read_bytes()).hexdigest(),
                                             method="root local Blutter extension reads isolate.field_table At(offset/4); Dart business not executed",
                                             used_slots={"0xb28": "xcs", "0xb94": "token", "0xba4": "", "0xbb4": "", "0xbcc": ""})

DYNAMIC_HELPERS = [
    dict(method="::getImgUrl", address="0x528820", signature="dynamic getImgUrl(String image)",
         algorithm="if image.startsWith('http://') || image.startsWith('https://'): return image; else return 'http://' + static slot 0xbb4 + '/' + image",
         base_host_slot="0xbb4", host_snapshot_default="", query="none inserted", encoding="plain String concatenation; no URL-encoding operation in helper",
         evidence=evidence("0x528820", ['"http://"', '"https://"', "LoadStaticField(0xbb4)"])),
    dict(method="_MainPageState.saveImg", address="0x5281d8", business_message_type=101,
         input="MessageUpImg.img String? (field_f), caller substitutes empty String when null",
         input_mapping_source=str(ROOT / "analysis/message_semantics/payload_models.json"),
         request=dict(http_method="GET", url="getImgUrl(message.img ?? '')", query_parameters=None, body=None,
                      shared_http_client=True, headers="same AppDio/RequestInterceptors headers described in transport",
                      call_address="0x5287a8", evidence=evidence("0x5281d8", ["getImgUrl", "HttpClient::get"])),
         response=dict(expected_dio_data_type="String (cast)", decoding="Utils.decode_data(response data) -> Base64Codec.decode -> File.writeAsBytesSync",
                       scope="application text decryption helper followed by base64-to-image-bytes; root owns crypto helper details",
                       evidence=evidence("0x529164", ["Utils::decode_data", "Base64Codec::decode", "writeAsBytesSync"])),
         cache="temporaryDirectory.path + '/cacheImg/' + concatenated date parts + '/' + Random.nextInt(1000000).toString() + '.png'",
         placeholder_branch="img == 'x' uses bundled images/other/empty.jpg and returns without HTTP GET",
         runtime_response_content_type="unknown; do not infer raw PNG HTTP body from .png cache filename")
]

candidate_path = ROOT / "analysis/flutter/api_candidates.json"
original_candidates = json.loads(candidate_path.read_text())["endpoints"]
LOGIN_PATHS = {"/api/login/login/distinguish": ("POST", "0x48f670"),
               "/api/server/get_server_addr": ("POST", "0x48fe38")}
COVERAGE = []
for candidate in original_candidates:
    p = candidate["text"]
    matched = next((e for e in ENDPOINTS if e["path_template"].split("{")[0] == p), None)
    if matched:
        covered = dict(path=p, static_string_offset=candidate["offset"], matched_template=matched["path_template"],
                       http_method=matched["http_method"], evidence_address=matched["address"], status="confirmed here")
    elif p in LOGIN_PATHS:
        verb, addr = LOGIN_PATHS[p]
        covered = dict(path=p, static_string_offset=candidate["offset"], http_method=verb,
                       evidence=evidence(addr, [p, "HttpClient::" + verb.lower()]),
                       status="confirmed service call here; detailed login map/response contract owned by root",
                       detailed_contract_directory=str(ROOT / "analysis/login_flow"))
    else:
        covered = dict(path=p, static_string_offset=candidate["offset"], status="unresolved static candidate; no dead-code claim")
    COVERAGE.append(covered)
dump("candidate_coverage.json", dict(original_api_string_candidates=len(COVERAGE),
                                     confirmed=sum(c["status"].startswith("confirmed") for c in COVERAGE),
                                     unresolved=sum(c["status"].startswith("unresolved") for c in COVERAGE),
                                     added_non_api_endpoint="POST /account/edit/pwd (not matched by initial /api filter)",
                                     static_service_template_total_including_root_login=len(ENDPOINTS) + len(LOGIN_PATHS),
                                     dynamic_image_get_separate=True, candidates=COVERAGE))

SCHEMAS = {}
for name, fields in BODY_SCHEMAS.items():
    props = {}
    for f in fields:
        kind = f["dart_type"]
        typ = ["integer", "null"] if kind == "int?" else "integer" if kind == "int" else "number" if kind in ["num", "double"] else "string" if kind.startswith("String") else None
        prop = {"type": typ} if typ else {}
        prop["description"] = f["origin"]
        prop["x-client-dart-type"] = kind
        prop["x-backend-default"] = "unknown"
        if name == "check_update_query" and f["name"] == "type": prop["const"] = 1
        props[f["name"]] = prop
    SCHEMAS[name] = dict(type="object", properties=props, required=list(props), additionalProperties=False,
                         **{"x-scope": "exact map constructed by this reviewed client caller; required describes inclusion in client map, not server validation"})
SCHEMAS["zhuo_add_body"] = dict(type="array", items={"$ref": "#/$defs/zhuo_add_item"},
                                **{"x-scope": "client collects all nested row results into one list; no minItems inferred"})
dump("parameter_schemas.json", {"$schema": "https://json-schema.org/draft/2020-12/schema", "$defs": SCHEMAS})

RESULT = dict(scope="six assigned services + inlined preview image-type request; login contracts maintained separately by root",
              artifact_kind="static AOT-derived client contract, not original Dart source and not a tested server contract",
              source_dump=str(ROOT / "analysis/aot_dump"),
              evidence_rules=["direct literal Array/Map stores + actual HttpClient call sequence establish parameters",
                              "dynamic path argument traced from page Devices.id and corroborated with toJson/fromJson",
                              "Dart compressed tagged integers decoded: stored immediate 2 means int 1; tagged 0x322 means 401",
                              "server defaults, allowed ranges, authentication enforcement, live response values stay unknown"],
              counts=dict(endpoint_templates=len(ENDPOINTS), GET=sum(e["http_method"] == "GET" for e in ENDPOINTS),
                          POST=sum(e["http_method"] == "POST" for e in ENDPOINTS),
                          unique_body_or_query_fields=sum(map(len, BODY_SCHEMAS.values())),
                          evidence_method_snippets=len(EVIDENCE)),
              endpoints=ENDPOINTS, transport=TRANSPORT, dynamic_url_helpers=DYNAMIC_HELPERS,
              original_candidate_coverage_file=str(OUT / "candidate_coverage.json"),
              cautions=["SSID/password and old/new password are inserted as controller strings without an application-level crypto call in these reviewed methods",
                        "serial_number uses num.tryParse, so it is not proven integer-only; invalid non-null serial text throws",
                        "preview brightness is a double, unlike the other 18 integer parameters; spellings are bate and img_min_hreshold",
                        "backend required/default annotations intentionally unknown; local required array means caller inserts key"])
dump("endpoint_contracts.json", RESULT)
dump("evidence_manifest.json", list(EVIDENCE.values()))

lines = ["HTTP 静态合约提取说明", "", "本轮以 Blutter 的 arm64 Dart AOT 汇编和对象池为证据，未发送请求、未运行 APK/原库。",
         "恢复 20 个 URL 模板：11 个 GET、9 个 POST；6 个 service 和 1 处内联预览设置逻辑；39 个请求 body/query 字段。",
         "所有接口记录均附原汇编文件、起始行、方法地址和单独证据摘录。参数的 required 仅表示客户端总会插入该字段，不表示服务端校验。", "",
         "接口清单："]
for e in ENDPOINTS:
    lines.append(f"{e['http_method']:4} {e['path_template']}  [{e['owner']}.{e['method']} @ {e['address']}]")
    if e["query_parameters"]:
        lines.append("  query: " + ", ".join(f["name"] + ":" + f["dart_type"] for f in e["query_parameters"]))
    elif "properties" in e["request_body"]:
        lines.append("  body: " + e["request_body"]["dart_container_type"] + " {" + ", ".join(f["name"] + ":" + f["dart_type"] for f in e["request_body"]["properties"]) + "}")
    else:
        lines.append("  未传 data/query。" + ("POST 默认 data=null，默认转换器产生空文本。" if e["http_method"] == "POST" else ""))
lines += ["", "已确认的关键细节：",
          "1. get_default_wifi 是 POST；start_preview 是 GET；end_preview、set_params_v2、set_preview_img_type 是 POST。重启/开局/结束/重置通过 GET。",
          "2. 预览路径传 Devices.id，页面先按 Devices.direction 匹配设备；不能把这两个不同字段合并。拼接前调用 toString，无此层 URL segment 编码。",
          "3. Wi-Fi body 为 ssid/pwd 两个 String；修改密码 body 为 old_password/password 两个 String，确认密码只用于本地比较。这些构造/封装方法未调用 RSA/AES。",
          "4. 数据配置 body 为 data_send/timeout/delay/count_type/upload_img_clarity 五个 int；方位数量为 east/south/west/north 四个 int，文本数字使用 int.parse。",
          "5. 发牌/结果提交 /api/zhuo/add 的 body 是 List<Map<String,num?>>；每项 mahjong_number:int、serial_number:num、direction:int?、result:int。serial_number 调用 num.tryParse，仅 serial_no=null 才回退文本 0；返回 null 时抛 FormatException。",
          "6. 预览保存共 19 项；brightness 保持 double，left/top/right/bottom/motor 从 double.toInt，另外 13 项为 int。bate、img_min_hreshold 是实际拼写，不能擅自修正成 beta、img_min_threshold。",
          "7. 更新检查 query 为 type=1、version=PackageInfo.version、app_name=xcs（静态槽 0xb28 默认导出，无业务写入）；原汇编常量 2 为 tagged Smi，Dart 值为 1。",
          "8. 请求拦截器设置 clienttype=android、Authorization=Bearer + token 槽 0xba4、deviceId 槽 0xbcc；JWT 与 deviceId 的 snapshot 默认都是空字符串，初始 Authorization 为 Bearer 后接一个空格；未找到 deviceId 的业务写入，不能把它称为真实设备标识。AppDio 构造时设置 clientversion=Utils.version。Utils.version 默认 2.0.6；正常登录页 read_config 会以 PackageInfo.version 覆盖它（根任务证据），因此默认不是固定发送版本。",
          "9. Dio 基础 content-type=application/json、ResponseType=json，Map/List 经 JsonCodec.encode；CookieManager 使用临时目录下 FileStorage/PersistCookieJar。",
          "10. HttpResponse.ok 只依据 HTTP 状态 200～299；数据直接保留 Response.data，不依据 JSON success/code 自动判断业务成功。已检查的页面会再使用 success、msg 等字段。",
          "11. 401 错误拦截器只有在 HTTP statusCode 与 JSON code 同为 401 时才清 token、跳登录；未匹配则 handler.next(error)。匹配重定向分支未观察到 next/resolve/reject，但未做动态行为验证。",
          "12. 动态图片 GET 单列 dynamic_url_helpers：101 消息的 img，若已是 http:// 或 https:// 原样使用；否则 http:// + 槽 0xbb4 + / + img。saveImg 通过同一 HttpClient.get 获取 String 响应，经 Utils.decode_data、Base64Codec.decode 后写缓存 PNG；img='x' 用本地占位图不发送请求。",
          "13. 原先 21 个 /api 字符串现全部有直接调用证据：本文件 19 个，根任务登录链 2 个；另新增初始 /api 筛选遗漏的 /account/edit/pwd，共 22 个静态 service 模板。动态图片地址不并入该 22 个计数。candidate_coverage.json 逐条映射，无字符串被未经证据认定为死代码。",
          "", "无法仅凭静态客户端确认：服务端必填/默认值、数值范围、实际授权规则、运行时 JWT 的当前值、完整服务端响应 schema。",
          "endpoint_contracts.json 为详细合约；parameter_schemas.json 为已观察到的客户端 Map schema；reconstructed_http.dart 是人工逻辑重建，非原源码。"]
(OUT / "中文说明.txt").write_text("\n".join(lines) + "\n")

dart = ["// Static AOT logic reconstruction; not original source. No network implementation.",
        "// Method evidence and uncertainties: endpoint_contracts.json.",
        "abstract interface class RecoveredHttpClient {",
        "  Future<Object?> get(String path, {Object? queryParameters});",
        "  Future<Object?> post(String path, {Object? data});", "}", "",
        "class RecoveredServices {", "  final RecoveredHttpClient http;", "  final Object? appNameSlotB28;",
        "  RecoveredServices(this.http, this.appNameSlotB28);"]
for e in ENDPOINTS:
    method = e["method"].split(" /")[0].split(" (")[0]
    args, data = [], ""
    path = e["path_template"]
    if "{device_id}" in path:
        args.append("int? deviceId")
        path = path.replace("{device_id}", "${deviceId.toString()}")
    if "{img_type}" in path:
        args.append("int? imageType")
        path = path.replace("{img_type}", "${(imageType ?? 1).toString()}")
    if e["query_parameters"]:
        args.append("String version")
        data = ", queryParameters: <String, Object?>{'type': 1, 'version': version, 'app_name': appNameSlotB28}"
    elif "properties" in e["request_body"]:
        args.append(e["request_body"]["dart_container_type"] + " data")
        data = ", data: data"
    dart.append(f"  Future<Object?> {method}({', '.join(args)}) => http.{e['http_method'].lower()}('{path}'{data});")
dart += ["}", "", "String getImgUrl(String image, String imageHostSlotBB4) =>",
         "    image.startsWith('http://') || image.startsWith('https://') ? image : 'http://$imageHostSlotBB4/$image';", "",
         "Map<String, String> wifiData(String ssid, String pwd) => {'ssid': ssid, 'pwd': pwd};",
         "Map<String, String> editPasswordData(String oldPassword, String password) =>",
         "    {'old_password': oldPassword, 'password': password};",
         "// Confirmation text is validated locally and not inserted into editPasswordData.",
         "// serial_number equivalent: num.parse(device.serial_no ?? '0')",
         "// preview body: brightness: double; left/top/right/bottom/motor: double.toInt(); other 13 entries: int."]
(OUT / "reconstructed_http.dart").write_text("\n".join(dart) + "\n")
print(json.dumps(RESULT["counts"], ensure_ascii=False))
