package com.re.xcs.rebuild.core;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Executable reconstruction of bounded password/settings/WiFi contracts.
 * Evidence: evidence/logic/logic_contracts.json. This is newly written Java,
 * not recovered original Dart. Widget layout and unresolved scan ordering are
 * explicitly outside this implementation. All methods are independent of Android.
 */
public final class SettingsLogic {
    private SettingsLogic() {}

    public static final class Form {
        public String east = "26", south = "26", west = "26", north = "26";
        public String timeout = "60", delay = "5", ssid = "", wifiPassword = "";
        public int dataSend = 1, countType = 1, uploadImageClarity = 1;
        public boolean reverseChannels;
        public Map<String, Object> loadedConfig;
    }

    public enum Action { PASSWORD, DATA, NUMBER, WIFI_MANUAL, WIFI_SCAN, RESTART }
    public enum Failure { NONE, NETWORK, BUSINESS }
    public enum Navigation { NONE, LOGIN_CLEAR_STACK, POP }

    public static final class Outcome {
        public final Failure failure;
        public final String message;
        public final Navigation navigation;
        public final String logColor;
        public final boolean useOriginalShowErr;
        private Outcome(Failure failure, String message, Navigation navigation,
                        String logColor, boolean showErr) {
            this.failure = failure;
            this.message = message;
            this.navigation = navigation;
            this.logColor = logColor;
            this.useOriginalShowErr = showErr;
        }
        public boolean accepted() { return failure == Failure.NONE; }
    }

    /** Form validator messages are the exact observed strings, not new rules. */
    public static Map<String, String> validatePassword(String oldPassword,
                                                       String password,
                                                       String confirmation) {
        Map<String, String> errors = new LinkedHashMap<>();
        if (oldPassword == null || oldPassword.length() < 6)
            errors.put("old_password", "请输入原密码");
        if (password == null || password.isEmpty())
            errors.put("password", "请输入新密码");
        if (confirmation == null || confirmation.isEmpty())
            errors.put("confirmation", "请输入重复新密码");
        else if (!confirmation.equals(password))
            errors.put("confirmation", "重复密码与新密码不一致");
        return Collections.unmodifiableMap(errors);
    }

    public static ApiContract.Request preparePassword(String oldPassword,
                                                       String password,
                                                       String confirmation) {
        Map<String, String> errors = validatePassword(oldPassword, password, confirmation);
        if (!errors.isEmpty()) throw new IllegalArgumentException(errors.toString());
        return ApiContract.editPassword(oldPassword, password);
    }

    /**
     * Reproduce the pre-request mutation at 0x4b023c. No rollback occurs on an
     * HTTP/business rejection. The UI must call this when each radio changes too.
     */
    public static ApiContract.Request prepareDataSave(Form form, SessionState session) {
        int timeout = inputInteger(form.timeout);
        int delay = inputInteger(form.delay);
        ApiContract.Request request = ApiContract.dataConfig(form.dataSend, timeout,
                delay, form.countType, form.uploadImageClarity);
        session.user.put("timeout", timeout);
        return request;
    }

    public static ApiContract.Request prepareNumberSave(Form form) {
        return ApiContract.numberConfig(inputInteger(form.east), inputInteger(form.south),
                inputInteger(form.west), inputInteger(form.north));
    }

    /** Uses the CURRENT form values at response time, as the original callback does. */
    public static Outcome applyNumberResponse(Form currentForm, SessionState session,
                                               ApiContract.Response response,
                                               String exceptionMessage) {
        Outcome result = evaluateResponse(Action.NUMBER, response, exceptionMessage);
        if (!result.accepted()) return result;
        for (Models.Channel channel : session.channels) {
            Integer direction = channel.device.direction();
            if (direction == null) continue;
            String value;
            switch (direction) {
                case 1: value = currentForm.east; break;
                case 2: value = currentForm.south; break;
                case 3: value = currentForm.west; break;
                case 4: value = currentForm.north; break;
                default: continue;
            }
            channel.device.fields.put("mj_count", inputInteger(value));
        }
        return result;
    }

    /** scanPage=true has extra validation; the settings page's manual form does not. */
    public static ApiContract.Request prepareWifiSave(Form form, boolean scanPage) {
        if (form.ssid == null || form.wifiPassword == null)
            throw new IllegalArgumentException("Controllers must contain Strings");
        if (scanPage && form.ssid.isEmpty()) throw new IllegalArgumentException("请选择WIFI！");
        if (scanPage && form.wifiPassword.isEmpty()) throw new IllegalArgumentException("请输入WIFI密码！");
        return ApiContract.wifi(form.ssid, form.wifiPassword);
    }

    public static void selectWifi(Form form, WifiItem item) {
        form.wifiPassword = "";
        form.ssid = item.ssid;
    }

    /** Distinguishes transport failure from the original success == false test. */
    public static Outcome evaluateResponse(Action action, ApiContract.Response response,
                                            String exceptionMessage) {
        if (response == null || !response.ok()) {
            boolean log = action == Action.NUMBER || action == Action.WIFI_MANUAL
                    || action == Action.RESTART;
            return new Outcome(Failure.NETWORK, exceptionMessage == null ? "" : exceptionMessage,
                    Navigation.NONE, log ? "red" : "", true);
        }
        Map<String, Object> body = response.object();
        if (Boolean.FALSE.equals(body.get("success"))) {
            boolean log = action == Action.NUMBER || action == Action.RESTART;
            return new Outcome(Failure.BUSINESS, Models.string(body.get("msg")),
                    Navigation.NONE, log ? "red" : "", true);
        }
        switch (action) {
            case PASSWORD:
                return new Outcome(Failure.NONE, "修改密码成功", Navigation.LOGIN_CLEAR_STACK, "", false);
            case NUMBER:
                return new Outcome(Failure.NONE, "配置方位数量成功", Navigation.NONE, "", false);
            case RESTART:
                return new Outcome(Failure.NONE, "重启所有设备成功", Navigation.POP, "black", true);
            default:
                return new Outcome(Failure.NONE, "保存成功", Navigation.NONE, "", false);
        }
    }

    /** Loading config retains manual WiFi text, matching _initFormData. */
    public static boolean applyConfig(Form form, ApiContract.Response response) {
        if (!ApiContract.businessAccepted(response)) return false;
        Map<String, Object> values = Models.read("OnlineConfig",
                JsonCodec.object(response.object().get("data"))).values;
        Map<String, Object> number = JsonCodec.object(values.get("config_number"));
        Map<String, Object> data = JsonCodec.object(values.get("data_config"));
        form.loadedConfig = values;
        form.east = Integer.toString(Models.intOr(number.get("east"), 26));
        form.south = Integer.toString(Models.intOr(number.get("south"), 26));
        form.west = Integer.toString(Models.intOr(number.get("west"), 26));
        form.north = Integer.toString(Models.intOr(number.get("north"), 26));
        form.timeout = Integer.toString(Models.intOr(data.get("timeout"), 60));
        form.delay = Integer.toString(Models.intOr(data.get("delay"), 5));
        form.dataSend = Models.intOr(data.get("data_send"), 1);
        form.countType = Models.intOr(data.get("count_type"), 1);
        form.uploadImageClarity = Models.intOr(data.get("upload_img_clarity"), 1);
        return true;
    }

    /** This endpoint casts success to bool; it does NOT use success != false. */
    public static boolean applyDefaultWifi(Form form, ApiContract.Response response) {
        if (response == null || !response.ok()) return false;
        Object success = response.object().get("success");
        if (!(success instanceof Boolean))
            throw new IllegalArgumentException("get_default_wifi.success must be bool");
        if (!((Boolean) success)) return false;
        Map<String, Object> wifi = JsonCodec.object(response.object().get("data"));
        form.ssid = primitiveDartString(wifi.get("ssid"));
        form.wifiPassword = primitiveDartString(wifi.get("pwd"));
        return true;
    }

    public static int mapChannelId(int originalId, boolean reverseChannels) {
        if (!reverseChannels) return originalId;
        return (originalId & 1) == 0 ? Math.subtractExact(originalId, 1)
                : Math.addExact(originalId, 1);
    }

    /**
     * Bounded host adapter. The original int.parse has additional formats and
     * 64-bit values. Non-decimal and out-of-host-range inputs fail explicitly;
     * they are not silently accepted with fabricated normalization.
     */
    public static int inputInteger(String text) {
        if (text == null) throw new IllegalArgumentException("Expected numeric controller String");
        String value = text.trim();
        if (!value.matches("[+-]?[0-9]+"))
            throw new IllegalArgumentException("重建限制：此输入仅支持十进制整数；原 int.parse 其他格式尚未移植");
        try { return Integer.parseInt(value); }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("重建限制：设置数值超出 Java int 范围", e);
        }
    }

    private static String primitiveDartString(Object value) {
        if (value == null) return "null";
        if (value instanceof String || value instanceof Boolean || Models.isInteger(value))
            return String.valueOf(value);
        throw new UnsupportedOperationException("原 Dart 动态 toString 的此输入类型尚未移植");
    }

    public interface Cancel { void cancel(); }
    public interface Scheduler { Cancel every(long periodMillis, Runnable task); }
    public interface Completion { void complete(ApiContract.Response response, String exceptionMessage); }
    /** Dispatcher adapts IO failures to the application's ordinary HttpResponse callback. */
    public interface Dispatcher { void send(ApiContract.Request request, Completion completion); }

    public static final class WifiPolling implements AutoCloseable {
        private final Scheduler scheduler;
        private final Dispatcher dispatcher;
        private final Completion onList;
        private Cancel listTimer, deviceTimer;
        private boolean started;
        public WifiPolling(Scheduler scheduler, Dispatcher dispatcher, Completion onList) {
            this.scheduler = scheduler;
            this.dispatcher = dispatcher;
            this.onList = onList;
        }
        public void start() {
            if (started) throw new IllegalStateException("Wifi page already initialized");
            started = true;
            deviceUp();
            deviceUp();
            listTimer = scheduler.every(3000, new Runnable() {
                @Override public void run() { getList(); }
            });
            deviceTimer = scheduler.every(15000, new Runnable() {
                @Override public void run() { deviceUp(); }
            });
        }
        public void deviceUp() {
            dispatcher.send(ApiContract.wifiDeviceUp(), new Completion() {
                @Override public void complete(ApiContract.Response response, String error) {
                    // Original callback does not test ok/success or mounted.
                    getList();
                }
            });
        }
        public void getList() { dispatcher.send(ApiContract.wifiList(), onList); }
        @Override public void close() {
            if (listTimer != null) listTimer.cancel();
            if (deviceTimer != null) deviceTimer.cancel();
            // Existing network callbacks are intentionally not reported cancelled.
        }
    }

    public static final class WifiItem {
        public final String ssid, score;
        public final int percent;
        public WifiItem(String ssid, String score) {
            this.ssid = ssid;
            this.score = score;
            String[] parts = score.split("/", -1);
            if (score.isEmpty() || parts.length < 2) { percent = 0; return; }
            double ratio = ((double) inputInteger(parts[0])) / inputInteger(parts[1]) * 100.0;
            if (Double.isNaN(ratio) || Double.isInfinite(ratio)
                    || ratio < Integer.MIN_VALUE || ratio > Integer.MAX_VALUE)
                throw new IllegalArgumentException("Unrepresentable WiFi score");
            percent = (int) ratio;
        }
    }

    /** Exact recovered callback, deliberately NOT advertised as a Java Comparator. */
    public static int originalWifiCompare(WifiItem first, WifiItem second) {
        return first.percent > second.percent ? 0 : 1;
    }

    public static final class WifiScan {
        public final List<WifiItem> inputOrderItems;
        public final boolean orderingRecovered;
        public final String limitation;
        private WifiScan(List<WifiItem> items) {
            inputOrderItems = Collections.unmodifiableList(new ArrayList<>(items));
            orderingRecovered = items.size() < 2;
            limitation = orderingRecovered ? "" :
                    "原排序回调返回 0/1，不满足 Java Comparator 契约；当前保留响应顺序，原排序结果尚未恢复";
        }
    }

    /**
     * Parses the two observed well-formed string schemas. Malformed records that
     * enter unresolved original catch/recovery paths are rejected explicitly.
     * A null return means transport failure leaves the current list unchanged.
     */
    public static WifiScan parseWifiResponse(ApiContract.Response response) {
        if (response == null || !response.ok()) return null;
        Object data = response.object().get("data");
        if (!(data instanceof String))
            throw new UnsupportedOperationException("WiFi data 的非字符串 toString 路径尚未完整恢复");
        return parseWifiData((String) data);
    }

    public static WifiScan parseWifiData(String data) {
        List<WifiItem> items = new ArrayList<>();
        if (data.isEmpty()) return new WifiScan(items);
        boolean quoted = data.indexOf('"') != -1;
        String[] records = data.split(quoted ? "\\|" : ",", -1);
        for (String record : records) {
            if (record.isEmpty()) continue;
            String[] fields = record.split(quoted ? "," : "\\|", -1);
            if (!quoted && fields.length == 1) continue;
            if (fields[0].isEmpty() || fields[0].length() == 2) continue;
            if (fields.length < 2)
                throw new UnsupportedOperationException("WiFi 缺字段异常恢复路径尚未完整恢复");
            if (fields[1].isEmpty()) continue;
            try {
                String ssid, score;
                if (quoted) {
                    ssid = fields[0].replace("\"", "");
                    score = fields[1].split("Signallevel", -1)[0];
                } else {
                    ssid = fields[1].replace("\"", "");
                    double dbm = Double.parseDouble(fields[0].split("dBm", -1)[0]);
                    if (!Double.isFinite(dbm))
                        throw new IllegalArgumentException("Non-finite dBm outside checked subset");
                    score = dbm > -45 ? "5/5" : dbm > -55 ? "4/5"
                            : dbm > -70 ? "3/5" : dbm > -80 ? "2/5" : "1/5";
                }
                if (ssid.startsWith("\\x")) {
                    int end = ssid.lastIndexOf("\\x") + 4;
                    ssid = escapedHexToUtf8(ssid.substring(0, end)) + ssid.substring(end);
                }
                items.add(new WifiItem(ssid, score));
            } catch (RuntimeException error) {
                throw new UnsupportedOperationException(
                        "此 WiFi 记录进入未完成的原异常恢复路径；拒绝伪造解析结果", error);
            }
        }
        return new WifiScan(items);
    }

    public static String escapedHexToUtf8(String input) {
        String hex = input.replace("\\x", "");
        if ((hex.length() & 1) != 0) throw new IllegalArgumentException("Odd hexadecimal length");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (int i = 0; i < hex.length(); i += 2)
            bytes.write(Integer.parseInt(hex.substring(i, i + 2), 16));
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("Malformed UTF-8", error);
        }
    }
}
