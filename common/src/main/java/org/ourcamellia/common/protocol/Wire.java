package org.ourcamellia.common.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.Json;
import org.ourcamellia.common.Text;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Wire codecs: type-name constants, validated builders, and validated parsers for
 * every protocol message. Every field crossing the wire is length- and content-checked
 * here; nothing parsed from a peer is trusted beyond these checks.
 */
public final class Wire {

    private Wire() {}

    public static final String T_HELLO = "hello";
    public static final String T_WELCOME = "welcome";
    public static final String T_LOGIN = "login";
    public static final String T_REGISTER = "register";
    public static final String T_REGISTER_RESULT = "register-result";
    public static final String T_AUTH_OK = "auth-ok";
    public static final String T_FRIEND_REQUEST = "friend-request";
    public static final String T_FRIEND_REPLY = "friend-reply";
    public static final String T_FRIEND_STATE = "friend-state";
    public static final String T_MESSAGE = "message";
    public static final String T_DELIVERY = "delivery";
    public static final String T_GROUP_CREATE = "group-create";
    public static final String T_GROUP_INVITE = "group-invite";
    public static final String T_GROUP_REMOVE = "group-remove";
    public static final String T_GROUP_LEAVE = "group-leave";
    public static final String T_GROUP_TRANSFER = "group-transfer";
    public static final String T_GROUP_MEMBERS = "group-members";
    public static final String T_GROUP_MESSAGE = "group-message";
    public static final String T_GROUP_KEY_WRAP = "group-key-wrap";
    public static final String T_GROUP_UPDATE = "group-update";
    public static final String T_CHANNEL_MESSAGE = "channel-message";
    public static final String T_MOD_DELETE = "mod-delete";
    public static final String T_NOTIFY_LIST = "notify-list";
    public static final String T_NOTIFY_PUSH = "notify-push";
    public static final String T_NOTIFY_ACTION = "notify-action";
    public static final String T_NOTIFY_STATE = "notify-state";
    public static final String T_FRIENDS_LIST = "friends-list";
    public static final String T_PROFILE = "profile";
    public static final String T_PEER_STATE = "peer-state";
    public static final String T_PING = "ping";
    public static final String T_PONG = "pong";
    public static final String T_BYE = "bye";
    public static final String T_ERROR = "error";
    public static final String T_ACK = "ack";
    public static final String T_DISCOVER_QUERY = "discover-query";
    public static final String T_DISCOVER_REPLY = "discover-reply";

    private static final int MAX_TEXT = Text.MAX_MESSAGE;
    private static final int MAX_NAME = Text.MAX_NAME;

    // ---------- builders ----------

    public static Envelope hello(String client, String version) {
        var b = Json.object();
        b.put("client", client);
        b.put("version", version);
        return Envelope.make(T_HELLO, b, null);
    }

    public static Envelope welcome(String serverName, String channelId, int unread,
                                   String registrationPolicy, String groupPolicyNote) {
        var b = Json.object();
        b.put("serverName", serverName);
        b.put("channelId", channelId);
        b.put("unreadNotifications", unread);
        b.put("registrationPolicy", registrationPolicy);
        b.put("groupPolicyNote", groupPolicyNote);
        b.put("serverTime", System.currentTimeMillis());
        return Envelope.make(T_WELCOME, b, null);
    }

    public static Envelope login(String username, String password) {
        var b = Json.object();
        b.put("username", username);
        b.put("password", password);
        return Envelope.make(T_LOGIN, b, null);
    }

    public static Envelope register(String username, String password, String ticketId,
                                    Map<String, String> fields, String x25519PublicKey) {
        var b = Json.object();
        b.put("username", username);
        b.put("password", password);
        b.put("ticketId", ticketId == null ? Ids.newId() : ticketId);
        if (x25519PublicKey != null) {
            b.put("x25519PublicKey", x25519PublicKey);
        }
        var f = Json.object();
        fields.forEach(f::put);
        b.set("fields", f);
        return Envelope.make(T_REGISTER, b, null);
    }

    public static Envelope registerResult(String status, String ticketId, String message) {
        var b = Json.object();
        b.put("status", status);
        b.put("ticketId", ticketId);
        b.put("message", message == null ? "" : message);
        return Envelope.make(T_REGISTER_RESULT, b, null);
    }

    public static Envelope authOk(String username, boolean bot, int unread, String displayName) {
        var b = Json.object();
        b.put("username", username);
        b.put("bot", bot);
        b.put("unread", unread);
        b.put("displayName", displayName);
        return Envelope.make(T_AUTH_OK, b, null);
    }

    public static Envelope friendRequest(String requestId, String from, String to) {
        var b = Json.object();
        b.put("requestId", requestId);
        b.put("from", from);
        b.put("to", to);
        return Envelope.make(T_FRIEND_REQUEST, b, null);
    }

    public static Envelope friendReply(String requestId, String from, String to, boolean accept) {
        var b = Json.object();
        b.put("requestId", requestId);
        b.put("from", from);
        b.put("to", to);
        b.put("accept", accept);
        return Envelope.make(T_FRIEND_REPLY, b, null);
    }

    public static Envelope friendState(String requestId, String from, String to, String state) {
        var b = Json.object();
        b.put("requestId", requestId);
        b.put("from", from);
        b.put("to", to);
        b.put("state", state);
        return Envelope.make(T_FRIEND_STATE, b, null);
    }

    public static Envelope message(String msgId, String sender, String to, String text) {
        return message(msgId, sender, to, text, System.currentTimeMillis());
    }

    public static Envelope message(String msgId, String sender, String to, String text, long ts) {
        var b = Json.object();
        b.put("msgId", msgId);
        b.put("sender", sender);
        b.put("to", to);
        b.put("text", text);
        b.put("ts", ts);
        return Envelope.make(T_MESSAGE, b, null);
    }

    public static Envelope delivery(String msgId, String to, String status) {
        var b = Json.object();
        b.put("msgId", msgId);
        b.put("to", to);
        b.put("status", status);
        return Envelope.make(T_DELIVERY, b, null);
    }

    public static Envelope groupCreate(String groupId, String name, String privacy, List<String> members) {
        var b = Json.object();
        b.put("groupId", groupId);
        b.put("name", name);
        b.put("privacy", privacy);
        var arr = b.putArray("members");
        members.forEach(arr::add);
        return Envelope.make(T_GROUP_CREATE, b, null);
    }

    public static Envelope groupMemberOp(String type, String groupId, String member) {
        var b = Json.object();
        b.put("groupId", groupId);
        b.put("member", member);
        return Envelope.make(type, b, null);
    }

    public static Envelope groupOp(String type, String groupId) {
        var b = Json.object();
        b.put("groupId", groupId);
        return Envelope.make(type, b, null);
    }

    public static Envelope groupMessage(String msgId, String groupId, String sender, String text, String box) {
        var b = Json.object();
        b.put("msgId", msgId);
        b.put("groupId", groupId);
        b.put("sender", sender);
        b.put("ts", System.currentTimeMillis());
        if (text != null) {
            b.put("text", text);
        }
        if (box != null) {
            b.put("box", box);
        }
        return Envelope.make(T_GROUP_MESSAGE, b, null);
    }

    public static Envelope groupKeyWrap(String groupId, String forUser, String box, long generation,
                                        String from, String fromPub) {
        var b = Json.object();
        b.put("groupId", groupId);
        b.put("forUser", forUser);
        b.put("box", box);
        b.put("generation", generation);
        if (from != null) {
            b.put("from", from);
        }
        if (fromPub != null) {
            b.put("fromPub", fromPub);
        }
        return Envelope.make(T_GROUP_KEY_WRAP, b, null);
    }

    public static Envelope groupUpdate(WireMessages.GroupInfo group) {
        var b = Json.object();
        b.set("group", group.toJson());
        return Envelope.make(T_GROUP_UPDATE, b, null);
    }

    public static Envelope channelMessage(String msgId, String channelId, String text) {
        var b = Json.object();
        b.put("msgId", msgId);
        b.put("channelId", channelId);
        b.put("text", text);
        b.put("ts", System.currentTimeMillis());
        return Envelope.make(T_CHANNEL_MESSAGE, b, null);
    }

    public static Envelope modDelete(String groupId, String msgId, String operator) {
        var b = Json.object();
        b.put("groupId", groupId);
        b.put("msgId", msgId);
        b.put("operator", operator);
        return Envelope.make(T_MOD_DELETE, b, null);
    }

    public static Envelope notifyList(List<WireMessages.NotificationDto> items) {
        var b = Json.object();
        var arr = b.putArray("items");
        for (var item : items) {
            arr.add(notificationToJson(item));
        }
        return Envelope.make(T_NOTIFY_LIST, b, null);
    }

    public static Envelope notifyPush(WireMessages.NotificationDto item) {
        var b = Json.object();
        b.set("item", notificationToJson(item));
        return Envelope.make(T_NOTIFY_PUSH, b, null);
    }

    public static Envelope notifyAction(String notifId, String action) {
        var b = Json.object();
        b.put("notifId", notifId);
        b.put("action", action);
        return Envelope.make(T_NOTIFY_ACTION, b, null);
    }

    public static Envelope notifyState(String notifId, String state) {
        var b = Json.object();
        b.put("notifId", notifId);
        b.put("state", state);
        return Envelope.make(T_NOTIFY_STATE, b, null);
    }

    public static Envelope friendsList(List<WireMessages.FriendEntry> friends) {
        var b = Json.object();
        var arr = b.putArray("friends");
        for (var f : friends) {
            var o = arr.addObject();
            o.put("name", f.name());
            o.put("status", f.status());
            o.put("bot", f.bot());
        }
        return Envelope.make(T_FRIENDS_LIST, b, null);
    }

    public static Envelope profile(String username, boolean bot, String status) {
        var b = Json.object();
        b.put("username", username);
        b.put("bot", bot);
        b.put("status", status);
        return Envelope.make(T_PROFILE, b, null);
    }

    public static Envelope peerState(String user, String status) {
        var b = Json.object();
        b.put("user", user);
        b.put("status", status);
        return Envelope.make(T_PEER_STATE, b, null);
    }

    public static Envelope ping() {
        return Envelope.make(T_PING, Json.object(), null);
    }

    public static Envelope pong(String ref) {
        return Envelope.make(T_PONG, Json.object(), ref);
    }

    public static Envelope bye() {
        return Envelope.make(T_BYE, Json.object(), null);
    }

    public static Envelope error(String ref, Errors.Category category, String message) {
        var b = Json.object();
        b.put("category", category.name().toLowerCase());
        b.put("message", message == null ? "" : Text.requireCleanText(message, "error", 512));
        return Envelope.make(T_ERROR, b, ref);
    }

    public static Envelope ack(String ref, String status) {
        var b = Json.object();
        b.put("status", status);
        return Envelope.make(T_ACK, b, ref);
    }

    public static JsonNode discoverQuery(String id) {
        var b = Json.object();
        b.put("v", Envelope.PROTOCOL_VERSION);
        b.put("id", id);
        b.put("type", T_DISCOVER_QUERY);
        return b;
    }

    public static JsonNode discoverReply(String id, String username, int tcpPort, String fp, long expiresAt) {
        var b = Json.object();
        b.put("v", Envelope.PROTOCOL_VERSION);
        b.put("id", id);
        b.put("type", T_DISCOVER_REPLY);
        b.put("username", username);
        b.put("tcpPort", tcpPort);
        b.put("fp", fp);
        b.put("expiresAt", expiresAt);
        return b;
    }

    private static JsonNode notificationToJson(WireMessages.NotificationDto n) {
        var o = Json.object();
        o.put("id", n.id());
        o.put("kind", n.kind());
        o.put("state", n.state());
        o.put("from", n.from());
        o.put("text", n.text());
        o.put("createdAt", n.createdAt());
        o.put("expiresAt", n.expiresAt());
        if (n.refId() != null) {
            o.put("refId", n.refId());
        }
        return o;
    }

    // ---------- parsers ----------

    public static WireMessages.Hello parseHello(Envelope e) {
        return new WireMessages.Hello(
                Json.reqStr(e.body(), "client", 32),
                Json.reqStr(e.body(), "version", 16));
    }

    public static WireMessages.Welcome parseWelcome(Envelope e) {
        var b = e.body();
        return new WireMessages.Welcome(
                Json.reqStr(b, "serverName", 128),
                Json.reqStr(b, "channelId", 64),
                (int) Json.reqLong(b, "unreadNotifications"),
                Json.reqStr(b, "registrationPolicy", 16),
                Json.reqStr(b, "groupPolicyNote", 256),
                Json.reqLong(b, "serverTime"));
    }

    public static WireMessages.Login parseLogin(Envelope e) {
        var b = e.body();
        String username = Json.reqStr(b, "username", 65);
        String password = Json.reqStr(b, "password", 256);
        return new WireMessages.Login(Text.requireServerName(username), password);
    }

    public static WireMessages.Register parseRegister(Envelope e) {
        var b = e.body();
        String username = Text.requireServerName(Json.reqStr(b, "username", 65));
        String password = Json.reqStr(b, "password", 256);
        String ticketId = Json.optStr(b, "ticketId", 64);
        JsonNode fieldsNode = b.get("fields");
        Map<String, String> fields = new LinkedHashMap<>();
        if (fieldsNode != null && !fieldsNode.isNull()) {
            if (!fieldsNode.isObject()) {
                throw new Errors.Malformed("fields must be an object");
            }
            fieldsNode.fields().forEachRemaining(entry -> {
                if (!entry.getValue().isTextual() || entry.getValue().asText().length() > 512) {
                    throw new Errors.Malformed("invalid registration field");
                }
                fields.put(entry.getKey(), entry.getValue().asText());
            });
        }
        return new WireMessages.Register(username, password, ticketId, fields);
    }

    /** Reads the optional base64 X25519 public key from a register frame. */
    public static String parseRegisterPublicKey(Envelope e) {
        String pk = Json.optStr(e.body(), "x25519PublicKey", 256);
        if (pk != null && !pk.isEmpty()) {
            try {
                java.util.Base64.getDecoder().decode(pk);
            } catch (IllegalArgumentException ex) {
                throw new Errors.Malformed("invalid x25519 public key");
            }
        }
        return pk;
    }

    public static WireMessages.RegisterResult parseRegisterResult(Envelope e) {
        var b = e.body();
        String status = Json.reqStr(b, "status", 16);
        if (!status.equals("approved") && !status.equals("pending") && !status.equals("rejected")) {
            throw new Errors.Malformed("invalid register result status");
        }
        return new WireMessages.RegisterResult(status, Json.optStr(b, "ticketId", 64), Json.optStr(b, "message", 256));
    }

    public static WireMessages.AuthOk parseAuthOk(Envelope e) {
        var b = e.body();
        return new WireMessages.AuthOk(
                Json.reqStr(b, "username", 65),
                Json.optBool(b, "bot", false),
                (int) Json.reqLong(b, "unread"),
                Json.reqStr(b, "displayName", 128));
    }

    public static WireMessages.FriendRequest parseFriendRequest(Envelope e) {
        var b = e.body();
        return new WireMessages.FriendRequest(
                Ids.requireId(Json.reqStr(b, "requestId", 64), "request id"),
                Text.requireCleanText(Json.reqStr(b, "from", 65), "name", MAX_NAME),
                Text.requireCleanText(Json.reqStr(b, "to", 65), "name", MAX_NAME));
    }

    public static WireMessages.FriendReply parseFriendReply(Envelope e) {
        var b = e.body();
        return new WireMessages.FriendReply(
                Ids.requireId(Json.reqStr(b, "requestId", 64), "request id"),
                Text.requireCleanText(Json.reqStr(b, "from", 65), "name", MAX_NAME),
                Text.requireCleanText(Json.reqStr(b, "to", 65), "name", MAX_NAME),
                Json.optBool(b, "accept", false));
    }

    public static WireMessages.FriendState parseFriendState(Envelope e) {
        var b = e.body();
        String state = Json.reqStr(b, "state", 16);
        if (!List.of("accepted", "rejected", "pending", "expired", "undeliverable").contains(state)) {
            throw new Errors.Malformed("invalid friend state");
        }
        return new WireMessages.FriendState(
                Ids.requireId(Json.reqStr(b, "requestId", 64), "request id"),
                Text.requireCleanText(Json.reqStr(b, "from", 65), "name", MAX_NAME),
                Text.requireCleanText(Json.reqStr(b, "to", 65), "name", MAX_NAME),
                state);
    }

    public static WireMessages.Message parseMessage(Envelope e) {
        var b = e.body();
        return new WireMessages.Message(
                Ids.requireId(Json.reqStr(b, "msgId", 64), "message id"),
                Text.requireCleanText(Json.reqStr(b, "sender", 65), "name", MAX_NAME),
                Text.requireCleanText(Json.reqStr(b, "to", 65), "name", MAX_NAME),
                Text.requireCleanText(Json.reqStr(b, "text", MAX_TEXT), "message", MAX_TEXT),
                Json.reqLong(b, "ts"));
    }

    public static WireMessages.Delivery parseDelivery(Envelope e) {
        var b = e.body();
        String status = Json.reqStr(b, "status", 16);
        if (!status.equals("delivered") && !status.equals("failed")) {
            throw new Errors.Malformed("invalid delivery status");
        }
        return new WireMessages.Delivery(
                Ids.requireId(Json.reqStr(b, "msgId", 64), "message id"),
                Text.requireCleanText(Json.reqStr(b, "to", 65), "name", MAX_NAME),
                status);
    }

    public static WireMessages.GroupCreate parseGroupCreate(Envelope e) {
        var b = e.body();
        String privacy = Json.reqStr(b, "privacy", 24);
        if (!privacy.equals("operator-visible") && !privacy.equals("encrypted")) {
            throw new Errors.Malformed("invalid group privacy");
        }
        JsonNode members = b.get("members");
        List<String> list = new ArrayList<>();
        if (members != null) {
            if (!members.isArray() || members.size() > 256) {
                throw new Errors.Malformed("invalid member list");
            }
            for (JsonNode m : members) {
                if (!m.isTextual()) {
                    throw new Errors.Malformed("invalid member");
                }
                list.add(Text.requireCleanText(m.asText(), "member", MAX_NAME));
            }
        }
        return new WireMessages.GroupCreate(
                Ids.requireId(Json.reqStr(b, "groupId", 64), "group id"),
                Text.requireGroupName(Json.reqStr(b, "name", 64)),
                privacy,
                list);
    }

    public static WireMessages.GroupMemberOp parseGroupMemberOp(Envelope e) {
        var b = e.body();
        return new WireMessages.GroupMemberOp(
                Ids.requireId(Json.reqStr(b, "groupId", 64), "group id"),
                Text.requireCleanText(Json.reqStr(b, "member", 65), "member", MAX_NAME));
    }

    public static WireMessages.GroupOp parseGroupOp(Envelope e) {
        return new WireMessages.GroupOp(Ids.requireId(Json.reqStr(e.body(), "groupId", 64), "group id"));
    }

    public static WireMessages.GroupMessage parseGroupMessage(Envelope e) {
        var b = e.body();
        String text = Json.optStr(b, "text", MAX_TEXT);
        String box = Json.optStr(b, "box", MAX_TEXT * 2);
        if ((text == null) == (box == null)) {
            throw new Errors.Malformed("group message needs exactly one of text/box");
        }
        return new WireMessages.GroupMessage(
                Ids.requireId(Json.reqStr(b, "msgId", 64), "message id"),
                Ids.requireId(Json.reqStr(b, "groupId", 64), "group id"),
                Text.requireCleanText(Json.reqStr(b, "sender", 65), "name", MAX_NAME),
                Json.reqLong(b, "ts"),
                text,
                box);
    }

    public static WireMessages.GroupKeyWrap parseGroupKeyWrap(Envelope e) {
        var b = e.body();
        return new WireMessages.GroupKeyWrap(
                Ids.requireId(Json.reqStr(b, "groupId", 64), "group id"),
                Text.requireCleanText(Json.reqStr(b, "forUser", 65), "name", MAX_NAME),
                Json.reqStr(b, "box", MAX_TEXT * 2),
                Json.reqLong(b, "generation"),
                Json.optStr(b, "from", 65),
                Json.optStr(b, "fromPub", 256));
    }

    public static WireMessages.GroupUpdate parseGroupUpdate(Envelope e) {
        return new WireMessages.GroupUpdate(WireMessages.GroupInfo.fromJson(Json.reqNode(e.body(), "group")));
    }

    public static WireMessages.ChannelMessage parseChannelMessage(Envelope e) {
        var b = e.body();
        return new WireMessages.ChannelMessage(
                Ids.requireId(Json.reqStr(b, "msgId", 64), "message id"),
                Ids.requireId(Json.reqStr(b, "channelId", 64), "channel id"),
                Text.requireCleanText(Json.reqStr(b, "text", MAX_TEXT), "announcement", MAX_TEXT),
                Json.reqLong(b, "ts"));
    }

    public static WireMessages.ModDelete parseModDelete(Envelope e) {
        var b = e.body();
        return new WireMessages.ModDelete(
                Ids.requireId(Json.reqStr(b, "groupId", 64), "group id"),
                Ids.requireId(Json.reqStr(b, "msgId", 64), "message id"),
                Text.requireCleanText(Json.reqStr(b, "operator", 65), "operator", MAX_NAME));
    }

    public static WireMessages.NotificationDto parseNotification(JsonNode o) {
        String kind = Json.reqStr(o, "kind", 16);
        if (!List.of("friend-request", "announcement", "info").contains(kind)) {
            throw new Errors.Malformed("invalid notification kind");
        }
        String state = Json.reqStr(o, "state", 16);
        if (!List.of("unread", "read", "acted", "dismissed", "expired").contains(state)) {
            throw new Errors.Malformed("invalid notification state");
        }
        return new WireMessages.NotificationDto(
                Ids.requireId(Json.reqStr(o, "id", 64), "notification id"),
                kind,
                state,
                Json.optStr(o, "from", 128),
                Json.optStr(o, "text", 1024),
                Json.reqLong(o, "createdAt"),
                Json.reqLong(o, "expiresAt"),
                Json.optStr(o, "refId", 64));
    }

    public static WireMessages.NotifyList parseNotifyList(Envelope e) {
        JsonNode items = e.body().get("items");
        List<WireMessages.NotificationDto> list = new ArrayList<>();
        if (items != null) {
            if (!items.isArray() || items.size() > 512) {
                throw new Errors.Malformed("invalid notification list");
            }
            for (JsonNode item : items) {
                list.add(parseNotification(item));
            }
        }
        return new WireMessages.NotifyList(list);
    }

    public static WireMessages.NotifyPush parseNotifyPush(Envelope e) {
        return new WireMessages.NotifyPush(parseNotification(Json.reqNode(e.body(), "item")));
    }

    public static WireMessages.NotifyAction parseNotifyAction(Envelope e) {
        var b = e.body();
        String action = Json.reqStr(b, "action", 16);
        if (!action.equals("pass") && !action.equals("reject") && !action.equals("over")) {
            throw new Errors.Malformed("invalid notification action");
        }
        return new WireMessages.NotifyAction(
                Ids.requireId(Json.reqStr(b, "notifId", 64), "notification id"),
                action);
    }

    public static WireMessages.NotifyState parseNotifyState(Envelope e) {
        var b = e.body();
        String state = Json.reqStr(b, "state", 16);
        if (!List.of("unread", "read", "acted", "dismissed", "expired").contains(state)) {
            throw new Errors.Malformed("invalid notification state");
        }
        return new WireMessages.NotifyState(
                Ids.requireId(Json.reqStr(b, "notifId", 64), "notification id"),
                state);
    }

    public static WireMessages.FriendsList parseFriendsList(Envelope e) {
        JsonNode friends = e.body().get("friends");
        List<WireMessages.FriendEntry> list = new ArrayList<>();
        if (friends != null) {
            if (!friends.isArray() || friends.size() > 4096) {
                throw new Errors.Malformed("invalid friend list");
            }
            for (JsonNode f : friends) {
                String name = Text.requireCleanText(Json.reqStr(f, "name", 65), "name", MAX_NAME);
                String status = Json.reqStr(f, "status", 16);
                if (!status.equals("connected") && !status.equals("disconnected")) {
                    throw new Errors.Malformed("invalid peer status");
                }
                list.add(new WireMessages.FriendEntry(name, status, Json.optBool(f, "bot", false)));
            }
        }
        return new WireMessages.FriendsList(list);
    }

    public static WireMessages.Profile parseProfile(Envelope e) {
        var b = e.body();
        return new WireMessages.Profile(
                Json.reqStr(b, "username", 65),
                Json.optBool(b, "bot", false),
                Json.reqStr(b, "status", 16));
    }

    public static WireMessages.PeerState parsePeerState(Envelope e) {
        var b = e.body();
        String status = Json.reqStr(b, "status", 16);
        if (!status.equals("connected") && !status.equals("disconnected")) {
            throw new Errors.Malformed("invalid peer status");
        }
        return new WireMessages.PeerState(
                Text.requireCleanText(Json.reqStr(b, "user", 65), "name", MAX_NAME),
                status);
    }

    public static WireMessages.DiscoverQuery parseDiscoverQuery(JsonNode root) {
        if (root.get("v") == null || root.get("v").asInt() != Envelope.PROTOCOL_VERSION) {
            throw new Errors.Malformed("discovery protocol version mismatch");
        }
        return new WireMessages.DiscoverQuery(Ids.requireId(Json.reqStr(root, "id", 64), "query id"));
    }

    public static WireMessages.DiscoverReply parseDiscoverReply(JsonNode root) {
        if (root.get("v") == null || root.get("v").asInt() != Envelope.PROTOCOL_VERSION) {
            throw new Errors.Malformed("discovery protocol version mismatch");
        }
        String fp = Json.reqStr(root, "fp", 128);
        if (!fp.matches("[0-9a-f]{64}")) {
            throw new Errors.Malformed("invalid fingerprint in discovery reply");
        }
        int port = (int) Json.reqLong(root, "tcpPort");
        if (port < 1 || port > 65535) {
            throw new Errors.Malformed("invalid port in discovery reply");
        }
        return new WireMessages.DiscoverReply(
                Ids.requireId(Json.reqStr(root, "id", 64), "query id"),
                Text.requireLocalName(Json.reqStr(root, "username", 64)),
                port,
                fp,
                Json.reqLong(root, "expiresAt"));
    }
}
