package org.ourcamellia.common.protocol;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Typed payload records for every wire message. All construction happens through
 * {@link Wire} builders, which validate; direct record construction assumes already
 * validated values.
 */
public final class WireMessages {

    private WireMessages() {}

    // ---- handshake / auth ----
    public record Hello(String client, String version) {}
    public record Welcome(String serverName, String channelId, int unreadNotifications,
                          String registrationPolicy, String groupPolicyNote, long serverTime) {}
    public record Login(String username, String password) {}
    public record Register(String username, String password, String ticketId, Map<String, String> fields) {}
    public record RegisterResult(String status, String ticketId, String message) {} // approved|pending|rejected
    public record AuthOk(String username, boolean bot, int unread, String displayName) {}

    // ---- friendship ----
    public record FriendRequest(String requestId, String from, String to) {}
    public record FriendReply(String requestId, String from, String to, boolean accept) {}
    public record FriendState(String requestId, String from, String to, String state) {}

    // ---- messaging ----
    public record Message(String msgId, String sender, String to, String text, long ts) {}
    public record Delivery(String msgId, String to, String status) {} // delivered|failed
    public record GroupMessage(String msgId, String groupId, String sender, long ts,
                               String text, String box) {}           // text XOR box
    public record GroupKeyWrap(String groupId, String forUser, String box, long generation,
                               String from, String fromPub) {}
    public record ChannelMessage(String msgId, String channelId, String text, long ts) {}
    public record ModDelete(String groupId, String msgId, String operator) {}

    // ---- groups ----
    public record GroupCreate(String groupId, String name, String privacy, List<String> members) {}
    public record GroupInfo(String id, String name, String privacy, String owner,
                            List<String> members, Map<String, String> pubKeys, long createdAt) {

        public com.fasterxml.jackson.databind.JsonNode toJson() {
            var o = org.ourcamellia.common.Json.object();
            o.put("id", id);
            o.put("name", name);
            o.put("privacy", privacy);
            o.put("owner", owner);
            var arr = o.putArray("members");
            members.forEach(arr::add);
            if (pubKeys != null && !pubKeys.isEmpty()) {
                var keys = o.putObject("pubKeys");
                pubKeys.forEach(keys::put);
            }
            o.put("createdAt", createdAt);
            return o;
        }

        public static GroupInfo fromJson(com.fasterxml.jackson.databind.JsonNode o) {
            String privacy = org.ourcamellia.common.Json.reqStr(o, "privacy", 24);
            if (!privacy.equals("operator-visible") && !privacy.equals("encrypted")) {
                throw new org.ourcamellia.common.Errors.Malformed("invalid group privacy");
            }
            com.fasterxml.jackson.databind.JsonNode members = o.get("members");
            List<String> list = new java.util.ArrayList<>();
            if (members != null) {
                if (!members.isArray() || members.size() > 256) {
                    throw new org.ourcamellia.common.Errors.Malformed("invalid member list");
                }
                for (com.fasterxml.jackson.databind.JsonNode m : members) {
                    if (!m.isTextual()) {
                        throw new org.ourcamellia.common.Errors.Malformed("invalid member");
                    }
                    list.add(org.ourcamellia.common.Text.requireCleanText(m.asText(), "member", 64));
                }
            }
            Map<String, String> pubKeys = new java.util.LinkedHashMap<>();
            com.fasterxml.jackson.databind.JsonNode keys = o.get("pubKeys");
            if (keys != null) {
                if (!keys.isObject() || keys.size() > 256) {
                    throw new org.ourcamellia.common.Errors.Malformed("invalid pubKeys");
                }
                keys.fields().forEachRemaining(entry -> {
                    if (!entry.getValue().isTextual() || entry.getValue().asText().length() > 256) {
                        throw new org.ourcamellia.common.Errors.Malformed("invalid pubKey");
                    }
                    pubKeys.put(entry.getKey(), entry.getValue().asText());
                });
            }
            return new GroupInfo(
                    org.ourcamellia.common.Ids.requireId(org.ourcamellia.common.Json.reqStr(o, "id", 64), "group id"),
                    org.ourcamellia.common.Text.requireGroupName(org.ourcamellia.common.Json.reqStr(o, "name", 64)),
                    privacy,
                    org.ourcamellia.common.Text.requireCleanText(org.ourcamellia.common.Json.reqStr(o, "owner", 65), "owner", 64),
                    list,
                    pubKeys,
                    org.ourcamellia.common.Json.reqLong(o, "createdAt"));
        }
    }
    public record GroupMemberOp(String groupId, String member) {}   // invite / remove / transfer(newOwner=member)
    public record GroupOp(String groupId) {}                        // leave / members-query
    public record GroupUpdate(GroupInfo group) {}

    // ---- notifications ----
    public record NotifyList(List<NotificationDto> items) {}
    public record NotificationDto(String id, String kind, String state, String from,
                                  String text, long createdAt, long expiresAt, String refId) {}
    public record NotifyPush(NotificationDto item) {}
    public record NotifyAction(String notifId, String action) {}    // pass|reject|over
    public record NotifyState(String notifId, String state) {}

    // ---- presence / misc ----
    public record PeerState(String user, String status) {}          // connected|disconnected
    public record FriendEntry(String name, String status, boolean bot) {}
    public record FriendsList(List<FriendEntry> friends) {}
    public record Profile(String username, boolean bot, String status) {}
    public record Ping(long ts) {}
    public record Bye() {}

    // ---- local discovery (UDP, not framed over TCP) ----
    public record DiscoverQuery(String id) {}
    public record DiscoverReply(String id, String username, int tcpPort, String fp, long expiresAt) {}
}
