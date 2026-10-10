package org.ourcamellia.core.app;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.Wire;
import org.ourcamellia.core.transport.Conn;

/**
 * Client-side handling of every server protocol frame after login: friends,
 * private messages, groups (incl. encrypted-group key wraps), notifications, and
 * the announcement channel. Received content is never parsed as commands.
 */
final class ServerProtocol {

    private ServerProtocol() {}

    static void handle(ServerSession s, Conn conn, Envelope envelope) {
        switch (envelope.type()) {
            case Wire.T_WELCOME -> {
                var w = Wire.parseWelcome(envelope);
                s.setWelcome(w.serverName(), w.channelId(), w.unreadNotifications(),
                        w.registrationPolicy(), w.groupPolicyNote());
            }
            case Wire.T_REGISTER_RESULT -> {
                var r = Wire.parseRegisterResult(envelope);
                s.onRegisterResult(r.status(), r.ticketId(), r.message());
            }
            case Wire.T_AUTH_OK -> {
                var a = Wire.parseAuthOk(envelope);
                s.setLoggedIn(a.username(), a.bot(), a.unread());
            }
            case Wire.T_NOTIFY_LIST -> {
                var list = Wire.parseNotifyList(envelope);
                s.onNotifications(list.items());
            }
            case Wire.T_NOTIFY_PUSH -> {
                var push = Wire.parseNotifyPush(envelope);
                s.onNotification(push.item());
            }
            case Wire.T_NOTIFY_STATE -> {
                var state = Wire.parseNotifyState(envelope);
                s.onNotificationState(state.notifId(), state.state());
            }
            case Wire.T_FRIENDS_LIST -> {
                var friends = Wire.parseFriendsList(envelope);
                s.onFriendsList(friends.friends());
            }
            case Wire.T_PEER_STATE -> {
                var ps = Wire.parsePeerState(envelope);
                s.onPeerState(ps.user(), ps.status());
            }
            case Wire.T_FRIEND_STATE -> {
                var fs = Wire.parseFriendState(envelope);
                s.onFriendState(fs);
            }
            case Wire.T_MESSAGE -> {
                var m = Wire.parseMessage(envelope);
                s.onPrivateMessage(m);
            }
            case Wire.T_DELIVERY -> {
                var d = Wire.parseDelivery(envelope);
                s.events().onInfo("delivery to " + d.to() + ": " + d.status());
            }
            case Wire.T_GROUP_UPDATE -> {
                var u = Wire.parseGroupUpdate(envelope);
                s.onGroupUpdate(u.group());
            }
            case Wire.T_GROUP_MESSAGE -> {
                var m = Wire.parseGroupMessage(envelope);
                s.onGroupMessage(m);
            }
            case Wire.T_GROUP_KEY_WRAP -> {
                var w = Wire.parseGroupKeyWrap(envelope);
                s.onGroupKeyWrap(w);
            }
            case Wire.T_CHANNEL_MESSAGE -> {
                var m = Wire.parseChannelMessage(envelope);
                s.onChannelMessage(m);
            }
            case Wire.T_MOD_DELETE -> {
                var d = Wire.parseModDelete(envelope);
                s.events().onInfo("operator removed a message from group "
                        + d.groupId() + " (msg " + d.msgId() + ")");
            }
            case Wire.T_ERROR -> s.events().onInfo(
                    "server reported: " + envelope.body().path("message").asText("error"));
            case Wire.T_ACK -> { /* server acknowledgements need no client action */ }
            default -> conn.send(Wire.error(envelope.id(), Errors.Category.USAGE, "unsupported frame type"));
        }
    }
}
