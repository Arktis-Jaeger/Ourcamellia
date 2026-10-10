package org.ourcamellia.common.domain;

/** Reference to a conversation as shown in the level-2 list. */
public record ConversationRef(
        Kind kind,
        String id,       // peer key ("@alice" / "bob") for PRIVATE; group id for GROUP; channel id for CHANNEL
        String title,
        GroupPrivacy privacy,
        boolean pinned) {

    public enum Kind { PRIVATE, GROUP, CHANNEL }

    public static ConversationRef privateChat(String peerName, boolean serverMode) {
        String key = serverMode ? peerName : peerName;
        return new ConversationRef(Kind.PRIVATE, key, peerName, null, false);
    }

    public static ConversationRef group(String id, String name, GroupPrivacy privacy) {
        return new ConversationRef(Kind.GROUP, id, name, privacy, false);
    }

    public static ConversationRef channel(String id, String name) {
        return new ConversationRef(Kind.CHANNEL, id, name, null, true);
    }
}
