package org.ourcamellia.common.domain;

/** A chat message as exchanged and stored. Text is the literal payload; never parsed. */
public record Message(
        String id,
        String conversationId,
        String sender,     // display form: "@name" (server) or bare name (local)
        String text,
        long ts) {

    public static Message create(String conversationId, String sender, String text) {
        return new Message(
                org.ourcamellia.common.Ids.newId(),
                conversationId,
                sender,
                text,
                System.currentTimeMillis());
    }
}
