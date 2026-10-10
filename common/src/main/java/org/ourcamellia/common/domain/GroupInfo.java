package org.ourcamellia.common.domain;

import java.util.List;

/** Group metadata as known to a participant or the server. */
public record GroupInfo(
        String id,
        String name,
        GroupPrivacy privacy,
        String owner,                       // display name
        List<String> members,               // display names
        long createdAt,
        String description) {

    public GroupInfo {
        members = members == null ? List.of() : List.copyOf(members);
    }

    public boolean isMember(String user) {
        return members.contains(user) || owner.equals(user);
    }
}
