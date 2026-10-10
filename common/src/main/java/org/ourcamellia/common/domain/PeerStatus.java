package org.ourcamellia.common.domain;

/**
 * Observer-relative reachability of a peer as seen by the local client.
 * UNCONFIRMED is used whenever we cannot honestly distinguish "offline" from
 * "unknown" (REQUIREMENTS 3.4).
 */
public enum PeerStatus { UNCONFIRMED, CONNECTED, DISCOVERED, UNREACHABLE }
