package org.ourcamellia.core.app;

import org.ourcamellia.common.Errors;
import org.ourcamellia.core.persist.ClientStateStore;

/**
 * Trust-on-first-use pin policy (Local mode and Server mode share it):
 *
 * - First sighting of a certificate fingerprint at an address is recorded.
 * - A known friend connects from their known address with a different fingerprint →
 *   refused (possible impersonation).
 * - The same fingerprint appearing from a new address is allowed (peer moved) and
 *   recorded.
 */
final class PinGuard {

    private PinGuard() {}

    /** Returns the fingerprint a friend previously used at this address, or null. */
    static String expectedFingerprint(ClientStateStore store, String address) {
        for (var e : store.state().friends.entrySet()) {
            ClientStateStore.FriendRec f = e.getValue();
            if (address.equals(f.address()) && f.fingerprint() != null) {
                return f.fingerprint();
            }
        }
        return null;
    }

    /** Post-handshake check + pin recording. */
    static void check(ClientStateStore store, String fingerprint, String address) {
        for (var e : store.state().friends.entrySet()) {
            ClientStateStore.FriendRec f = e.getValue();
            if (address.equals(f.address()) && f.fingerprint() != null
                    && !f.fingerprint().equalsIgnoreCase(fingerprint)) {
                throw new Errors.Network(
                        "certificate for " + address + " changed (possible impersonation); connection refused");
            }
        }
        ClientStateStore.PinRec pin = store.pin(fingerprint);
        if (pin == null || !pin.addresses().contains(address)) {
            store.putPin(fingerprint, pin == null ? null : pin.name(), address);
        }
    }
}
