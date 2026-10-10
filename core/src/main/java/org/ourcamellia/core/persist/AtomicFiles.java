package org.ourcamellia.core.persist;

import org.ourcamellia.common.Errors;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * Robust file writes: write to a temp file in the same directory, fsync, then
 * atomically replace the target (fallback: non-atomic replace on filesystems without
 * atomic move). Corruption of the previous file can therefore never produce a
 * half-written state file.
 */
public final class AtomicFiles {

    private AtomicFiles() {}

    public static void write(Path target, byte[] content) {
        Path dir = target.toAbsolutePath().getParent();
        if (dir == null) {
            throw new Errors.Persistence("cannot resolve directory for " + target);
        }
        try {
            Files.createDirectories(dir);
            Path tmp = Files.createTempFile(dir, ".tmp-" + target.getFileName(), ".part");
            try {
                try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                    ch.write(java.nio.ByteBuffer.wrap(content));
                    ch.force(true);
                }
                try {
                    Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE,
                            StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new Errors.Persistence("cannot write " + target, e);
        }
    }

    public static void writeString(Path target, String content) {
        write(target, content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Reads bytes or returns null when the file does not exist. */
    public static byte[] readOrNull(Path target) {
        try {
            if (!Files.exists(target)) {
                return null;
            }
            return Files.readAllBytes(target);
        } catch (IOException e) {
            throw new Errors.Persistence("cannot read " + target, e);
        }
    }

    /**
     * Corrupted-file quarantine: move the broken file aside (never silently delete
     * recoverable data), so a human can inspect it later.
     */
    public static void quarantine(Path target, String reason) {
        try {
            if (!Files.exists(target)) {
                return;
            }
            Path q = target.resolveSibling(target.getFileName() + ".corrupt-" + System.currentTimeMillis());
            Files.move(target, q, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // Quarantine is best effort; the original error still propagates to the caller.
        }
    }
}
