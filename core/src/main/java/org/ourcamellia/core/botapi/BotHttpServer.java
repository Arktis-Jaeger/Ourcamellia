package org.ourcamellia.core.botapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Json;
import org.ourcamellia.common.config.ServerConfig;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.core.server.ServerCore;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Optional BOT API HTTP adapter (ARCHITECTURE.md §3): a thin wrapper over the
 * in-process BotSession operations. Default bind is loopback-only and disabled
 * unless the operator enables it; there are no administrative endpoints and every
 * request requires a valid bot token (bearer auth). Binding to a non-loopback
 * address is possible via configuration and documented as an explicit operator
 * risk decision (no TLS on this adapter — use it on loopback only).
 *
 * Endpoints:
 *   POST /v1/auth        {token}                        → {bot, status:"ok"}
 *   POST /v1/send        {token, to, text}              → private message
 *   POST /v1/group-send  {token, groupId, text}         → group message
 *   POST /v1/friend-request {token, to}                 → friend request
 *   GET  /v1/events?token=...                           → queued events (JSON array)
 */
public final class BotHttpServer implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(BotHttpServer.class.getName());

    private final ServerCore server;
    private final ServerConfig config;
    private HttpServer http;
    private final Map<String, BotSession> sessions = new ConcurrentHashMap<>();

    public BotHttpServer(ServerCore server, ServerConfig config) {
        this.server = server;
        this.config = config;
    }

    public void start() {
        try {
            http = HttpServer.create(new InetSocketAddress(config.botApi().bindHost(), config.botApi().port()), 0);
            http.createContext("/v1/auth", this::handleAuth);
            http.createContext("/v1/send", this::handleSend);
            http.createContext("/v1/group-send", this::handleGroupSend);
            http.createContext("/v1/friend-request", this::handleFriendRequest);
            http.createContext("/v1/events", this::handleEvents);
            http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
            http.start();
            LOG.info("bot api listening on " + config.botApi().bindHost() + ":" + config.botApi().port());
        } catch (IOException e) {
            throw new Errors.Persistence("cannot start bot api listener", e);
        }
    }

    private BotSession sessionFor(JsonNode body) {
        String token = body.path("token").asText("");
        if (token.isBlank()) {
            throw new Errors.Auth("missing token");
        }
        return sessions.computeIfAbsent(token, t -> {
            try {
                return server.openBotSession(t, "");
            } catch (Errors.OcException e) {
                throw e;
            }
        });
    }

    private void handleAuth(HttpExchange exchange) {
        withBody(exchange, body -> {
            BotSession s = sessionFor(body);
            var out = Json.object();
            out.put("bot", s.botName());
            out.put("status", "ok");
            return out;
        });
    }

    private void handleSend(HttpExchange exchange) {
        withBody(exchange, body -> {
            BotSession s = sessionFor(body);
            s.sendPrivate(body.path("to").asText(""), body.path("text").asText(""));
            var out = Json.object();
            out.put("status", "sent");
            return out;
        });
    }

    private void handleGroupSend(HttpExchange exchange) {
        withBody(exchange, body -> {
            BotSession s = sessionFor(body);
            s.sendGroup(body.path("groupId").asText(""), body.path("text").asText(""));
            var out = Json.object();
            out.put("status", "sent");
            return out;
        });
    }

    private void handleFriendRequest(HttpExchange exchange) {
        withBody(exchange, body -> {
            BotSession s = sessionFor(body);
            s.sendFriendRequest(body.path("to").asText(""));
            var out = Json.object();
            out.put("status", "pending");
            return out;
        });
    }

    private void handleEvents(HttpExchange exchange) {
        try {
            String token = query(exchange, "token");
            if (token == null) {
                respond(exchange, 401, "{\"error\":\"missing token\"}");
                return;
            }
            BotSession s = sessions.get(token);
            if (s == null) {
                respond(exchange, 401, "{\"error\":\"invalid token\"}");
                return;
            }
            var out = Json.array();
            List<Envelope> events = s.drainEvents();
            for (Envelope e : events) {
                out.add(e.root());
            }
            respond(exchange, 200, Json.write(out));
        } catch (RuntimeException e) {
            respond(exchange, 500, "{\"error\":\"internal error\"}");
        }
    }

    private void withBody(HttpExchange exchange, java.util.function.Function<JsonNode, JsonNode> handler) {
        try {
            String raw;
            try {
                raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                respond(exchange, 400, "{\"error\":\"cannot read request body\"}");
                return;
            }
            JsonNode body = Json.parse(raw);
            JsonNode out = handler.apply(body);
            respond(exchange, 200, Json.write(out));
        } catch (Errors.OcException e) {
            int code = switch (e.category) {
                case AUTH -> 401;
                case DENIED -> 403;
                case RATE_LIMITED -> 429;
                case VALIDATION, USAGE -> 400;
                case NOT_FOUND -> 404;
                case CONFLICT -> 409;
                default -> 500;
            };
            respond(exchange, code, "{\"error\":" + Json.write(e.getMessage()) + "}");
        } catch (RuntimeException e) {
            LOG.log(Level.FINE, "bot api request failed", e);
            respond(exchange, 400, "{\"error\":\"bad request\"}");
        }
    }

    private static String query(HttpExchange exchange, String key) {
        String q = exchange.getRequestURI().getQuery();
        if (q == null) {
            return null;
        }
        for (String part : q.split("&")) {
            int eq = part.indexOf('=');
            if (eq > 0 && part.substring(0, eq).equals(key)) {
                return java.net.URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private void respond(HttpExchange exchange, int code, String body) {
        try {
            byte[] out = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(code, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        } catch (IOException ignored) {
        } finally {
            exchange.close();
        }
    }

    @Override
    public void close() {
        if (http != null) {
            http.stop(0);
        }
        for (BotSession s : new ArrayList<>(sessions.values())) {
            s.close();
        }
        sessions.clear();
    }
}
