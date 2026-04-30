package com.security.burp.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptOptions;
import burp.api.montoya.ai.chat.PromptResponse;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Thin wrapper around Montoya Ai. Gates on api.ai().isEnabled(),
 * caches identical prompts, and swallows exceptions so AI features
 * never break the scan.
 */
public class AiClient {

    private static final int CACHE_LIMIT = 1024;

    private final MontoyaApi api;
    private final ConcurrentMap<String, String> cache = new ConcurrentHashMap<>();
    private final boolean killSwitch;

    public AiClient(MontoyaApi api) {
        this.api = api;
        this.killSwitch = Boolean.getBoolean("com.security.burp.ai.disabled");
    }

    public boolean isAvailable() {
        if (killSwitch) return false;
        try {
            return api.ai().isEnabled();
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Send a system + user prompt with temperature 0.0. Returns trimmed
     * content, or null if AI is unavailable or the call failed.
     */
    public String ask(String system, String user) {
        if (!isAvailable()) return null;
        String key = system + "" + user;
        String cached = cache.get(key);
        if (cached != null) return cached;
        try {
            PromptOptions opts = PromptOptions.promptOptions().withTemperature(0.0);
            PromptResponse resp = api.ai().prompt().execute(opts,
                    Message.systemMessage(system),
                    Message.userMessage(user));
            String content = resp == null ? null : resp.content();
            if (content != null) {
                content = content.trim();
                if (cache.size() < CACHE_LIMIT) cache.put(key, content);
            }
            return content;
        } catch (Throwable t) {
            api.logging().logToError("[AI] Prompt failed: " + t.getMessage());
            return null;
        }
    }
}
