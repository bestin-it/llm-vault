# VS Code + GitHub Copilot Chat -> LLM Vault (Custom Endpoint)

1. In LLM Vault: **Clients & agents > New client token** (e.g. "VS Code - Code Reviewer", models
   `foundry-glm, qwen-local`, consent "Ask once per session"). Copy the token (`lvk_...`).
2. In VS Code: **Chat: Manage Language Models** > **Add Models** > **Custom Endpoint**, API type
   **Chat Completions**, URL `http://127.0.0.1:8765/v1/chat/completions`, API key = the client token.
   Alternatively paste [`chatLanguageModels.json`](chatLanguageModels.json) into the file VS Code opens.
3. Set `"toolCalling": true` - models without tool calling are hidden in agent mode.
4. Pick the model in the chat model picker or in a custom agent
   ([`../.github/agents/code-reviewer.agent.md`](../.github/agents/code-reviewer.agent.md)).
5. The first request shows a consent prompt in LLM Vault; choose *Allow for this session*.

Notes
- Copilot Business / Enterprise: the organization must enable the policy
  **Bring Your Own Language Model Key in VS Code**.
- Built-in Copilot models stay on GitHub's own authentication path and are not visible to the vault.
- The client token is a *permission to call the gateway*, not a provider key: scope it to the models
  you need, give it an expiry and revoke it from the vault at any time.
- Tested request shape: OpenAI Chat Completions with streaming and tool calls. The vault also serves
  `apiType: "messages"` for aliases backed by Anthropic or Ollama.
