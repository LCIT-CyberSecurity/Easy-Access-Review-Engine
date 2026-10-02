import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { postJson } from "../api/client";

type Message = { role: "user" | "assistant"; content: string; action?: { label: string; route: string } };

export function assistantSuggestions(route: string, role = "ADMIN"): string[] {
  const canReadOperationalData = role === "ADMIN" || role === "OPERATOR";
  const suggestions: string[] = [];
  if (route === "/" || route === "/dashboard") {
    suggestions.push("Résumer mon dashboard", "Que dois-je traiter en priorité ?");
  } else if (route.startsWith("/campaigns") && canReadOperationalData) {
    suggestions.push(
      "Résumer cette campagne",
      "Que reste-t-il à traiter ?",
      "Que reste-t-il à faire ?",
      "Quels sont les principaux findings ?",
      "Pourquoi cette campagne n'est-elle pas terminée ?",
    );
  } else if (route.startsWith("/golden") && canReadOperationalData) {
    suggestions.push(
      "Évaluer la qualité de ma Golden",
      "Quels accès sont incomplets ?",
      "Quels owners manquent ?",
      "Qu'est-ce que je dois compléter ?",
      "Puis-je lancer une campagne ?",
    );
  } else if (route.startsWith("/reviews")) {
    suggestions.push("Que dois-je traiter ?", "Explique cet accès", "Pourquoi est-il unexpected ?");
  } else if (route.startsWith("/sources") && canReadOperationalData) {
    suggestions.push("Quel est l'état de cette source ?", "Le snapshot est-il exploitable ?");
  } else if (route.startsWith("/actions") && (canReadOperationalData || role === "BUSINESS_ADMIN" || role === "REMEDIATION_MANAGER")) {
    suggestions.push("Que dois-je faire maintenant ?", "Quelles remédiations restent ouvertes ?");
  } else {
    suggestions.push("Que dois-je faire maintenant ?");
  }
  return suggestions;
}

export function safeAssistantActionRoute(route: unknown): string | null {
  return typeof route === "string" && route.startsWith("/") && !route.startsWith("//")
    && !route.includes("://") && !route.includes("\\") && !/[\u0000-\u001f]/.test(route)
    ? route
    : null;
}

export function AssistantDrawer({ route, role = "ADMIN", close }: { route: string; role?: string; close: () => void }) {
  const navigate = useNavigate();
  const [messages, setMessages] = useState<Message[]>([]);
  const [value, setValue] = useState("");
  const [conversationId, setConversationId] = useState<string>();
  const [loading, setLoading] = useState(false);
  const send = async (text = value) => {
    const message = text.trim();
    if (!message || loading) return;
    setValue("");
    setMessages((items) => [...items, { role: "user", content: message }]);
    setLoading(true);
    try {
      const result = await postJson("chatbot/message", {
        message,
        route,
        ...(conversationId ? { conversation_id: conversationId } : {}),
      });
      setConversationId(String(result.conversation_id ?? conversationId ?? ""));
      setMessages((items) => [...items, { role: "assistant", content: String(result.answer ?? "") }]);
      for (const action of Array.isArray(result.actions) ? result.actions : []) {
        const actionRoute = safeAssistantActionRoute(action?.route);
        if (actionRoute) {
          setMessages((items) => [...items, { role: "assistant", content: "", action: { label: String(action.label ?? action.action_id), route: actionRoute } }]);
        }
      }
    } catch (error) {
      setMessages((items) => [...items, { role: "assistant", content: error instanceof Error ? error.message : "Assistant indisponible." }]);
    } finally {
      setLoading(false);
    }
  };
  return (
    <aside className="chatbot-drawer" aria-label="Assistant EARE">
      <div className="chatbot-header"><strong>Assistant EARE</strong><button className="text-button" onClick={close}>×</button></div>
      <div className="chatbot-messages">
        {!messages.length ? <p className="muted">Je peux vous aider à comprendre EARE, vos campagnes, vos revues et votre Golden Source.</p> : null}
        {messages.map((item, index) => {
          if (item.role === "assistant" && item.action?.route.startsWith("/")) {
            return <button className="chatbot-action" key={`${item.role}-${index}`} onClick={() => { navigate(item.action!.route); close(); }}>{item.action.label}</button>;
          }
          return <div className={`chatbot-message ${item.role}`} key={`${item.role}-${index}`}>{item.content}</div>;
        })}
        {loading ? <div className="chatbot-message assistant">Analyse en cours…</div> : null}
      </div>
      <div className="chatbot-suggestions">
        {assistantSuggestions(route, role).map((suggestion) => <button key={suggestion} onClick={() => void send(suggestion)}>{suggestion}</button>)}
      </div>
      <form className="chatbot-form" onSubmit={(event) => { event.preventDefault(); void send(); }}>
        <input value={value} maxLength={8000} onChange={(event) => setValue(event.target.value)} placeholder="Posez une question sur EARE…" aria-label="Question à l'assistant" />
        <button className="button primary" disabled={loading || !value.trim()}>Envoyer</button>
      </form>
    </aside>
  );
}
