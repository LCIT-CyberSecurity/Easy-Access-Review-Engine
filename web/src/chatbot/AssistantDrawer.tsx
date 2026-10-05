import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { postJson } from "../api/client";

type AssistantSource = { id: string; publisher: string; title: string; reference?: string | null; version?: string | null; url?: string | null };
type Message = {
  role: "user" | "assistant";
  content: string;
  action?: { label: string; route: string };
  sources?: AssistantSource[];
  securityState?: string;
};

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
  } else if (route.startsWith("/perimeters")) {
    suggestions.push("À quoi servent les périmètres ?", "Comment associer un SI à une organisation ?");
  } else {
    if (canReadOperationalData) {
      suggestions.push(
        "Que dois-je traiter en priorité ?",
        "Quels contrôles mettre en place sur les accès privilégiés ?",
        "Quelles bonnes pratiques pour les comptes techniques ?",
        "Où créer une campagne ?",
      );
    } else {
      suggestions.push("Que dois-je faire maintenant ?");
    }
  }
  return suggestions;
}

export function safeAssistantSourceUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password ? parsed.href : null;
  } catch {
    return null;
  }
}

export function safeAssistantActionRoute(route: unknown): string | null {
  return typeof route === "string" && route.startsWith("/") && !route.startsWith("//")
    && !route.includes("://") && !route.includes("\\") && !/[\u0000-\u001f]/.test(route)
    ? route
    : null;
}

export function AssistantDrawer({ route, role = "ADMIN", open = true, close }: { route: string; role?: string; open?: boolean; close: () => void }) {
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
      const answer = typeof result.answer === "string" && result.answer.trim()
        ? result.answer
        : "Le chatbot n'a pas retourné de réponse exploitable.";
      const sources = Array.isArray(result.sources)
        ? result.sources.filter((source): source is AssistantSource => Boolean(source && typeof source === "object" && source.id && source.publisher && source.title))
        : [];
      setMessages((items) => [...items, {
        role: "assistant",
        content: answer,
        sources,
        securityState: typeof result.security_state === "string" ? result.security_state : undefined,
      }]);
      for (const action of Array.isArray(result.actions) ? result.actions : []) {
        const actionRoute = safeAssistantActionRoute(action?.route);
        if (actionRoute) {
          setMessages((items) => [...items, { role: "assistant", content: "", action: { label: String(action.label ?? action.action_id), route: actionRoute } }]);
        }
      }
    } catch (error) {
      setMessages((items) => [...items, { role: "assistant", content: error instanceof Error ? error.message : "Chatbot indisponible." }]);
    } finally {
      setLoading(false);
    }
  };
  return (
    <aside className="chatbot-drawer" aria-label="Chatbot EARE" hidden={!open}>
      <div className="chatbot-header"><strong>Chatbot EARE</strong><button className="text-button" type="button" aria-label="Fermer le Chatbot EARE" onClick={close}>×</button></div>
      <div className="chatbot-messages">
        {!messages.length ? <p className="muted">Je peux vous aider à utiliser EARE, analyser les informations auxquelles vous avez accès et répondre à vos questions sur le contrôle d'accès.</p> : null}
        {messages.map((item, index) => {
          if (item.role === "assistant" && item.action?.route.startsWith("/")) {
            return <button className="chatbot-action" key={`${item.role}-${index}`} onClick={() => { navigate(item.action!.route); close(); }}>{item.action.label}</button>;
          }
          return <div className={`chatbot-message ${item.role}`} key={`${item.role}-${index}`}>
            {item.securityState === "out_of_scope" ? <span className="chatbot-state">Hors périmètre</span> : null}
            {item.content}
            {item.role === "assistant" && item.sources?.length ? <div className="chatbot-sources">
              <strong>Sources</strong>
              <ul>{item.sources.map((source) => {
                const label = `${source.publisher} — ${source.title}${source.reference ? ` (${source.reference})` : ""}`;
                const url = safeAssistantSourceUrl(source.url);
                return <li key={source.id}>{url ? <a href={url} target="_blank" rel="noopener noreferrer">{label}</a> : label}</li>;
              })}</ul>
            </div> : null}
          </div>;
        })}
        {loading ? <div className="chatbot-message assistant">Analyse en cours…</div> : null}
      </div>
      <div className="chatbot-suggestions">
        {assistantSuggestions(route, role).map((suggestion) => <button key={suggestion} onClick={() => void send(suggestion)}>{suggestion}</button>)}
      </div>
      <form className="chatbot-form" onSubmit={(event) => { event.preventDefault(); void send(); }}>
        <input value={value} maxLength={8000} onChange={(event) => setValue(event.target.value)} placeholder="Posez une question au chatbot EARE…" aria-label="Question au chatbot" />
        <button className="button primary" disabled={loading || !value.trim()}>Envoyer</button>
      </form>
    </aside>
  );
}
