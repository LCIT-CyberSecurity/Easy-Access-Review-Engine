import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { postJson } from "../api/client";

type Message = { role: "user" | "assistant"; content: string; action?: { label: string; route: string } };

export function AssistantDrawer({ route, close }: { route: string; close: () => void }) {
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
        if (typeof action?.route === "string" && action.route.startsWith("/") && !action.route.includes("://")) {
          setMessages((items) => [...items, { role: "assistant", content: "", action: { label: String(action.label ?? action.action_id), route: action.route } }]);
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
        <button onClick={() => void send("Que dois-je faire maintenant ?")}>Que faire maintenant ?</button>
        {route.startsWith("/campaigns") ? <button onClick={() => void send("Que reste-t-il à faire ?")}>Que reste-t-il à faire ?</button> : null}
        {route.startsWith("/golden") ? <button onClick={() => void send("Qu'est-ce que je dois compléter ?")}>Que compléter ?</button> : null}
        {route.startsWith("/reviews") ? <button onClick={() => void send("Que dois-je traiter ?")}>Que traiter ?</button> : null}
      </div>
      <form className="chatbot-form" onSubmit={(event) => { event.preventDefault(); void send(); }}>
        <input value={value} maxLength={8000} onChange={(event) => setValue(event.target.value)} placeholder="Posez une question sur EARE…" aria-label="Question à l'assistant" />
        <button className="button primary" disabled={loading || !value.trim()}>Envoyer</button>
      </form>
    </aside>
  );
}
