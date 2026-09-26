import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./i18n";
import "@fontsource-variable/inter";
import "./styles.css";
import { applyAppearance, applyTheme, readAppearance, readTheme } from "./theme";

// Applied before the first render so a stored style or appearance never flashes
// the default one first.
applyTheme(readTheme());
applyAppearance(readAppearance());

const queryClient = new QueryClient();
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
