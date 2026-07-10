import "@fontsource-variable/inter/index.css";
import "@fontsource-variable/newsreader/index.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles/index.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Concordance root element was not found.");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
