import { render } from "@testing-library/react";
import { App } from "../src/App";

export function renderInspect(hash = "#/inspect") {
  window.location.hash = hash;
  return render(<App />);
}

export function resetHash() {
  window.location.hash = "";
}
