import { useSyncExternalStore } from "react";
import type { Dataset } from "./types";
import type { ViewMode } from "./view-model";

export interface InspectRef {
  questionId?: string;
  modelKey?: string;
  variantId?: string;
  view?: ViewMode;
  open?: "receipts";
}

export type Route =
  | { mode: "story" }
  | ({ mode: "inspect"; anchor?: string } & InspectRef);

const LEGACY_ANCHORS = new Set(["cases", "method", "top"]);

export function parseHash(hash: string, dataset: Dataset): Route {
  const value = hash.startsWith("#") ? hash.slice(1) : hash;
  if (value === "" || value === "/" || value === "/story") {
    return { mode: "story" };
  }

  if (value === "/inspect" || value.startsWith("/inspect/") || value.startsWith("/inspect?")) {
    const [path, query = ""] = value.split("?");
    const segments = path.split("/").filter(Boolean);
    const route: Route = { mode: "inspect" };
    const questionId = segments[1];
    const question = questionId
      ? dataset.questions.find((entry) => entry.id === questionId)
      : undefined;
    if (question) {
      route.questionId = question.id;
      const params = new URLSearchParams(query);
      const modelKey = params.get("model");
      if (
        modelKey &&
        dataset.manifest.models.some((model) => model.model_key === modelKey)
      ) {
        route.modelKey = modelKey;
      }
      const variantId = params.get("variant");
      if (
        variantId &&
        question.prompt_variants.some((variant) => variant.id === variantId)
      ) {
        route.variantId = variantId;
      }
      const view = params.get("view");
      if (view === "answer" || view === "challenge") {
        route.view = view;
      }
      if (params.get("open") === "receipts") {
        route.open = "receipts";
      }
    }
    return route;
  }

  if (LEGACY_ANCHORS.has(value)) {
    return { mode: "inspect", anchor: value };
  }
  const legacyQuestion = dataset.questions.find((entry) => entry.id === value);
  if (legacyQuestion) {
    return { mode: "inspect", questionId: legacyQuestion.id };
  }

  return { mode: "story" };
}

export function buildInspectHash(ref: InspectRef): string {
  if (!ref.questionId) return "#/inspect";
  const params = new URLSearchParams();
  if (ref.modelKey) params.set("model", ref.modelKey);
  if (ref.variantId) params.set("variant", ref.variantId);
  if (ref.view) params.set("view", ref.view);
  if (ref.open) params.set("open", ref.open);
  const query = params.toString();
  return `#/inspect/${ref.questionId}${query ? `?${query}` : ""}`;
}

function subscribe(listener: () => void): () => void {
  window.addEventListener("hashchange", listener);
  return () => window.removeEventListener("hashchange", listener);
}

function getHashSnapshot(): string {
  return window.location.hash;
}

export function useHashRoute(dataset: Dataset): Route {
  const hash = useSyncExternalStore(subscribe, getHashSnapshot, () => "");
  return parseHash(hash, dataset);
}
