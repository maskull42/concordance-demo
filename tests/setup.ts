import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(cleanup);

// jsdom implements neither scrolling nor IntersectionObserver. Scrolling is a
// no-op in unit tests; observed story steps simply never activate.
if (typeof Element.prototype.scrollIntoView !== "function") {
  Element.prototype.scrollIntoView = () => {};
}
window.scrollTo = (() => {}) as typeof window.scrollTo;

if (typeof globalThis.IntersectionObserver === "undefined") {
  class IntersectionObserverStub implements IntersectionObserver {
    readonly root: Element | Document | null = null;
    readonly rootMargin: string = "0px";
    readonly scrollMargin: string = "0px";
    readonly thresholds: ReadonlyArray<number> = [0];
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
    takeRecords(): IntersectionObserverEntry[] {
      return [];
    }
  }
  globalThis.IntersectionObserver =
    IntersectionObserverStub as unknown as typeof IntersectionObserver;
}
