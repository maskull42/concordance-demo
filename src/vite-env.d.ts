/// <reference types="vite/client" />

declare module "@dataset" {
  import type { Dataset } from "./lib/types";
  export const dataset: Dataset;
}
