import path from "node:path";
import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));
const datasetName = process.env.VITE_DATASET ?? "sample";
const datasetModules = {
  sample: "src/lib/dataset.sample.ts",
  prototype: "src/lib/dataset.prototype.ts",
  production: "src/lib/dataset.production.ts",
} as const;

if (!(datasetName in datasetModules)) {
  throw new Error(
    `Unknown VITE_DATASET "${datasetName}". Expected sample, prototype, or production.`,
  );
}

const datasetModule = datasetModules[datasetName as keyof typeof datasetModules];

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@dataset": path.resolve(
        projectRoot,
        datasetModule,
      ),
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
  },
});
