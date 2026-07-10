import index from "../../data/index.json";
import manifest from "../../data/manifests/models.json";
import { validateDataset } from "./validate";

const questionModules = import.meta.glob("../../data/questions/*.json", {
  eager: true,
  import: "default",
});
const runModules = import.meta.glob("../../data/runs/*.json", {
  eager: true,
  import: "default",
});
const mappingModules = import.meta.glob("../../data/mappings/*.json", {
  eager: true,
  import: "default",
});

export const dataset = validateDataset(
  {
    index,
    manifest,
    questions: Object.values(questionModules),
    runs: Object.values(runModules),
    mappings: Object.values(mappingModules),
  },
  { production: true },
);
