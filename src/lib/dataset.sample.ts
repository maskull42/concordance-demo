import index from "../../sample/index.json";
import manifest from "../../sample/manifests/models.json";
import { validateDataset } from "./validate";

const questionModules = import.meta.glob("../../sample/questions/*.json", {
  eager: true,
  import: "default",
});
const runModules = import.meta.glob("../../sample/runs/*.json", {
  eager: true,
  import: "default",
});
const mappingModules = import.meta.glob("../../sample/mappings/*.json", {
  eager: true,
  import: "default",
});

export const dataset = validateDataset({
  index,
  manifest,
  questions: Object.values(questionModules),
  runs: Object.values(runModules),
  mappings: Object.values(mappingModules),
});
