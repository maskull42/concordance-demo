import { validateDataset } from "./validate";

const prototypeRoot = "../../.pilot/prototype-data";
const assemblyInstruction =
  "Prototype dataset is absent or incomplete. Run `npm run prototype:data` first.";

const indexModules = import.meta.glob(
  "../../.pilot/prototype-data/index.json",
  { eager: true, import: "default" },
);
const manifestModules = import.meta.glob(
  "../../.pilot/prototype-data/manifests/*.json",
  { eager: true, import: "default" },
);
const questionModules = import.meta.glob(
  "../../.pilot/prototype-data/questions/*.json",
  { eager: true, import: "default" },
);
const runModules = import.meta.glob(
  "../../.pilot/prototype-data/runs/*.json",
  { eager: true, import: "default" },
);
const mappingModules = import.meta.glob(
  "../../.pilot/prototype-data/mappings/*.json",
  { eager: true, import: "default" },
);

interface PrototypeIndex {
  model_manifest?: string;
  questions?: Array<{
    question?: string;
    run?: string;
    mapping?: string;
  }>;
}

const index = Object.values(indexModules)[0];
if (!index) throw new Error(assemblyInstruction);

const indexed = index as PrototypeIndex;
const entries = indexed.questions ?? [];

export const dataset = validateDataset({
  index,
  manifest: loadIndexedModule(manifestModules, indexed.model_manifest),
  questions: entries.map((entry) =>
    loadIndexedModule(questionModules, entry.question),
  ),
  runs: entries.map((entry) => loadIndexedModule(runModules, entry.run)),
  mappings: entries.map((entry) =>
    loadIndexedModule(mappingModules, entry.mapping),
  ),
});

function loadIndexedModule(
  modules: Record<string, unknown>,
  relativePath: string | undefined,
): unknown {
  if (!relativePath) throw new Error(assemblyInstruction);
  const modulePath = `${prototypeRoot}/${relativePath}`;
  const loaded = modules[modulePath];
  if (!loaded) throw new Error(`${assemblyInstruction} Missing ${relativePath}.`);
  return loaded;
}
