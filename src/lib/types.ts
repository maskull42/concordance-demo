import type { z } from "zod";
import type {
  datasetIndexSchema,
  errorCellSchema,
  mappingAssignmentSchema,
  mappingSchema,
  modelManifestSchema,
  modelSnapshotSchema,
  positionSchema,
  questionSchema,
  responseCellSchema,
  runManifestSchema,
  sourceSchema,
  successCellSchema,
  verificationSchema,
} from "./schema";

export type Verification = z.infer<typeof verificationSchema>;
export type Source = z.infer<typeof sourceSchema>;
export type Position = z.infer<typeof positionSchema>;
export type Question = z.infer<typeof questionSchema>;
export type ModelSnapshot = z.infer<typeof modelSnapshotSchema>;
export type ModelManifest = z.infer<typeof modelManifestSchema>;
export type SuccessCell = z.infer<typeof successCellSchema>;
export type ErrorCell = z.infer<typeof errorCellSchema>;
export type ResponseCell = z.infer<typeof responseCellSchema>;
export type RunManifest = z.infer<typeof runManifestSchema>;
export type MappingAssignment = z.infer<typeof mappingAssignmentSchema>;
export type Mapping = z.infer<typeof mappingSchema>;
export type DatasetIndex = z.infer<typeof datasetIndexSchema>;

export interface Dataset {
  index: DatasetIndex;
  manifest: ModelManifest;
  questions: Question[];
  runs: RunManifest[];
  mappings: Mapping[];
  modelFamilies: string[];
  isSample: boolean;
}

export type PositionRepresentation =
  | "represented"
  | "mentioned-only"
  | "not-represented";

export interface DerivedPositionState {
  positionId: string;
  representation: PositionRepresentation;
  primaryModels: string[];
  additionalModels: string[];
  mentioningModels: string[];
}
