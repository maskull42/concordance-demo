import {
  derivePositionStates,
  endorsementSet,
  joinAssignments,
  recoveredPositions,
  sensitivityMovementCount,
  sensitivityUnmappedTransitionCount,
} from "./derived";
import type {
  Mapping,
  MappingAssignment,
  ModelSnapshot,
  Position,
  Question,
  ResponseCell,
  RunManifest,
  SuccessCell,
} from "./types";

export type ViewMode = "answer" | "challenge";

export interface ModelViewState {
  model: ModelSnapshot;
  cell: ResponseCell | undefined;
  assignment: MappingAssignment | undefined;
  initialAssignment: MappingAssignment | undefined;
  primaryPosition: Position | undefined;
  initialPrimaryPosition: Position | undefined;
  additionalPositions: Position[];
  mentionedPositions: Position[];
  recoveredPositionIds: string[];
  status: "mapped" | "mixed" | "error" | "not-run";
}

export interface PositionViewState {
  position: Position;
  representation: "represented" | "mentioned-only" | "not-represented";
  primaryModels: ModelViewState[];
  additionalModels: ModelViewState[];
  mentioningModels: ModelViewState[];
  recoveredModels: ModelViewState[];
}

export interface CaseViewModel {
  question: Question;
  run: RunManifest;
  mapping: Mapping;
  variantId: string;
  mode: ViewMode;
  positions: PositionViewState[];
  models: ModelViewState[];
  mixedModels: ModelViewState[];
  errorModels: ModelViewState[];
  notRunModels: ModelViewState[];
  representedCount: number;
  mentionedOnlyCount: number;
  absentCount: number;
  recoveredPositionCount: number;
}

export function buildCaseViewModel(
  question: Question,
  run: RunManifest,
  mapping: Mapping,
  models: ModelSnapshot[],
  variantId: string,
  mode: ViewMode,
): CaseViewModel {
  const joined = joinAssignments(run, mapping, variantId, mode);
  const derived = derivePositionStates(question, joined);
  const positionById = new Map(
    question.position_map.map((position) => [position.id, position]),
  );
  const assignmentByResponse = new Map(
    mapping.assignments.map((assignment) => [assignment.response_id, assignment]),
  );
  const currentCells = new Map(
    run.cells
      .filter(
        (cell) => cell.variant_id === variantId && cell.call_type === mode,
      )
      .map((cell) => [cell.model_key, cell]),
  );
  const initialCells = new Map(
    run.cells
      .filter(
        (cell): cell is SuccessCell =>
          cell.status === "success" &&
          cell.variant_id === variantId &&
          cell.call_type === "answer",
      )
      .map((cell) => [cell.model_key, cell]),
  );

  const modelStates: ModelViewState[] = models.map((model) => {
    const cell = currentCells.get(model.model_key);
    const assignment =
      cell?.status === "success"
        ? assignmentByResponse.get(cell.response_id)
        : undefined;
    const initialCell = initialCells.get(model.model_key);
    const initialAssignment = initialCell
      ? assignmentByResponse.get(initialCell.response_id)
      : undefined;
    const recoveredPositionIds =
      mode === "challenge" && initialAssignment && assignment
        ? recoveredPositions(initialAssignment, assignment)
        : [];

    let status: ModelViewState["status"];
    if (!cell) status = "not-run";
    else if (cell.status === "error") status = "error";
    else if (!assignment?.primary_endorsed) status = "mixed";
    else status = "mapped";

    return {
      model,
      cell,
      assignment,
      initialAssignment,
      primaryPosition: assignment?.primary_endorsed
        ? positionById.get(assignment.primary_endorsed)
        : undefined,
      initialPrimaryPosition: initialAssignment?.primary_endorsed
        ? positionById.get(initialAssignment.primary_endorsed)
        : undefined,
      additionalPositions: (assignment?.also_endorsed ?? []).flatMap(
        (positionId) => {
          const position = positionById.get(positionId);
          return position ? [position] : [];
        },
      ),
      mentionedPositions: (assignment?.mentioned ?? []).flatMap((positionId) => {
        const position = positionById.get(positionId);
        return position ? [position] : [];
      }),
      recoveredPositionIds,
      status,
    };
  });

  const modelByFamily = new Map(
    modelStates.map((modelState) => [modelState.model.family, modelState]),
  );
  const derivedById = new Map(derived.map((state) => [state.positionId, state]));
  const positions = question.position_map.map((position): PositionViewState => {
    const state = derivedById.get(position.id);
    if (!state) throw new Error(`Missing derived state for ${position.id}`);
    return {
      position,
      representation: state.representation,
      primaryModels: state.primaryModels.flatMap((family) => {
        const model = modelByFamily.get(family);
        return model ? [model] : [];
      }),
      additionalModels: state.additionalModels.flatMap((family) => {
        const model = modelByFamily.get(family);
        return model ? [model] : [];
      }),
      mentioningModels: state.mentioningModels.flatMap((family) => {
        const model = modelByFamily.get(family);
        return model ? [model] : [];
      }),
      recoveredModels: modelStates.filter((model) =>
        model.recoveredPositionIds.includes(position.id),
      ),
    };
  });

  return {
    question,
    run,
    mapping,
    variantId,
    mode,
    positions,
    models: modelStates,
    mixedModels: modelStates.filter((model) => model.status === "mixed"),
    errorModels: modelStates.filter((model) => model.status === "error"),
    notRunModels: modelStates.filter((model) => model.status === "not-run"),
    representedCount: positions.filter(
      (position) => position.representation === "represented",
    ).length,
    mentionedOnlyCount: positions.filter(
      (position) => position.representation === "mentioned-only",
    ).length,
    absentCount: positions.filter(
      (position) => position.representation === "not-represented",
    ).length,
    recoveredPositionCount: new Set(
      modelStates.flatMap((model) => model.recoveredPositionIds),
    ).size,
  };
}

export function variantMovementCount(
  run: RunManifest,
  mapping: Mapping,
  leftVariantId: string,
  rightVariantId: string,
  mode: ViewMode,
): number {
  return sensitivityMovementCount(
    joinAssignments(run, mapping, leftVariantId, mode),
    joinAssignments(run, mapping, rightVariantId, mode),
  );
}

export function variantUnmappedTransitionCount(
  run: RunManifest,
  mapping: Mapping,
  leftVariantId: string,
  rightVariantId: string,
  mode: ViewMode,
): number {
  return sensitivityUnmappedTransitionCount(
    joinAssignments(run, mapping, leftVariantId, mode),
    joinAssignments(run, mapping, rightVariantId, mode),
  );
}

export function challengeMovementCount(
  run: RunManifest,
  mapping: Mapping,
  variantId: string,
): number {
  const initial = new Map(
    joinAssignments(run, mapping, variantId, "answer").map(
      ({ cell, assignment }) => [cell.model_key, assignment.primary_endorsed],
    ),
  );
  return joinAssignments(run, mapping, variantId, "challenge").filter(
    ({ cell, assignment }) =>
      initial.has(cell.model_key) &&
      initial.get(cell.model_key) !== assignment.primary_endorsed,
  ).length;
}

export function mappingSummary(assignment: MappingAssignment | undefined): string {
  if (!assignment) return "No human mapping is available.";
  const endorsed = endorsementSet(assignment);
  if (endorsed.size === 0) return "Mixed or unclear; no primary position assigned.";
  const suffix = endorsed.size > 1 ? ` plus ${endorsed.size - 1} additional` : "";
  return `Mapped to ${assignment.primary_endorsed ?? "no primary"}${suffix}.`;
}

export function safeExternalUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:" ||
      parsed.username ||
      parsed.password ||
      parsed.hostname === "localhost" ||
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname === "[::1]"
    ) {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}
