import type {
  DerivedPositionState,
  Mapping,
  MappingAssignment,
  Question,
  RunManifest,
  SuccessCell,
} from "./types";

export interface JoinedAssignment {
  cell: SuccessCell;
  assignment: MappingAssignment;
}

export function endorsementSet(assignment: MappingAssignment): Set<string> {
  return new Set(
    assignment.primary_endorsed
      ? [assignment.primary_endorsed, ...assignment.also_endorsed]
      : assignment.also_endorsed,
  );
}

export function joinAssignments(
  run: RunManifest,
  mapping: Mapping,
  variantId: string,
  callType: "answer" | "challenge",
): JoinedAssignment[] {
  const assignments = new Map(
    mapping.assignments.map((assignment) => [assignment.response_id, assignment]),
  );

  return run.cells
    .filter(
      (cell): cell is SuccessCell =>
        cell.status === "success" &&
        cell.variant_id === variantId &&
        cell.call_type === callType,
    )
    .map((cell) => {
      const assignment = assignments.get(cell.response_id);
      if (!assignment) {
        throw new Error(`Missing mapping for response ${cell.response_id}`);
      }
      return { cell, assignment };
    });
}

export function derivePositionStates(
  question: Question,
  joined: JoinedAssignment[],
): DerivedPositionState[] {
  return question.position_map.map((position) => {
    const primaryModels: string[] = [];
    const additionalModels: string[] = [];
    const mentioningModels: string[] = [];

    for (const { cell, assignment } of joined) {
      if (assignment.primary_endorsed === position.id) {
        primaryModels.push(cell.model_family);
      }
      if (assignment.also_endorsed.includes(position.id)) {
        additionalModels.push(cell.model_family);
      }
      if (assignment.mentioned.includes(position.id)) {
        mentioningModels.push(cell.model_family);
      }
    }

    const represented = primaryModels.length > 0 || additionalModels.length > 0;
    const mentioned = mentioningModels.length > 0;

    return {
      positionId: position.id,
      representation: represented
        ? "represented"
        : mentioned
          ? "mentioned-only"
          : "not-represented",
      primaryModels,
      additionalModels,
      mentioningModels,
    };
  });
}

export function recoveredPositions(
  parent: MappingAssignment,
  challenge: MappingAssignment,
): string[] {
  const initial = endorsementSet(parent);
  return [...endorsementSet(challenge)].filter((positionId) => !initial.has(positionId));
}

export function sensitivityMovementCount(
  left: JoinedAssignment[],
  right: JoinedAssignment[],
): number {
  const leftByModel = new Map(
    left.map(({ cell, assignment }) => [cell.model_key, assignment.primary_endorsed]),
  );
  let changed = 0;

  for (const { cell, assignment } of right) {
    const leftPrimary = leftByModel.get(cell.model_key);
    const rightPrimary = assignment.primary_endorsed;
    if (
      leftPrimary !== undefined &&
      leftPrimary !== null &&
      rightPrimary !== null &&
      leftPrimary !== rightPrimary
    ) {
      changed += 1;
    }
  }
  return changed;
}
