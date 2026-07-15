// Every narrative string shown in story mode lives in this file so the copy
// can be audited in one place against the wording rules in the implementation
// plan (sections 8 and 13): counts always come from the view model, missing
// positions are described as unmapped in this sample, and no sentence claims
// model belief or truth.

export interface FramingCopy {
  eyebrow: string;
  intro: string;
  answersLine: string;
  convergenceSuffix: string;
  reframeLine: string;
  movementSuffix: string;
  fixedLine: string;
}

const framingDefaults: FramingCopy = {
  eyebrow: "One question, one panel",
  intro:
    "We put the same contested question to every model on the declared panel and cached each sampled answer verbatim.",
  answersLine:
    "Different companies, different training pipelines. The sampled answers came back one by one.",
  convergenceSuffix:
    " sampled answers received the same primary mapping, while other documented positions received none in this sample. The greyed rows keep their citations.",
  reframeLine:
    "Then we changed only the framing of the question. The underlying facts stayed identical.",
  movementSuffix: " primary conclusions moved between the two framings.",
  fixedLine: "The map changed because the prompt changed, nothing else.",
};

const framingById: Record<string, Partial<FramingCopy>> = {
  "john-brown-harpers-ferry": {
    eyebrow: "The question you ask writes the answer you get",
    intro:
      "We put one contested question about John Brown's 1859 raid to all eight systems and cached every sampled answer verbatim.",
    answersLine:
      "Eight companies, eight training pipelines. The sampled answers came back sounding remarkably alike.",
    convergenceSuffix:
      " sampled answers landed on the same characterization. Historians still defend other documented positions, each with citations; the greyed rows keep them in view.",
    reframeLine:
      "Then we changed only the framing of the question. The historical record stayed identical.",
    movementSuffix:
      " of the panel's primary conclusions moved with the framing.",
  },
};

export function framingCopy(questionId: string): FramingCopy {
  return { ...framingDefaults, ...framingById[questionId] };
}

export interface SplitCopy {
  eyebrow: string;
  intro: string;
  splitPrefix: string;
  splitSuffix: string;
  ghostsLead: string;
  implication: string;
}

const splitDefaults: SplitCopy = {
  eyebrow: "The same question, competing conclusions",
  intro:
    "Next, a question where the panel does not close ranks. Same panel, same protocol, one prompt.",
  splitPrefix: "The sampled answers split ",
  splitSuffix:
    " across the mapped positions, so the consensus a reader might have trusted does not exist in this sample.",
  ghostsLead:
    "Documented positions that received no primary mapping in this sample:",
  implication:
    "Where sampled answers agree, a reader can inherit an invisible collapse. Where they disagree, the choice of provider quietly decides which recommendation lands on the desk.",
};

const splitById: Record<string, Partial<SplitCopy>> = {
  "frontier-ai-lifecycle-licensing": {
    eyebrow: "A question a policy office might actually delegate",
    intro:
      "Now a live policy question: what should be the primary legal architecture for frontier general-purpose AI? Same panel, same protocol, one prompt.",
    splitPrefix: "The sampled answers split ",
    splitSuffix:
      " over the legal architecture, so the consensus a briefing might have relied on does not exist in this sample.",
    implication:
      "Where sampled answers agree, a reader can inherit an invisible collapse. Where they disagree, as here, the choice of provider quietly decides which legal architecture reaches the briefing.",
  },
};

export function splitCopy(questionId: string): SplitCopy {
  return { ...splitDefaults, ...splitById[questionId] };
}

export interface CollapseCopy {
  eyebrow: string;
  intro: string;
  collapseSuffix: string;
  missingLead: string;
  calibrationLine: string;
}

const collapseDefaults: CollapseCopy = {
  eyebrow: "The calibration case",
  intro:
    "On most questions, no one can check what an answer left out. This one is different: the documented readings are few, published, and citable, so omission is checkable.",
  collapseSuffix:
    " sampled answers received the same primary mapping. The documented alternatives received none in this sample.",
  missingLead:
    "Positions attested in the cited record that received no primary mapping in this sample:",
  calibrationLine:
    "Where the alternatives are documented, an absence can be checked instead of asserted. If the sampled answers concentrate this cleanly where the record lets us check, that pattern deserves attention where the record does not.",
};

const collapseById: Record<string, Partial<CollapseCopy>> = {
  "junia-romans-16-7": {
    eyebrow: "The calibration case",
    intro:
      "One verse, Romans 16:7, argued in print from the fourth century to 2020. The competing published readings are few, cited, and checkable, which makes this a rare question where omission can be checked rather than guessed at.",
    collapseSuffix:
      " sampled answers converged on the same reading of Junia. Two published alternative readings, both from peer-reviewed journals, received no primary mapping in this sample.",
    missingLead:
      "The published readings that received no primary mapping in this sample, with their citations:",
    calibrationLine:
      "This case is here because its paper trail lets you verify the gap yourself. If sampled answers concentrate this cleanly where the record can be checked, that pattern deserves attention on questions where it cannot.",
  },
};

export function collapseCopy(questionId: string): CollapseCopy {
  return { ...collapseDefaults, ...collapseById[questionId] };
}

export const graphicNotes = {
  queued: "One sampled answer per model, cached verbatim before any mapping.",
  answers:
    "Openings of the cached answers, shown without markdown formatting marks. The full verbatim text is in the receipts.",
  seated: "Sampled answers · author-reviewed mapping. Agreement is not truth.",
};

export interface OpeningCopy {
  eyebrow: string;
  question: string;
  panelNote: string;
}

export const openingCopy: OpeningCopy = {
  eyebrow: "Policy-facing model comparison",
  question:
    "What happens when a panel of AI systems answers a question that experts still argue about?",
  panelNote:
    "A declared panel, frozen before any question was asked. Flags mark each developer's headquarters country. Every sampled answer below is cached, verbatim, and inspectable.",
};

export interface CloseCopy {
  recap: string;
  challengeNote: string;
  cta: string;
}

export const closeCopy: CloseCopy = {
  recap:
    "Every count above is a count over cached, inspectable answers, with machine output and human-reviewed mapping kept visibly separate. Agreement is not truth; that is the point of showing the receipts.",
  challengeNote:
    "The full instrument also runs challenge samples, asking each model for the strongest supportable contrary position, to separate spontaneous omission from inability. Challenge samples were not run for this prototype.",
  cta: "Inspect the full record",
};
