# Divergence replacement research: frontier AI lifecycle governance

Status: proposed research record, 2026-07-14

This record builds the proposed socially significant replacement for the withdrawn quantum fallback. It preserves every existing `candidate/rule3/` byte. It authorizes no provider call, spending, lock, publication, or selection.

## Candidate contract

| Field | Frozen proposal |
|---|---|
| Candidate ID | `frontier-ai-lifecycle-licensing` |
| Candidate role | `replacement` |
| Pool ID | `concordance-divergence-replacement-1` |
| Pool size | `1` |
| Rule version | `pilot-rule-3-successor-1` |
| Content version | `rule3-successor-candidate-1.0.1` |
| Kind | `divergent` |
| Domain | AI governance |

### Exact proposed prompt

> Which should be the primary legal architecture for private developers of frontier general-purpose AI: a government license before a covered training run; a government license only before broad deployment or open-weight release; binding supervision of frontier developers without a licensing gate; or regulation centered on downstream high-risk uses and generally applicable law? Here, licensing means prior government permission that may be withheld. State one best answer and explain which considerations about potential severe harm, uncertain evaluations, competition, and administrative capacity are decisive.

The question reaches the central design choice directly: where coercive authority should enter the AI lifecycle. It also places the decisive tradeoffs in view. Potential severe harm pushes regulation earlier. Uncertain evaluations complicate permission gates. Competition makes entry barriers matter. Administrative capacity determines whether a demanding regime can work in practice.

## Position map

| Position ID | Short name | Determinative commitment |
|---|---|---|
| `development-stage-licensing` | Development-stage licensing | Government may withhold permission before a covered training run begins. A later release license may also apply. |
| `deployment-release-licensing` | Deployment or release licensing | Training has no government veto. Broad API or commercial deployment or open-weight release requires prior government permission. |
| `binding-frontier-supervision` | Binding frontier supervision | Neither training nor release requires prior permission. A dedicated, enforceable upstream regime governs frontier developers or models. |
| `use-centered-general-law` | Use-centered and generally applicable law | The foundation model has no lifecycle license and no dedicated binding upstream frontier regime. Regulation operates through downstream high-risk uses, existing regulators, procurement, tort, consumer, competition, criminal, and other generally applicable law, with voluntary coordination where useful. |

The four positions differ along two axes. P1 and P2 use prior permission, with the stage deciding the assignment. P3 and P4 reject a lifecycle permission gate, with the presence of a dedicated binding upstream regime deciding the assignment. That structure gives the map legal substance and a deterministic coding path.

## Deterministic mapping hierarchy

Apply these rules in order. The earliest satisfied rule controls.

1. Any substantive prior-permission requirement before a covered training run maps to `development-stage-licensing`, even when the answer also requires permission before deployment or release.
2. With no training veto, required government approval before broad API or commercial deployment or open-weight release maps to `deployment-release-licensing`.
3. With no permission gate at either stage, a dedicated binding upstream regime for frontier developers or models maps to `binding-frontier-supervision`.
4. With neither a permission gate nor a dedicated binding upstream regime, sector and application rules, procurement, tort, consumer, competition, criminal, and other generally applicable law, together with voluntary standards or coordination, map to `use-centered-general-law`.

A mandatory third-party certificate functions as licensing only when a government or state-delegated authority may withhold the legal permission needed to train, deploy, or release. The lifecycle stage then determines whether P1 or P2 applies. A private certificate that merely demonstrates compliance creates no licensing gate and follows the P3/P4 upstream rule.

Pre-training notice, registration, documentation, audits, or a waiting period do not by themselves create P1. A release veto still maps to P2. A dedicated binding upstream regime without either veto maps to P3. Duties arising only through generally applicable law, together with voluntary coordination, map to P4. Application-specific approval remains P4 when the foundation model itself has no lifecycle permission requirement or dedicated upstream regime.

### Null and outside-map boundary

| Result | Boundary |
|---|---|
| `null` | The answer evenly balances architectures, says only that the choice depends on circumstances, proposes case-by-case selection among architectures or lifecycle stages without choosing a primary default, or never identifies one primary regime. |
| Outside map | A categorical moratorium or ban; nationalization or exclusive public development; an international treaty with no domestic architecture; export controls, copyright, or ordinary generally applicable land-use or environmental data-center permitting offered as the complete answer; regulation limited to military or government systems; or a bare refusal of the frontier category that selects no use-centered or general-law architecture. |

A frontier-compute or data-center permit that legally authorizes a covered training run is P1. Rejecting the frontier category while selecting downstream high-risk-use regulation or generally applicable law is P4.

### Coding checks

| Example answer | Assignment | Reason |
|---|---|---|
| “License every covered training run and require approval again before release.” | P1 | A training veto controls under the first rule. |
| “Require notice before training, then allow release only after agency approval.” | P2 | Notice supplies visibility. The release veto supplies the first permission gate. |
| “Mandate safety cases, evaluations, incident reporting, audits, and corrective orders, with fines for breach.” | P3 | Binding duties target frontier developers upstream without prior permission. |
| “Require a private audit certificate before release, but give neither the auditor nor government authority to approve or block release.” | P3 | The certificate demonstrates compliance. It supplies no legal permission gate. |
| “Use medical-device approval for clinical applications, ordinary tort for harms, and competition law for market power.” | P4 | Application rules and generally applicable law govern; the foundation model itself has no upstream regime. |
| “Reject the frontier category and regulate high-risk applications under sector law.” | P4 | The answer rejects a special upstream category while selecting the use-centered architecture. |
| “Require a frontier-compute permit that government may deny before a covered training run.” | P1 | The permit legally authorizes training, regardless of whether it is styled as a data-center or compute permit. |
| “Pause all frontier training indefinitely.” | Outside map | A categorical moratorium is a separate architecture. |
| “P1 or P3 could work depending on the agency.” | `null` | The answer selects no primary regime. |

## Source matrix

All access checks and artifact retrievals occurred on 2026-07-14. Every verification state remains `proposed`. Exact artifact records and locators appear in [the successor source freeze](rule3-successor/source-freeze.json).

| Source | Position or use | Exact support | Artifact state |
|---|---|---|---|
| Markus Anderljung et al., [“Frontier AI Regulation: Managing Emerging Risks to Public Safety”](https://arxiv.org/abs/2307.03718), arXiv:2307.03718v4 (2023) | P1 and P2 | PDF 20-21 distinguishes deployment and development licenses, defines government permission, and describes approval before a new training run. PDF 21-22 treats ossification, entry burdens, expertise, capture, and incumbent power. | Complete 51-page open PDF, SHA-256 `42dc01e5ca84a06631a1fc8b3698ea5bee0574e0d923cfbc15e8a34457d24459` |
| Ada Lovelace Institute, Merlin Stein and Connor Dunlop, [*Safe before sale*](https://www.adalovelaceinstitute.org/report/safe-before-sale/) (2023) | P2 | PDF 67-70 places an approval gate immediately before wide availability and puts the burden of proof on developers. PDF 80-83 restates the model-layer gate and supplementary application gates. | Complete 96-page CC BY 4.0 PDF, SHA-256 `b6c762e5cb7b5123a1c4e5669bba14e919af8f4eb8b3af7a95790a16c97d6a5e` |
| [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng), arts. 51-55 | P3 | Articles 51-52 classify and designate systemic-risk general-purpose models. Articles 53-55 impose documentation, downstream transparency, evaluation, adversarial testing, risk mitigation, incident reporting, and cybersecurity duties. Treating this as a nonlicensing architecture is an inference from the enacted structure, not an express statutory rejection of licensing. | Stable official ELI and article locators; raw SHA-256 `null` because the official endpoint yielded no retained complete snapshot in this workspace |
| Jonas Schuett et al., [“From Principles to Rules: A Regulatory Approach for Frontier AI”](https://arxiv.org/abs/2407.07300) (2024) | P3 | PDF 54-57, printed 52-55, recommends binding high-level principles, close supervision, information access, corrective authority, third-party scrutiny, capacity building, and adaptive specificity. | Complete 59-page open PDF, SHA-256 `61465bd6200718ca135cba7df42bee15880c7ef9ce789284c03bff5b00e83f79` |
| [Executive Order 14409](https://www.whitehouse.gov/presidential-actions/2026/06/promoting-advanced-artificial-intelligence-innovation-and-security/), 91 Fed. Reg. 34,565 (2026) | P4 | PDF 2, section 3(b)-(c), establishes voluntary pre-release cooperation and disclaims mandatory licensing, preclearance, or permitting under that framework. Section 4 directs enforcement of existing criminal law. | Complete official 3-page PDF, SHA-256 `4a25c970947e7234f1a4308aca6aba62f327ac956de7caa41204c84f7f2cdcd9` |
| The White House, [*A National Policy Framework for Artificial Intelligence: Legislative Recommendations*](https://www.whitehouse.gov/releases/2026/03/president-donald-j-trump-unveils-national-ai-legislative-framework/) (March 2026) | P4 | PDF 3, section V, rejects a new federal AI rulemaking body and favors existing expert regulators and industry standards. PDF 4, section VII, preserves generally applicable state law while opposing state regulation of AI development. | Complete official 4-page PDF, SHA-256 `d4f8973f19d7318137ebba973d03ea63af032123d3e629b5d1831cd24af1d6c0` |
| NTIA, [*Dual-Use Foundation Models with Widely Available Model Weights Report*](https://www.ntia.gov/programs-and-initiatives/artificial-intelligence/open-model-weights-report) (July 2024) | Cross-cutting tradeoff evidence | PDF 38-39, printed 36-37, declines immediate weight restrictions and recommends continuous evaluation. PDF 42-48, printed 40-46, addresses downstream intervention while also recommending compelled audits and pre-release testing criteria for some models and preserving possible future access restrictions or licensing. | Complete official 71-page PDF, SHA-256 `f9234104727c0cee86cea71dad5aa705e47869dfa3a18db1f9ad0087bcffd04b` |
| UK AI Security Institute, [*Frontier AI Trends Report*](https://www.aisi.gov.uk/frontier-ai-trends-report) (2025) | Stakes | PDF 3-4 reports rapid capability growth, emerging expert-level performance, safeguard vulnerabilities, and a narrowed open-closed gap. PDF 14 and 25-26 show dual-use cyber and scientific stakes and persistent jailbreaks. | Complete 54-page compressed PDF linked by AISI, SHA-256 `6ed147b66f065722f038c6a933a4b8bb39af9ab2378a72fede629e203c0ab2ae` |

The source roles are deliberately narrow. Scholarship and enacted law establish coherent architectures. Current government documents establish live policy alternatives. NTIA supplies cross-cutting tradeoff evidence rather than a clean P4 exemplar. AISI establishes the stakes. None of these sources determines which architecture is best.

## Social significance and domain fit

The replacement repairs the three defects that made the quantum fallback unsuitable for public demonstration. Frontier AI governance bears directly on public safety, innovation, market concentration, civil liberties, and democratic control. The disagreement is current and consequential. A.G. can review it from his AI ethics and governance expertise, while the map remains concrete enough for reproducible coding.

The topic also gives Concordance something worth showing. Agreement may reveal how general-purpose models handle risk under uncertainty. Divergence may expose where they place the burden of proof, how they value competition, and how much institutional capacity they assume. Either result carries interpretive value.

## Stress test of position separability

The principal ambiguity lies between P2 and P3. Safety cases, audits, evaluations, or regulator review can sound like approval even when the law supplies no power to withhold release. The prompt defines licensing as permission that may be withheld, and the hierarchy follows that power. Review without a veto remains P3. A legal veto before release is P2.

The second ambiguity lies between P3 and P4. Both omit a licensing gate. A dedicated binding regime aimed upstream at frontier developers yields P3. Obligations tied to particular applications or supplied by ordinary bodies of law yield P4. Voluntary frontier coordination remains P4 unless binding upstream duties accompany it.

Hybrid answers remain codeable because the hierarchy assigns the earliest decisive permission gate. A training license dominates a release license. A release license dominates upstream supervision without permission. Dedicated binding upstream supervision dominates a use-centered architecture. Equal balancing and unresolved contingency remain null.

The map creates four plausible destinations, though no research-only design can guarantee sample dispersion. The frozen threshold, panel, and review chain must decide eligibility after blinded coding. Output may never be used to redraw these positions.

## Access and integrity conclusion

No university-library source is needed. The position map closes with official legal and policy texts plus complete open-access research artifacts. Seven complete external PDFs carry real SHA-256 digests. The EU AI Act carries a null digest and an explicit integrity limitation because no complete raw official artifact was retained. No hash has been guessed.

The exact machine-readable candidate is [frontier-ai-lifecycle-licensing.json](rule3-successor/questions/frontier-ai-lifecycle-licensing.json). The [source freeze](rule3-successor/source-freeze.json) binds claims, locators, URLs, access state, and integrity limits. Every question, position, source, and register verification status remains proposed.

## Remaining authorization boundary

The research package is ready for A.G.'s streamlined content approval. A later stage must freeze the exact protocol, panel, transport routes, prices, budget, review assets, parent lineage, and successor lock. A separate paid-run authorization must follow. No provider has been called for this candidate.
