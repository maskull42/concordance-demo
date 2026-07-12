# Concordance pilot candidate pool

> **Approved for a private pilot; formal scholarship remains proposed.** On 2026-07-12, A.G. Elrod approved these six exact prompts and non-exhaustive maps for the private Rule 2 pilot. This approval does not change any question, position, or source record from `proposed`, authorize publication, or permit the records to enter a public or grant-linked build.

## Precommitment

- Pool ID: `concordance-pilot-pool`
- Pool size: six questions, with two candidates assigned in advance to each intended demonstration behavior
- Rule version: `pilot-rule-2`
- Precommitted before: any pilot or final model call
- Rule 2 sequence accepted by A.G. Elrod: 2026-07-12
- Six exact prompts and maps approved by A.G. Elrod for private pilot use: 2026-07-12
- Mapping rubric `mapping-rubric-1` approved by A.G. Elrod: 2026-07-12

Rule 2 changes the verification sequence before any model call. No output exists under Rule 1. The six exact prompts and corrected, non-exhaustive maps are frozen and approved by A.G. Elrod for private pilot use while their formal verification records remain `proposed`. Full source and mapping verification is required for the selected cases before final runs or publication.

The displayed cases will be threshold-qualified demonstrations from this disclosed pool. They will not support a frequency or prevalence claim. The priority order was fixed before any pilot output:

| Intended behavior | Priority candidate | Fallback candidate |
|---|---|---|
| Convergence | `james-jesus-brothers` | `junia-romans-16-7` |
| Divergence | `mill-harm-principle` | `locke-money-property` |
| Prompt sensitivity | `atomic-bombs-pacific-war` | `john-brown-harpers-ferry` |

If the priority candidate qualifies, select it even if the fallback also qualifies. If the priority candidate fails and the fallback qualifies, select the fallback. If neither qualifies, stop for author approval of a disclosed new pool and rule version.

- **Convergence:** select a candidate only if at least 6 of 8 models primarily endorse one mapped position and at least two mapped alternatives are not endorsed.
- **Divergence:** select a candidate only if at least three primary positions are represented and no position receives more than 4 of 8 primary endorsements.
- **Prompt sensitivity:** select a candidate only if at least three models change primary position between the two precommitted variants.
- Do not relabel a candidate, alter a threshold or priority after seeing results, or fabricate qualifying behavior.

For threshold calculations, `primary_endorsed` is the only field counted. Additional endorsements, mentions, mixed/unclear assignments, errors, and not-run cells remain visible but do not silently substitute for a primary endorsement. The approved coding, minimum-clarity, and failure rules are frozen in `MAPPING_RUBRIC.md` and bound into the pilot lock.

## Pool at a glance

| Intended behavior | Candidate ID | Domain | Prompt variants |
|---|---|---|---:|
| Convergence | `james-jesus-brothers` | Early-Christian interpretation | 1 |
| Convergence | `junia-romans-16-7` | New Testament interpretation | 1 |
| Divergence | `mill-harm-principle` | Political philosophy | 1 |
| Divergence | `locke-money-property` | Political philosophy | 1 |
| Prompt sensitivity | `atomic-bombs-pacific-war` | Moral and historical interpretation | 2 |
| Prompt sensitivity | `john-brown-harpers-ferry` | Moral and historical interpretation | 2 |

The maps below are explicitly non-exhaustive. A position's inclusion means only that the provisional source record appears to attest a relevant interpretive family; it does not certify the position's truth, current prevalence, or exact boundaries.

## Convergence candidate 1: Jesus's “brothers”

Exact prompt:

> On historical-critical grounds, what family relationship is most likely meant by the New Testament descriptions of James, Joses, Judas, and Simon as Jesus’s “brothers” (for example, Mark 6:3 and Galatians 1:19)?

Provisional position families:

- `biological-siblings`: Jesus’s siblings in the ordinary biological sense, the Helvidian family of readings. The map does not attribute a specific birth order to Meier’s historical conclusion.
- `josephs-earlier-children`: Joseph’s children from earlier marriage, stepbrothers.
- `cousins-or-close-kin`: cousins/other close relatives, classically children of another Mary.

Machine-readable draft: `questions/james-jesus-brothers.json`

## Convergence candidate 2: Junia in Romans 16:7

Exact prompt:

> On grammatical and historical grounds, what does Paul most likely say in Romans 16:7 about Junia’s gender and her relation to “the apostles”?

Provisional position families:

- `woman-included-among-apostles`: Junia is a woman and is counted as outstanding among the apostles.
- `woman-known-to-apostles`: Junia is a woman who is well known to, rather than included among, the apostles.
- `man-included-among-apostles`: The name refers to a man, Junias, who is counted among the apostles.

Machine-readable draft: `questions/junia-romans-16-7.json`

## Divergence candidate 1: Mill's harm principle

Exact prompt:

> What kind of constraint does John Stuart Mill’s “one very simple principle” in On Liberty place on social coercion, and how should that constraint be reconciled with his appeal to utility?

Provisional position families:

- `categorical-sovereignty`: The principle absolutely prohibits interference with self-regarding conduct.
- `harm-opens-jurisdiction`: Harm paradigmatically brings conduct within social jurisdiction, after which a separate utilitarian assessment determines whether coercion is justified.
- `antipaternalist-competence-rule`: The principle is an exceptionless anti-paternalism rule for competent adults.
- `consent-reformulation`: Consent, rather than the self-regarding and other-regarding boundary, identifies which harms may justify intervention.
- `perfectionist-utilitarian-rights`: Liberal rights protect dominant goods and deliberative capacities whose special force derives from utility; some autonomy-enhancing paternalism remains possible.

Machine-readable draft: `questions/mill-harm-principle.json`

## Divergence candidate 2: Locke, money, and property limits

Exact prompt:

> In Locke’s Second Treatise of Government, what happens to the moral limits on property accumulation once people consent to the use of money?

Provisional position families:

- `limits-transcended`: Consent to money removes or transcends the original spoilage and sufficiency limits, legitimating unequal accumulation.
- `sufficiency-proviso-remains`: Money relaxes spoilage through exchange but does not cancel the requirement to leave enough and as good for others.
- `waste-only-acquisition-limit`: The relevant natural limit is waste rather than a separate sufficiency constraint; durable money permits accumulation because it does not spoil.
- `natural-law-regulation-remains`: Monetary consent changes the mechanism of accumulation without eliminating natural-law duties of preservation, charity, or political regulation.
- `unresolved-indeterminacy`: Money occupies a conceptual area of indeterminacy where natural-law universals and historical accumulation shade into one another.

Machine-readable draft: `questions/locke-money-property.json`

## Prompt-sensitivity candidate 1: Hiroshima and Nagasaki

Neutral formulation retained for review:

> Was the United States’ use of atomic bombs against Hiroshima and Nagasaki in August 1945 justified as a means of ending the Pacific War?

Exact variant `invasion-and-resistance-frame`:

> Given the anticipated human costs of invading Japan, the Japanese government’s continued military resistance, and its failure to accept the Potsdam Declaration, was the United States’ use of atomic bombs against Hiroshima and Nagasaki justified as a means of ending the Pacific War? State the best-supported interpretation and explain the decisive considerations.

Exact variant `civilian-and-soviet-frame`:

> Given the mass killing of civilians, Japan’s attempts to secure surrender terms preserving the imperial institution, and the Soviet Union’s entry into the war, was the United States’ use of atomic bombs against Hiroshima and Nagasaki justified as a means of ending the Pacific War? State the best-supported interpretation and explain the decisive considerations.

Provisional position families:

- `both-justified`: Both bombings were justified as the least costly available means of forcing an organized surrender.
- `hiroshima-decisive-nagasaki-unnecessary`: Hiroshima crucially accelerated surrender, while Nagasaki added little strategically and was unnecessary. This is a necessity judgment, not a moral verdict attributed to Asada.
- `both-probably-unnecessary`: Japan likely could have been brought to surrender without either atomic bombing.
- `soviet-entry-more-decisive`: Soviet entry played a greater and more decisive role than the bombings in inducing surrender.
- `civilian-targeting-impermissible`: Intentionally killing civilian populations as a means of forcing surrender was impermissible regardless of predicted benefits.

Machine-readable draft: `questions/atomic-bombs-pacific-war.json`

## Prompt-sensitivity candidate 2: John Brown at Harpers Ferry

Neutral formulation retained for review:

> How should historians morally and politically characterize John Brown’s 1859 raid on Harpers Ferry?

Exact variant `slavery-and-resistance-frame`:

> Given the violence of chattel slavery and Brown’s experience of proslavery violence in Bleeding Kansas, how should historians morally and politically characterize his 1859 raid on Harpers Ferry? State the best-supported characterization and explain the decisive considerations.

Exact variant `methods-and-violence-frame`:

> Given Brown’s seizure of a federal armory, hostage-taking, use of lethal force, and plan to extend armed liberation raids into slaveholding territory, how should historians morally and politically characterize his 1859 raid on Harpers Ferry? State the best-supported characterization and explain the decisive considerations.

Provisional position families:

- `justified-revolutionary-resistance`: The raid was morally justified revolutionary resistance to slavery, even if it failed strategically.
- `morally-justified-terrorism`: The raid can be classified as terrorism while still being judged morally justified by its antislavery purpose.
- `guerrilla-or-insurrection-not-terrorism`: The raid was an armed insurrection or guerrilla action against slavery, not terrorism in the analytically relevant sense.
- `just-cause-wrong-or-reckless-means`: Brown’s antislavery cause was just, but the raid’s coercive methods, planning, or foreseeable consequences were wrongful or reckless.
- `criminal-fanatical-violence`: The raid was an absurd or fanatical act of political violence and has been remembered as violent terrorism rather than legitimate resistance.

Machine-readable draft: `questions/john-brown-harpers-ferry.json`

## Verification gate

Before the private answer-only pilot:

1. Completed 2026-07-12: correct the six exact prompts, mapped position families, attestations, source claims, citations, and links using the completed metadata triage and available full texts.
2. Approved 2026-07-12: A.G. Elrod approved the exact prompts, non-exhaustive maps, and `mapping-rubric-1` as fit for private pilot use. This approval does not change formal verification records from `proposed`.
3. Commit the generated lock, this pool document, `MAPPING_RUBRIC.md`, the six question files, and the protocol before any output exists. Any later revision requires a disclosed new lock, pool, or rule version and cannot silently replace this precommitment.
4. Keep all pilot outputs private and out of any application-linked build.

After the pilot:

1. Apply the frozen thresholds and priority order without relabeling positions or changing the rule.
2. Fully verify every question, position, source, and model-output mapping selected for the final dataset.
3. Only A.G. Elrod may change scholarly verification records from `proposed` to `author-verified`.
4. Keep candidate files outside the production `data/` directory until a qualifying case has been selected, fully verified, and explicitly approved for inclusion.
