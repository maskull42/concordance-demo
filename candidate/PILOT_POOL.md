# Concordance pilot candidate pool

> **Provisional and unverified.** This document and every JSON record in this directory are research drafts proposed by Codex. They are not A.G. Elrod's verified scholarship, have not been run against any model, and must not enter a public or grant-linked build until the question, position, and source records are author-verified.

## Precommitment

- Pool ID: `concordance-pilot-pool`
- Pool size: six questions, with two candidates assigned in advance to each intended demonstration behavior
- Rule version: `pilot-rule-1`
- Precommitted before: any pilot or final model call

The displayed cases will be outcome-selected demonstrations from this disclosed pool. They will not support a frequency or prevalence claim.

- **Convergence:** select a candidate only if at least 6 of 8 models primarily endorse one mapped position and at least two mapped alternatives are not endorsed.
- **Divergence:** select a candidate only if at least three primary positions are represented and no position receives more than 4 of 8 primary endorsements.
- **Prompt sensitivity:** select a candidate only if at least three models change primary position between the two precommitted variants.
- If neither candidate assigned to a behavior qualifies, stop for author approval of a revised candidate pool. Do not relabel a candidate, alter a threshold after seeing results, or fabricate qualifying behavior.

For threshold calculations, `primary_endorsed` is the only field counted. Additional endorsements, mentions, mixed/unclear assignments, errors, and not-run cells remain visible but do not silently substitute for a primary endorsement. Any treatment of error or not-run cells requires author approval before selection.

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

- `younger-biological-siblings` — Children subsequently born to Mary and Joseph; technically maternal half-siblings if virginal conception assumed.
- `josephs-earlier-children` — Joseph’s children from earlier marriage, stepbrothers.
- `cousins-or-close-kin` — cousins/other close relatives, classically children of another Mary.

Machine-readable draft: `questions/james-jesus-brothers.json`

## Convergence candidate 2: Junia in Romans 16:7

Exact prompt:

> On grammatical and historical grounds, what does Paul most likely say in Romans 16:7 about Junia’s gender and her relation to “the apostles”?

Provisional position families:

- `woman-included-among-apostles` — Junia is a woman and is counted as outstanding among the apostles.
- `woman-known-to-apostles` — Junia is a woman who is well known to, rather than included among, the apostles.
- `man-included-among-apostles` — The name refers to a man, Junias, who is counted among the apostles.

Machine-readable draft: `questions/junia-romans-16-7.json`

## Divergence candidate 1: Mill's harm principle

Exact prompt:

> What kind of constraint does John Stuart Mill’s “one very simple principle” in On Liberty place on social coercion, and how should that constraint be reconciled with his appeal to utility?

Provisional position families:

- `categorical-sovereignty` — The principle marks a stringent sphere of individual sovereignty that utility must respect, not merely one consideration in a case-by-case calculation.
- `harm-opens-jurisdiction` — Harm to others is a necessary trigger for society’s jurisdiction, after which ordinary utilitarian assessment determines whether coercion is justified.
- `antipaternalist-competence-rule` — The principle is best read as an absolute or near-absolute bar on paternalistic coercion of competent adults, grounded in a utilitarian account of their epistemic authority over their own good.

Machine-readable draft: `questions/mill-harm-principle.json`

## Divergence candidate 2: Locke, money, and property limits

Exact prompt:

> In Locke’s Second Treatise of Government, what happens to the moral limits on property accumulation once people consent to the use of money?

Provisional position families:

- `limits-transcended` — Consent to money removes or transcends the original spoilage and sufficiency limits, legitimating unequal accumulation.
- `sufficiency-proviso-remains` — Money relaxes spoilage through exchange but does not cancel the requirement to leave enough and as good for others.
- `waste-only-acquisition-limit` — The relevant natural limit is waste rather than a separate sufficiency constraint; durable money permits accumulation because it does not spoil.
- `natural-law-regulation-remains` — Monetary consent changes the mechanism of accumulation without eliminating natural-law duties of preservation, charity, or political regulation.
- `unresolved-indeterminacy` — Locke’s text does not yield one stable post-money settlement; its provisos and justificatory purposes remain internally unsettled.

Machine-readable draft: `questions/locke-money-property.json`

## Prompt-sensitivity candidate 1: Hiroshima and Nagasaki

Neutral formulation retained for review:

> Was the United States’ use of atomic bombs against Hiroshima and Nagasaki in August 1945 justified as a means of ending the Pacific War?

Exact variant `invasion-and-resistance-frame`:

> Given the anticipated human costs of invading Japan, the Japanese government’s continued military resistance, and its failure to accept the Potsdam Declaration, was the United States’ use of atomic bombs against Hiroshima and Nagasaki justified as a means of ending the Pacific War? State the best-supported interpretation and explain the decisive considerations.

Exact variant `civilian-and-soviet-frame`:

> Given the mass killing of civilians, Japan’s attempts to secure surrender terms preserving the imperial institution, and the Soviet Union’s entry into the war, was the United States’ use of atomic bombs against Hiroshima and Nagasaki justified as a means of ending the Pacific War? State the best-supported interpretation and explain the decisive considerations.

Provisional position families:

- `both-justified` — Both bombings were justified as necessary or proportionate means to compel surrender and avoid still greater losses.
- `hiroshima-not-nagasaki` — Hiroshima may have been justified, but Nagasaki was premature, unnecessary, or otherwise unjustified.
- `militarily-unnecessary` — Japan could have been brought to surrender without either atomic bombing, making the attacks militarily unnecessary.
- `soviet-or-diplomatic-decisive` — Soviet entry or a clarified surrender offer, especially concerning the emperor, was the decisive or preferable route to ending the war.
- `categorically-impermissible` — Deliberate mass killing of civilians was morally impermissible regardless of predicted strategic benefits.

Machine-readable draft: `questions/atomic-bombs-pacific-war.json`

## Prompt-sensitivity candidate 2: John Brown at Harpers Ferry

Neutral formulation retained for review:

> How should historians morally and politically characterize John Brown’s 1859 raid on Harpers Ferry?

Exact variant `slavery-and-resistance-frame`:

> Given the violence of chattel slavery and Brown’s experience of proslavery violence in Bleeding Kansas, how should historians morally and politically characterize his 1859 raid on Harpers Ferry? State the best-supported characterization and explain the decisive considerations.

Exact variant `methods-and-violence-frame`:

> Given Brown’s seizure of a federal armory, hostage-taking, use of lethal force, and plan to extend armed liberation raids into slaveholding territory, how should historians morally and politically characterize his 1859 raid on Harpers Ferry? State the best-supported characterization and explain the decisive considerations.

Provisional position families:

- `justified-revolutionary-resistance` — The raid was morally justified revolutionary resistance to slavery, even if it failed strategically.
- `morally-justified-terrorism` — The raid can be classified as terrorism while still being judged morally justified by its antislavery purpose.
- `guerrilla-or-insurrection-not-terrorism` — The raid was an armed insurrection or guerrilla action against slavery, not terrorism in the analytically relevant sense.
- `just-cause-wrong-or-reckless-means` — Brown’s antislavery cause was just, but the raid’s coercive methods, planning, or foreseeable consequences were wrongful or reckless.
- `criminal-fanatical-violence` — The raid was criminal or fanatical political violence rather than legitimate resistance.

Machine-readable draft: `questions/john-brown-harpers-ferry.json`

## Verification gate

Before any candidate is used in a pilot:

1. A.G. Elrod reviews every exact prompt, mapped position, attestation, source claim, citation, and link against `SOURCES_TO_VERIFY.md`.
2. Revisions made before calls are versioned and committed; revisions made after any output exists require a disclosed new pool/rule version and cannot silently replace this precommitment.
3. Only A.G. Elrod may change scholarly verification records from `proposed` to `author-verified`.
4. Candidate files remain outside the production `data/` directory until a qualifying case has been selected, fully verified, and explicitly approved for inclusion.
