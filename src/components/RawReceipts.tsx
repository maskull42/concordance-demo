import type { SuccessCell } from "../lib/types";
import type { CaseViewModel, ModelViewState } from "../lib/view-model";

export function RawReceipts({ view }: { view: CaseViewModel }) {
  return (
    <section className="receipts-section" aria-labelledby={`${view.question.id}-receipts`}>
      <div className="subsection-heading">
        <div>
          <p className="micro-label">Raw receipts</p>
          <h4 id={`${view.question.id}-receipts`}>Inspect the sampled text</h4>
        </div>
        <p>
          Provider text is shown verbatim and inert. Human-authored mappings are
          labeled separately.
        </p>
      </div>
      <div className="receipt-list">
        {view.models.map((model) => (
          <Receipt key={model.model.model_key} model={model} view={view} />
        ))}
      </div>
    </section>
  );
}

function Receipt({ model, view }: { model: ModelViewState; view: CaseViewModel }) {
  const cell = model.cell;
  const parent =
    cell?.call_type === "challenge" && cell.parent_response_id
      ? view.run.cells.find(
          (candidate): candidate is SuccessCell =>
            candidate.status === "success" &&
            candidate.response_id === cell.parent_response_id,
        )
      : undefined;
  const status = !cell ? "Not run" : cell.status === "success" ? "Complete" : "Unavailable";

  return (
    <details className="receipt" data-model={model.model.model_key}>
      <summary>
        <span className="receipt-model">{model.model.family}</span>
        <span className={`receipt-status receipt-status--${status.toLowerCase().replace(" ", "-")}`}>
          {status}
        </span>
        <span className="receipt-summary-route">{model.model.requested_model_id}</span>
      </summary>
      <div className="receipt-body">
        {!cell ? (
          <p className="error-note">No response cell exists for this model and view.</p>
        ) : (
          <>
            <dl className="receipt-metadata">
              <Meta label="Provider" value={cell.provider} />
              <Meta label="Requested model" value={cell.requested_model_id} />
              <Meta
                label="Returned model"
                value={cell.status === "success" ? cell.provider_returned_model_id ?? "Not reported" : "No response"}
              />
              <Meta label="Route" value={model.model.route} />
              <Meta label="Call type" value={cell.call_type} />
              <Meta label="Variant" value={cell.variant_id} />
              <Meta label="Attempted" value={cell.attempted_at} />
              <Meta label="Attempts" value={String(cell.attempt_count)} />
              <Meta label="Run ID" value={view.run.run_id} code />
              <Meta label="Prompt SHA-256" value={cell.prompt_sha256} code />
              <Meta label="Question file SHA-256" value={view.run.question_file_sha256} code />
              <Meta label="Harness config SHA-256" value={view.run.harness_config_sha256} code />
              <Meta label="Model manifest SHA-256" value={view.run.model_manifest_file_sha256} code />
              <Meta label="Manifest captured" value={view.run.model_manifest_snapshot.captured_at} />
              <Meta label="Cell ID" value={cell.cell_id} code />
              {cell.parent_response_id ? (
                <Meta label="Parent response" value={cell.parent_response_id} code />
              ) : null}
            </dl>

            <MessageReceipt messages={cell.messages} />

            <div className="parameter-grid">
              <JsonReceipt label="Requested parameters" value={cell.requested_params} />
              {cell.status === "success" ? (
                <JsonReceipt label="Effective parameters" value={cell.effective_params} />
              ) : null}
            </div>

            {parent ? <ParentAnswer parent={parent} /> : null}

            {cell.status === "success" ? (
              <>
                <dl className="receipt-metadata receipt-metadata--compact">
                  <Meta label="Generated" value={cell.generated_at} />
                  <Meta label="Latency" value={`${cell.latency_ms} ms`} />
                  <Meta label="Finish reason" value={cell.finish_reason ?? "Not reported"} />
                  <Meta label="Provider response ID" value={cell.provider_response_id ?? "Not reported"} code />
                  <Meta label="Stable response ID" value={cell.response_id} code />
                  <Meta label="Input tokens" value={tokenValue(cell.usage.input_tokens)} />
                  <Meta label="Output tokens" value={tokenValue(cell.usage.output_tokens)} />
                  <Meta label="Reasoning tokens" value={tokenValue(cell.usage.reasoning_tokens)} />
                  <Meta label="Cache read tokens" value={tokenValue(cell.usage.cache_read_tokens)} />
                  <Meta label="Cache write tokens" value={tokenValue(cell.usage.cache_write_tokens)} />
                  <Meta label="Total tokens" value={tokenValue(cell.usage.total_tokens)} />
                  <Meta label="Cost" value={`$${cell.cost.usd.toFixed(6)} (${cell.cost.source})`} />
                  <Meta label="Pricing date" value={cell.cost.pricing_as_of} />
                </dl>
                <RawText label="Raw provider text — unedited" text={cell.response_text} />
              </>
            ) : (
              <div className="receipt-error" role="note">
                <p className="micro-label">Sanitized provider error</p>
                <p>{cell.error.sanitized_summary}</p>
                <p>{cell.error.category} · {cell.error.retryable ? "retryable" : "not retryable"}</p>
                <p>Failed at {cell.failed_at}</p>
              </div>
            )}

            <MappingReceipt model={model} view={view} />
          </>
        )}
      </div>
    </details>
  );
}

function MessageReceipt({ messages }: { messages: { role: string; content: string }[] }) {
  return (
    <section className="message-receipt">
      <p className="receipt-label">Exact request messages</p>
      <ol>
        {messages.map((message, index) => (
          <li key={`${message.role}-${index}`}>
            <span>{message.role}</span>
            <pre>{message.content}</pre>
          </li>
        ))}
      </ol>
    </section>
  );
}

function ParentAnswer({ parent }: { parent: SuccessCell }) {
  return (
    <details className="parent-answer">
      <summary>Linked initial answer: {parent.response_id}</summary>
      <dl className="receipt-metadata receipt-metadata--compact">
        <Meta label="Generated" value={parent.generated_at} />
        <Meta label="Prompt SHA-256" value={parent.prompt_sha256} code />
      </dl>
      <RawText label="Exact parent text supplied to the challenge" text={parent.response_text} />
    </details>
  );
}

function MappingReceipt({
  model,
  view,
}: {
  model: ModelViewState;
  view: CaseViewModel;
}) {
  const mapping = model.assignment;
  return (
    <section className="mapping-receipt">
      <p className="receipt-label">Human-authored mapping — separate from provider text</p>
      {mapping ? (
        <dl className="receipt-metadata receipt-metadata--compact">
          <Meta label="Mapping ID" value={view.mapping.mapping_id} code />
          <Meta label="Mapping version" value={view.mapping.mapping_version} />
          <Meta label="Rubric version" value={view.mapping.rubric_version} />
          <Meta label="Run file SHA-256" value={view.mapping.run_file_sha256} code />
          <Meta label="Primary endorsed" value={mapping.primary_endorsed ?? "Mixed / unclear"} />
          <Meta label="Also endorsed" value={mapping.also_endorsed.join(", ") || "None"} />
          <Meta label="Mentioned" value={mapping.mentioned.join(", ") || "None"} />
          <Meta label="Verification" value={mapping.verification.status} />
          <Meta label="Audit note" value={mapping.audit_note ?? "None"} />
        </dl>
      ) : (
        <p>No mapping exists because this cell is unavailable or not run.</p>
      )}
    </section>
  );
}

function RawText({ label, text }: { label: string; text: string }) {
  return (
    <section className="raw-text">
      <p className="receipt-label">{label}</p>
      <pre data-raw-response>{text}</pre>
    </section>
  );
}

function JsonReceipt({ label, value }: { label: string; value: unknown }) {
  return (
    <section className="json-receipt">
      <p className="receipt-label">{label}</p>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </section>
  );
}

function Meta({
  label,
  value,
  code = false,
}: {
  label: string;
  value: string;
  code?: boolean;
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{code ? <code>{value}</code> : value}</dd>
    </div>
  );
}

function tokenValue(value: number | null) {
  return value === null ? "Not reported" : String(value);
}
