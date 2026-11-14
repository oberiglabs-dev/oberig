'use strict';
// OpenAI Responses API <-> Chat Completions. Codex speaks only the Responses API,
// so Oberig turns each request into a Chat Completions request for NEAR AI Cloud
// and the answer back into Responses items and events. The shield, the mask and
// the signature check then work on the same bytes as for every other agent.
// Nothing is stored: each request must carry its whole input (store: false).

const { genId, openaiChunksFromCompletion } = require('./translate.js');

/** One Chat Completions function name for a tool inside a namespace. */
function joinName(namespace, name) {
  if (!namespace) return String(name || '');
  return /_$/.test(namespace) ? `${namespace}${name}` : `${namespace}__${name}`;
}

const TEXT_PARTS = new Set(['input_text', 'output_text', 'text', 'summary_text', 'reasoning_text']);

function partText(p) {
  if (typeof p === 'string') return p;
  if (!p || typeof p !== 'object') return '';
  if (TEXT_PARTS.has(p.type) && typeof p.text === 'string') return p.text;
  if (p.type === 'refusal' && typeof p.refusal === 'string') return p.refusal;
  if (p.type === 'input_image') return '[image omitted]';
  if (p.type === 'input_file') return '[file omitted]';
  if (p.type === 'input_audio') return '[audio omitted]';
  return '';
}

function textOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.map(partText).filter((t) => t !== '').join('\n');
}

/** User content: plain text, or text and image parts when images are attached by URL. */
function userContent(content) {
  if (!Array.isArray(content)) return textOf(content);
  const parts = [];
  for (const p of content) {
    if (p && p.type === 'input_image' && typeof p.image_url === 'string' && p.image_url) parts.push({ type: 'image_url', image_url: { url: p.image_url } });
    else {
      const t = partText(p);
      if (t) parts.push({ type: 'text', text: t });
    }
  }
  return parts.every((p) => p.type === 'text') ? parts.map((p) => p.text).join('\n') : parts;
}

function outputText(output) {
  if (typeof output === 'string') return output;
  if (Array.isArray(output)) return textOf(output);
  if (output && typeof output === 'object') return typeof output.content === 'string' ? output.content : JSON.stringify(output);
  return output == null ? '' : String(output);
}

const CUSTOM_PARAMETERS = {
  type: 'object',
  properties: { input: { type: 'string', description: 'The whole input for this tool, as raw text.' } },
  required: ['input'],
  additionalProperties: false,
};

function customDescription(t) {
  const f = t.format;
  let d = t.description || '';
  d += `${d ? '\n\n' : ''}Pass the whole input as the "input" string.`;
  if (f && f.type === 'grammar' && typeof f.definition === 'string') d += ` It must follow this ${f.syntax || ''} grammar:\n${f.definition}`;
  return d;
}

/**
 * Responses tools -> Chat Completions functions. Function and custom (freeform) tools
 * are kept, namespaces are flattened. Hosted tools (web search, file search, image
 * generation and the like) are dropped: NEAR AI Cloud runs only the model.
 */
function buildTools(tools) {
  const list = [];
  const byName = new Map();
  const add = (raw, namespace, nsDescription) => {
    if (!raw || typeof raw !== 'object') return;
    const t = raw.type === 'function' && raw.function && !raw.name ? { ...raw.function, type: 'function' } : raw;
    if (typeof t.name !== 'string' || !t.name) return;
    const name = joinName(namespace, t.name);
    if (t.type === 'custom') {
      list.push({ type: 'function', function: { name, description: customDescription(t), parameters: CUSTOM_PARAMETERS } });
      byName.set(name, { kind: 'custom', name: t.name, namespace: namespace || null });
    } else if (t.type === 'function' || t.type === undefined) {
      list.push({ type: 'function', function: { name, description: t.description || nsDescription || '', parameters: t.parameters || { type: 'object', properties: {} } } });
      byName.set(name, { kind: 'function', name: t.name, namespace: namespace || null });
    }
  };
  for (const t of Array.isArray(tools) ? tools : []) {
    if (t && t.type === 'namespace' && Array.isArray(t.tools)) for (const inner of t.tools) add(inner, t.name, t.description);
    else add(t, null);
  }
  return { list, byName };
}

function mapToolChoice(tc) {
  if (typeof tc === 'string') return ['auto', 'none', 'required'].includes(tc) ? tc : undefined;
  if (!tc || typeof tc !== 'object') return undefined;
  if ((tc.type === 'function' || tc.type === 'custom') && tc.name) return { type: 'function', function: { name: joinName(tc.namespace, tc.name) } };
  if (tc.type === 'allowed_tools') return tc.mode === 'required' ? 'required' : 'auto';
  return undefined;
}

/**
 * Responses request body -> Chat Completions request body.
 * Returns { request, ctx }; ctx maps tool names back when the answer is translated.
 */
function responsesToChat(body, model, { maxTokens } = {}) {
  if (body.previous_response_id) {
    throw Object.assign(new Error('previous_response_id is not supported, because Oberig stores nothing. Send the whole conversation in input (store: false).'), { status: 400 });
  }
  const tools = buildTools(body.tools);
  const system = [];
  if (typeof body.instructions === 'string' && body.instructions.trim()) system.push(body.instructions);
  const messages = [];
  const called = new Set();
  let open = null; // the assistant message being built (text and tool calls of one step)
  const flush = () => { if (open) { messages.push(open); open = null; } };
  const call = (id, name, args) => {
    if (!open) open = { role: 'assistant', content: null };
    if (!open.tool_calls) open.tool_calls = [];
    const callId = typeof id === 'string' && id ? id : genId('call');
    open.tool_calls.push({ id: callId, type: 'function', function: { name, arguments: args } });
    called.add(callId);
  };
  const result = (id, text) => {
    flush();
    // A tool message must follow the call it answers; an orphan result goes in as plain text.
    if (id && called.has(id)) messages.push({ role: 'tool', tool_call_id: id, content: text });
    else messages.push({ role: 'user', content: `Tool result:\n${text}` });
  };

  const input = typeof body.input === 'string' ? [{ type: 'message', role: 'user', content: body.input }] : Array.isArray(body.input) ? body.input : [];
  for (const item of input) {
    if (!item || typeof item !== 'object') continue;
    const type = item.type || (item.role ? 'message' : '');
    if (type === 'message') {
      if (item.role === 'system' || item.role === 'developer') {
        // One leading system message: some chat templates refuse a system message later on.
        const t = textOf(item.content);
        if (t) system.push(t);
      } else if (item.role === 'assistant') {
        const t = textOf(item.content);
        if (!t) continue;
        if (open && open.tool_calls) flush();
        if (!open) open = { role: 'assistant', content: null };
        open.content = open.content ? `${open.content}\n\n${t}` : t;
      } else {
        flush();
        const c = userContent(item.content);
        if (c.length) messages.push({ role: 'user', content: c });
      }
    } else if (type === 'function_call') {
      call(item.call_id, joinName(item.namespace, item.name), typeof item.arguments === 'string' ? item.arguments : JSON.stringify(item.arguments ?? {}));
    } else if (type === 'custom_tool_call') {
      call(item.call_id, joinName(item.namespace, item.name), JSON.stringify({ input: typeof item.input === 'string' ? item.input : '' }));
    } else if (type === 'function_call_output' || type === 'custom_tool_call_output') {
      result(item.call_id, outputText(item.output));
    } else if (type === 'agent_message') {
      flush();
      const t = textOf(item.content);
      if (t) messages.push({ role: 'user', content: t });
    }
    // Reasoning, hosted tool calls, compaction blobs and item references carry nothing NEAR AI can use.
  }
  flush();

  const request = { model, messages: system.length ? [{ role: 'system', content: system.join('\n\n') }, ...messages] : messages };
  if (tools.list.length) {
    request.tools = tools.list;
    const choice = mapToolChoice(body.tool_choice);
    if (choice) request.tool_choice = choice;
  }
  if (Number.isInteger(body.max_output_tokens) && body.max_output_tokens > 0) {
    request.max_tokens = maxTokens ? Math.min(body.max_output_tokens, maxTokens) : body.max_output_tokens;
  }
  for (const k of ['temperature', 'top_p']) if (typeof body[k] === 'number') request[k] = body[k];
  const fmt = body.text && body.text.format;
  if (fmt && fmt.type === 'json_schema' && fmt.schema) {
    request.response_format = { type: 'json_schema', json_schema: { name: fmt.name || 'output', schema: fmt.schema, ...(typeof fmt.strict === 'boolean' ? { strict: fmt.strict } : {}) } };
  } else if (fmt && fmt.type === 'json_object') request.response_format = { type: 'json_object' };

  const ctx = { tools: tools.byName, model, toolChoice: typeof body.tool_choice === 'string' ? body.tool_choice : 'auto', parallelToolCalls: body.parallel_tool_calls !== false };
  return { request, ctx };
}

function usageOf(u) {
  u = u || {};
  const input = u.prompt_tokens || 0;
  const output = u.completion_tokens || 0;
  return {
    input_tokens: input,
    input_tokens_details: { cached_tokens: (u.prompt_tokens_details && u.prompt_tokens_details.cached_tokens) || 0 },
    output_tokens: output,
    output_tokens_details: { reasoning_tokens: (u.completion_tokens_details && u.completion_tokens_details.reasoning_tokens) || 0 },
    total_tokens: u.total_tokens || input + output,
  };
}

function customInput(args) {
  try {
    const v = JSON.parse(args);
    if (v && typeof v === 'object' && typeof v.input === 'string') return v.input;
    if (typeof v === 'string') return v;
  } catch { /* not JSON: pass it on as written */ }
  return args;
}

function shell(ctx) {
  return {
    id: genId('resp'), object: 'response', created_at: Math.floor(Date.now() / 1000), status: 'in_progress',
    error: null, incomplete_details: null, model: ctx.model, output: [], parallel_tool_calls: ctx.parallelToolCalls !== false,
    previous_response_id: null, store: false, tool_choice: ctx.toolChoice || 'auto', tools: [], usage: null, metadata: {},
  };
}

/**
 * Turns Chat Completions stream chunks into Responses stream events.
 * Call push(chunk) for each parsed `data:` object (placeholders already restored), then end().
 * Output items come in the order the model produced them: reasoning, message, tool calls.
 */
function createStreamTranslator(ctx) {
  let seq = 0;
  const ev = (type, data) => ({ event: type, data: { type, sequence_number: seq++, ...data } });
  const head = shell(ctx);
  const items = [];
  const calls = new Map();
  let started = false;
  let reasoning = null;
  let message = null;
  let finish = null;
  let usage = null;

  const start = (out) => {
    if (started) return;
    started = true;
    out.push(ev('response.created', { response: head }), ev('response.in_progress', { response: head }));
  };
  const closeReasoning = (out) => {
    if (!reasoning) return;
    const r = reasoning;
    reasoning = null;
    r.item.content = [{ type: 'reasoning_text', text: r.text }];
    out.push(ev('response.reasoning_text.done', { item_id: r.item.id, output_index: r.index, content_index: 0, text: r.text }));
    out.push(ev('response.output_item.done', { output_index: r.index, item: r.item }));
  };
  const openMessage = (out) => {
    message = { item: { id: genId('msg'), type: 'message', status: 'in_progress', role: 'assistant', content: [] }, index: items.length, text: '' };
    items.push(message.item);
    out.push(ev('response.output_item.added', { output_index: message.index, item: { ...message.item, content: [] } }));
    out.push(ev('response.content_part.added', { item_id: message.item.id, output_index: message.index, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } }));
  };
  const closeMessage = (out) => {
    if (!message) return;
    const m = message;
    message = null;
    const part = { type: 'output_text', text: m.text, annotations: [] };
    m.item.status = 'completed';
    m.item.content = [part];
    out.push(ev('response.output_text.done', { item_id: m.item.id, output_index: m.index, content_index: 0, text: m.text }));
    out.push(ev('response.content_part.done', { item_id: m.item.id, output_index: m.index, content_index: 0, part }));
    out.push(ev('response.output_item.done', { output_index: m.index, item: m.item }));
  };
  const closeCalls = (out) => {
    for (const c of calls.values()) {
      if (c.done) continue;
      c.done = true;
      c.item.status = 'completed';
      if (c.item.type === 'custom_tool_call') {
        c.item.input = customInput(c.args);
        out.push(ev('response.custom_tool_call_input.done', { item_id: c.item.id, call_id: c.item.call_id, output_index: c.index, input: c.item.input }));
      } else {
        c.item.arguments = c.args;
        out.push(ev('response.function_call_arguments.done', { item_id: c.item.id, output_index: c.index, arguments: c.args }));
      }
      out.push(ev('response.output_item.done', { output_index: c.index, item: c.item }));
    }
  };

  return {
    push(chunk) {
      const out = [];
      start(out);
      if (chunk.usage) usage = chunk.usage;
      const choice = (chunk.choices || []).find((c) => (c.index ?? 0) === 0);
      if (!choice) return out;
      const d = choice.delta || {};
      const think = typeof d.reasoning_content === 'string' ? d.reasoning_content : typeof d.reasoning === 'string' ? d.reasoning : '';
      if (think) {
        if (!reasoning) {
          reasoning = { item: { id: genId('rs'), type: 'reasoning', summary: [], content: [], encrypted_content: null }, index: items.length, text: '' };
          items.push(reasoning.item);
          out.push(ev('response.output_item.added', { output_index: reasoning.index, item: { ...reasoning.item, content: [] } }));
        }
        reasoning.text += think;
        out.push(ev('response.reasoning_text.delta', { item_id: reasoning.item.id, output_index: reasoning.index, content_index: 0, delta: think }));
      }
      if (typeof d.content === 'string' && d.content) {
        closeReasoning(out);
        if (!message) openMessage(out);
        message.text += d.content;
        out.push(ev('response.output_text.delta', { item_id: message.item.id, output_index: message.index, content_index: 0, delta: d.content }));
      }
      for (const tc of d.tool_calls || []) {
        closeReasoning(out);
        closeMessage(out);
        const k = tc.index ?? 0;
        let c = calls.get(k);
        if (!c) {
          const fnName = (tc.function && tc.function.name) || '';
          const spec = ctx.tools.get(fnName) || { kind: 'function', name: fnName, namespace: null };
          const custom = spec.kind === 'custom';
          const item = { id: genId(custom ? 'ctc' : 'fc'), type: custom ? 'custom_tool_call' : 'function_call', status: 'in_progress', call_id: tc.id || genId('call'), name: spec.name };
          if (spec.namespace) item.namespace = spec.namespace;
          if (custom) item.input = ''; else item.arguments = '';
          c = { item, index: items.length, args: '', done: false };
          items.push(item);
          calls.set(k, c);
          out.push(ev('response.output_item.added', { output_index: c.index, item: { ...item } }));
        }
        const piece = tc.function && typeof tc.function.arguments === 'string' ? tc.function.arguments : '';
        if (piece) {
          c.args += piece;
          if (c.item.type === 'function_call') out.push(ev('response.function_call_arguments.delta', { item_id: c.item.id, output_index: c.index, delta: piece }));
        }
      }
      if (choice.finish_reason) finish = choice.finish_reason;
      return out;
    },
    end() {
      const out = [];
      start(out);
      closeReasoning(out);
      closeMessage(out);
      closeCalls(out);
      if (!items.some((i) => i.type !== 'reasoning')) { openMessage(out); closeMessage(out); }
      const reason = finish === 'length' ? 'max_output_tokens' : finish === 'content_filter' ? 'content_filter' : null;
      const response = { ...head, status: reason ? 'incomplete' : 'completed', incomplete_details: reason ? { reason } : null, output: items, usage: usageOf(usage) };
      out.push(ev(reason ? 'response.incomplete' : 'response.completed', { response }));
      return out;
    },
  };
}

/** A finished chat completion as the full Responses event sequence. */
function eventsFromCompletion(resp, ctx) {
  const tr = createStreamTranslator(ctx);
  const out = [];
  // Some servers name the reasoning field `reasoning` instead of `reasoning_content`.
  const choices = (resp.choices || []).map((c) => {
    const m = c && c.message;
    if (!m || typeof m.reasoning !== 'string' || typeof m.reasoning_content === 'string') return c;
    return { ...c, message: { ...m, reasoning_content: m.reasoning } };
  });
  for (const chunk of openaiChunksFromCompletion({ ...resp, choices })) out.push(...tr.push(chunk));
  out.push(...tr.end());
  return out;
}

/** A finished chat completion as one Responses object (non-streaming). */
function responseFromCompletion(resp, ctx) {
  const events = eventsFromCompletion(resp, ctx);
  return events[events.length - 1].data.response;
}

/** Error code a Responses client understands for an upstream or local failure. */
function errorCode(status, message) {
  if (/context[ _-]?(length|window)|maximum context|too many tokens|prompt is too long/i.test(String(message))) return 'context_length_exceeded';
  if (status === 429) return 'rate_limit_exceeded';
  if (status === 402) return 'insufficient_quota';
  if (status >= 400 && status < 500) return 'invalid_prompt';
  return 'server_error';
}

/** The event that ends a stream when NEAR AI Cloud fails after the stream has started. */
function failedEvent(status, message, model) {
  const response = { ...shell({ model }), status: 'failed', error: { code: errorCode(status, message), message } };
  return { event: 'response.failed', data: { type: 'response.failed', sequence_number: 0, response } };
}

module.exports = {
  responsesToChat, createStreamTranslator, eventsFromCompletion, responseFromCompletion, errorCode, failedEvent, buildTools, joinName,
};
