'use strict';
// Translation between Anthropic Messages and OpenAI Chat Completions, and streaming.

const test = require('node:test');
const assert = require('node:assert/strict');
const T = require('../src/translate.js');
const S = require('../src/streams.js');

test('Anthropic request with tools and tool results becomes a chat request', () => {
  const body = {
    model: 'claude-x', max_tokens: 64000, system: [{ type: 'text', text: 'Be brief.' }], stream: true,
    tools: [{ name: 'Bash', description: 'run', input_schema: { type: 'object', properties: { cmd: { type: 'string' } } } }],
    tool_choice: { type: 'any' },
    messages: [
      { role: 'user', content: 'list files' },
      { role: 'assistant', content: [{ type: 'text', text: 'Sure.' }, { type: 'tool_use', id: 'toolu_1', name: 'Bash', input: { cmd: 'ls' } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: [{ type: 'text', text: 'a.txt' }] }, { type: 'text', text: 'thanks' }] },
    ],
  };
  const out = T.anthropicToOpenAI(body, 'near/model', { maxTokens: 32768, stream: false });
  assert.equal(out.model, 'near/model');
  assert.equal(out.max_tokens, 32768);
  assert.equal(out.stream, undefined);
  assert.deepEqual(out.messages[0], { role: 'system', content: 'Be brief.' });
  assert.equal(out.messages[2].tool_calls[0].function.arguments, '{"cmd":"ls"}');
  assert.deepEqual(out.messages[3], { role: 'tool', tool_call_id: 'toolu_1', content: 'a.txt' });
  assert.deepEqual(out.messages[4], { role: 'user', content: 'thanks' });
  assert.equal(out.tool_choice, 'required');
  assert.equal(out.tools[0].function.name, 'Bash');
});

test('chat completion with a tool call becomes an Anthropic message', () => {
  const msg = T.openAIToAnthropic({ choices: [{ message: { content: 'Running.', tool_calls: [{ id: 'call_1', function: { name: 'Bash', arguments: '{"cmd":"ls"}' } }] }, finish_reason: 'tool_calls' }], usage: { prompt_tokens: 9, completion_tokens: 3 } }, 'near/model');
  assert.equal(msg.stop_reason, 'tool_use');
  assert.deepEqual(msg.content[1], { type: 'tool_use', id: 'call_1', name: 'Bash', input: { cmd: 'ls' } });
  assert.deepEqual(msg.usage, { input_tokens: 9, output_tokens: 3 });
});

test('a finished message replays as a valid Anthropic event stream', () => {
  const msg = T.openAIToAnthropic({ choices: [{ message: { content: 'Hi', tool_calls: [{ id: 'c', function: { name: 'f', arguments: '{"a":1}' } }] }, finish_reason: 'tool_calls' }] }, 'm');
  const types = T.anthropicEventsFromMessage(msg).map((e) => e.event);
  assert.deepEqual(types, ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'content_block_start', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop']);
});

test('a finished completion replays as OpenAI chunks', () => {
  const chunks = T.openaiChunksFromCompletion({ id: 'x', model: 'm', choices: [{ index: 0, message: { content: 'yo', reasoning_content: 'think' }, finish_reason: 'stop' }], usage: { prompt_tokens: 1, completion_tokens: 1 } });
  assert.equal(chunks[0].choices[0].delta.content, 'yo');
  assert.equal(chunks[0].choices[0].delta.reasoning_content, 'think');
  assert.equal(chunks[1].choices[0].finish_reason, 'stop');
  assert.deepEqual(chunks[2].usage, { prompt_tokens: 1, completion_tokens: 1 });
});

test('stream translator turns chat chunks into Anthropic events with tool input deltas', () => {
  const tr = T.createStreamTranslator('m');
  const evs = [
    ...tr.push({ choices: [{ delta: { content: 'Hel' } }] }),
    ...tr.push({ choices: [{ delta: { content: 'lo' } }] }),
    ...tr.push({ choices: [{ delta: { tool_calls: [{ index: 0, id: 'c1', function: { name: 'Bash', arguments: '{"cmd"' } }] } }] }),
    ...tr.push({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: ':"ls"}' } }] }, finish_reason: 'tool_calls' }], usage: { prompt_tokens: 5, completion_tokens: 2 } }),
    ...tr.end(),
  ];
  const text = evs.filter((e) => e.data.delta && e.data.delta.type === 'text_delta').map((e) => e.data.delta.text).join('');
  const json = evs.filter((e) => e.data.delta && e.data.delta.type === 'input_json_delta').map((e) => e.data.delta.partial_json).join('');
  assert.equal(text, 'Hello');
  assert.deepEqual(JSON.parse(json), { cmd: 'ls' });
  assert.equal(evs.at(-2).data.delta.stop_reason, 'tool_use');
  assert.equal(evs.at(-1).event, 'message_stop');
});

test('SSE reader handles split chunks and CRLF, and reports raw bytes', async () => {
  const raw = [];
  async function* body() { yield Buffer.from('data: {"a":1}\r\n\r\nda'); yield Buffer.from('ta: [DONE]\n\n'); }
  const out = [];
  for await (const e of S.readSSE(body(), (c) => raw.push(c))) out.push(e.data);
  assert.deepEqual(out, ['{"a":1}', '[DONE]']);
  assert.equal(Buffer.concat(raw).toString(), 'data: {"a":1}\r\n\r\ndata: [DONE]\n\n');
});
