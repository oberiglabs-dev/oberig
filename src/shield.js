/*
 * Oberig shield: finds hidden instructions in content an agent is about to
 * send to a model (tool results, web pages, READMEs, issues, emails, files).
 *
 *   scan(text, {scope, mode}) -> {findings, clean, changed, count}
 *     scope 'full'   (tool results): every rule
 *     scope 'hidden' (text the user typed): only rules for hidden content
 *     mode 'block' returns `clean` with hidden parts removed or neutralised
 *     and one short note for the model at the top; other modes return text unchanged.
 *   reveal(text) -> text with invisible characters shown as <U+XXXX>
 *
 * Pure and dependency-free (UMD). The same file runs in Node and in the browser.
 * It is a pattern scanner: it raises the cost of common tricks, it does not
 * understand intent, and it can miss new phrasings.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.OberigShield = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var NOTE = '[oberig: removed hidden instructions from this content]';
  var CUT = '[oberig: removed instruction]';
  var CUT_LINK = '[oberig: removed link]';

  var LABELS = {
    'html-comment': 'HTML comment with instructions',
    'md-comment': 'markdown comment with instructions',
    'css-hidden': 'CSS-hidden text with instructions',
    'invisible': 'zero-width or invisible characters',
    'unicode-tags': 'Unicode tag characters (hidden text)',
    'bidi': 'bidirectional control characters',
    'override': 'instruction override',
    'remote-exec': 'instruction to run a remote script',
    'exfil-link': 'link or image that sends data out'
  };

  // ---- instruction-like text (used for hidden regions) ----
  var STRONG = [
    /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:instructions?|prompts?|rules?|guidelines?|above|previous|prior)\b/i,
    /\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:ai|assistant|agent|language model|llm|chatbot)\b/i,
    /\b(?:ai|llms?|assistants?|agents?|bots?|models?|claude|codex|copilot|chatgpt|gpt|cursor|gemini|opencode)\b[^.\n]{0,60}\b(?:must|should|shall|need to|have to|are required|always|never|do not|don't)\b/i,
    /\b(?:note|attention|message|instructions?|important)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:ai|llm|assistant|agent|model|bot)s?\b/i,
    /\bif\s+you\s+are\s+(?:an?\s+)?(?:ai|llm|assistant|agent|language model|bot)\b/i,
    /\bsystem\s+prompt\b/i,
    /\b(?:run|execute|exec|eval)\b[^.\n]{0,60}\b(?:command|script|shell|terminal|curl|wget|bash|powershell|payload)\b/i,
    /\b(?:curl|wget|iwr|invoke-webrequest)\s+\S+/i,
    /\b(?:send|upload|post|exfiltrate|leak|email|forward|transmit|paste)\b[^\n]{0,60}?(?:\b(?:secrets?|keys?|tokens?|passwords?|credentials?|ssh|cookies?|environment|private)\b|\.env\b|id_rsa|~\/\.)/i,
    /\b(?:read|cat|open|print|output|reveal|show|dump)\b[^\n]{0,40}?(?:~\/|\.env\b|id_rsa|\.ssh|\bsecrets?\b|\bcredentials?\b|private keys?\b|api keys?\b|passwords?\b)/i,
    /^\s*(?:dear\s+|note\s+to\s+(?:the\s+)?|attention\s+)?(?:ai|assistants?|agents?|llms?|claude|codex|copilot|chatgpt|gpt|cursor|gemini|opencode)(?:\s+(?:agents?|assistants?|models?))?\s*[,:]/i,
    /\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show|alert)\b[^.\n]{0,30}\buser\b/i,
    /\b(?:secretly|silently|quietly|covertly)\b/i,
    /\bwithout\s+(?:telling|asking|informing|notifying|alerting)\b/i,
    /(?:\brm\s+-rf\b|\bdrop\s+table\b|\bgit\s+push\s+--force\b)/i
  ];
  var WEAK = /(?:^|[.!?;\n]\s*)(?:please\s+)?(?:run|execute|send|delete|remove|insert|write|open|read|print|output|reply|respond|say|tell|include|append|download|install|fetch|visit|navigate|click|call|post|upload|copy|replace|grant|approve|merge|push|commit)\s+\w+/i;
  var TOOLING = /^\s*(?:markdownlint|prettier|eslint|textlint|cspell|spell-?checker|all-contributors|toc\b|tocstop|omit in toc|vale|dprint|deno-fmt|badges?\b|@?generated|auto-?generated|do not edit|spdx|copyright|license)/i;

  function words(s) { return (String(s).match(/[A-Za-zÀ-ɏЀ-ӿ]{2,}/g) || []).length; }

  function isInstruction(s) {
    var t = String(s || '');
    for (var i = 0; i < STRONG.length; i++) if (STRONG[i].test(t)) return true;
    if (TOOLING.test(t)) return false;
    return words(t) >= 8 && WEAK.test(t);
  }

  // ---- characters ----
  var INVIS_RUN = /[​-‏⁠-⁤᠎﻿­͏]{2,}|[​⁠-⁤᠎﻿]/g;
  var BIDI = /[‪-‮⁦-⁩]+/g;
  var TAGS = /(?:\uDB40[\uDC00-\uDC7F])+/g; // U+E0000..U+E007F as surrogate pairs (works without the u flag)

  function hex(cp) { return 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'); }

  function reveal(s) {
    return String(s).replace(/[​-‏⁠-⁤᠎﻿­͏‪-‮⁦-⁩]|\uDB40[\uDC00-\uDC7F]/g, function (ch) {
      return '<' + hex(ch.codePointAt(0)) + '>';
    });
  }

  function decodeTags(run) {
    var out = '';
    for (var i = 0; i < run.length; i += 2) {
      var cp = run.codePointAt(i) - 0xE0000;
      if (cp >= 0x20 && cp < 0x7F) out += String.fromCharCode(cp);
    }
    return out;
  }

  // ---- visible directives ----
  var OVERRIDE = [
    /\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|the|your|these|those|my|of|every)\s+){0,3}(?:previous|prior|above|earlier|preceding|former|original|system|developer|safety|initial|other)\s+(?:instructions?|prompts?|messages?|rules?|directions?|guidelines?|context|guidance|constraints?)\b/gi,
    /\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+(?:above|before|you(?:'ve| have) been told|previously)\b/gi,
    /\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|god|unrestricted|admin)\b/gi,
    /\b(?:new|updated|real|actual)\s+(?:system\s+)?instructions?\s*:/gi,
    /<\|im_start\|>|<\|im_end\|>|\[\/?INST\]|<<\/?SYS>>|<\/?system>/gi,
    /\b(?:do\s+not|don't|never)\s+(?:tell|inform|alert|notify)\s+the\s+user\b/gi
  ];
  var REMOTE = [
    /\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/gi,
    /\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b/gi,
    /\b(?:bash|sh|zsh)\s+(?:-c\s+)?["']?(?:\$\(|<\()\s*(?:curl|wget)\b[^\n]{0,200}/gi,
    /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(?:iex|invoke-expression)\b/gi,
    /\b(?:iex|invoke-expression)\s*\(?\s*(?:\(?\s*new-object\s+net\.webclient\)?\.downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,200}/gi,
    /\bpowershell(?:\.exe)?\s+[^\n]{0,40}-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{20,}/gi
  ];
  var AGENT_CUE = [
    /(?:^|[.!?\n]\s*)(?:dear\s+|note\s+to\s+(?:the\s+)?|attention\s+)?(?:ai|assistants?|agents?|models?|llms?|claude|codex|copilot|chatgpt|gpt|cursor|opencode)(?:\s+agents?|\s+assistants?|\s+models?)?\s*[,:]/i,
    /\b(?:ai|assistants?|agents?|models?|llms?|claude|codex|copilot|chatgpt|gpt|cursor|opencode)\s+(?:must|should|shall|needs? to|has to|have to|is required to|are required to|will now|please)\b/i,
    /\b(?:silently|quietly|secretly|covertly)\b/i,
    /\bwithout\s+(?:asking|telling|confirm\w*|prompting|informing)\b/i,
    /\bdo\s+not\s+(?:tell|mention|ask|inform)\b/i,
    /\bbefore\s+(?:answering|responding|replying|you\s+(?:answer|respond|reply|continue))\b/i,
    /\bignore\s+(?:the|all|any|previous|prior|above|your)\b/i,
    /\bimmediately\s+(?:run|execute)\b/i
  ];
  function agentCue(s) { for (var i = 0; i < AGENT_CUE.length; i++) if (AGENT_CUE[i].test(s)) return true; return false; }

  // ---- links ----
  var MD_IMAGE = /!\[[^\]\n]{0,200}\]\(\s*<?(https?:\/\/[^)\s>]{1,2000})>?(?:\s+"[^"\n]*")?\s*\)/gi;
  var MD_LINK = /(?:^|[^!])\[[^\]\n]{1,200}\]\(\s*<?(https?:\/\/[^)\s>]{1,2000})>?(?:\s+"[^"\n]*")?\s*\)/gi;
  var HTML_IMG = /<img\b[^>]{0,500}?\bsrc\s*=\s*["'](https?:\/\/[^"']{1,2000})["'][^>]{0,500}>/gi;
  var SAFE_PARAMS = /^(?:style|branch|logo|logocolor|color|label|labelcolor|cacheseconds|link|v|version|sanitize|raw|width|height|w|h|s|size|format|auto|fit|q|quality|ixlib|ixid|fm|crop|dpr|theme|t|ref|tab|path|file|lang|locale|utm_[a-z]+|event|workflow|query|search|page|sort|per_page|plastic|flat)$/i;
  var TEMPLATE = /[{}$<>]|%7B|%7D|%24|%3C|%3E|\b(?:INSERT|REPLACE|SECRETS?|CONVERSATION|HISTORY|CONTEXT|API_?KEY|TOKEN|PASSWORD|DATA)\b/;
  var SECRETISH = /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.)/;

  function suspiciousUrl(url, strict) {
    var q = url.indexOf('?');
    if (q === -1) return false;
    var query = url.slice(q + 1).split('#')[0];
    if (SECRETISH.test(query)) return true;
    var pairs = query.split('&');
    for (var i = 0; i < pairs.length; i++) {
      var eq = pairs[i].indexOf('=');
      var key = eq === -1 ? pairs[i] : pairs[i].slice(0, eq);
      var val = eq === -1 ? '' : pairs[i].slice(eq + 1);
      if (TEMPLATE.test(val)) return true;
      if (SAFE_PARAMS.test(key)) continue;
      if (/^(?:data|d|q|c|secret|token|key|password|payload|leak|exfil|env|content|msg|message|info|x)$/i.test(key) && val.length >= (strict ? 24 : 12)) return true;
      if (!strict && val.length >= 32 && /^[A-Za-z0-9+\/=_%.-]+$/.test(val)) return true;
    }
    return false;
  }

  function lineOf(text, index) {
    var n = 1;
    for (var i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
    return n;
  }

  function sentenceAround(text, start, end) {
    var s = start;
    var e = end;
    var lim = Math.max(0, start - 300);
    while (s > lim && !/[.!?\n]/.test(text[s - 1])) s--;
    var lim2 = Math.min(text.length, end + 300);
    while (e < lim2 && !/[.!?\n]/.test(text[e])) e++;
    if (e < text.length && /[.!?]/.test(text[e])) e++;
    while (s < start && /\s/.test(text[s])) s++;
    return [s, e];
  }

  function stripTags(s) { return String(s).replace(/<[^>]{0,500}>/g, ' '); }

  var HIDDEN_STYLE = /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|em|rem|pt|%)?\s*(?:;|$|!)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$|!)|(?:^|;)\s*(?:max-)?height\s*:\s*0(?:px)?\s*;[^"']{0,200}overflow\s*:\s*hidden|(?:left|top|text-indent)\s*:\s*-\d{3,}px|clip\s*:\s*rect\(\s*0|color\s*:\s*transparent/i;

  function cssHidden(text, add) {
    var open = /<([a-zA-Z][a-zA-Z0-9-]{0,20})\b([^<>]{0,1000})>/g;
    var m;
    while ((m = open.exec(text)) !== null) {
      var tag = m[1].toLowerCase();
      var attrs = m[2];
      if (attrs.slice(-1) === '/') continue;
      var style = /\bstyle\s*=\s*(["'])([\s\S]*?)\1/i.exec(attrs);
      var hidden = (style && HIDDEN_STYLE.test(style[2])) || /(?:^|\s)hidden(?:\s|=|$)/i.test(attrs);
      if (!hidden) continue;
      // find the matching close tag (same name, counting nesting)
      var re = new RegExp('<(/?)' + tag + '\\b[^>]{0,1000}>', 'gi');
      re.lastIndex = open.lastIndex;
      var depth = 1;
      var end = -1;
      var t;
      while ((t = re.exec(text)) !== null) {
        if (t[1]) depth--; else if (t[0].slice(-2) !== '/>') depth++;
        if (depth === 0) { end = re.lastIndex; break; }
        if (re.lastIndex - m.index > 20000) break;
      }
      if (end === -1) continue;
      var inner = stripTags(text.slice(open.lastIndex, end));
      if (words(inner) >= 3 && isInstruction(inner)) {
        add('css-hidden', m.index, end, null);
        open.lastIndex = end;
      }
    }
  }

  function scan(text, opts) {
    opts = opts || {};
    var src = typeof text === 'string' ? text : String(text == null ? '' : text);
    var full = opts.scope !== 'hidden';
    var findings = [];
    var cuts = [];
    function add(rule, start, end, hiddenText, replacement) {
      findings.push({ rule: rule, label: LABELS[rule], start: start, end: end, line: lineOf(src, start), excerpt: reveal(src.slice(start, end)).slice(0, 160), hidden: hiddenText || null });
      cuts.push({ start: start, end: end, rep: replacement || '' });
    }
    var m;

    // HTML comments carrying instructions
    var hc = /<!--([\s\S]*?)-->/g;
    while ((m = hc.exec(src)) !== null) {
      if (isInstruction(m[1])) add('html-comment', m.index, m.index + m[0].length, m[1].trim().slice(0, 300));
    }
    // Markdown reference-style comments: [//]: # (text)
    var mc = /^[ \t]*\[(?:\/\/|comment|#)\]:[ \t]*(?:#|<>)[ \t]*(?:\(([^)\n]*)\)|"([^"\n]*)"|'([^'\n]*)')[ \t]*$/gim;
    while ((m = mc.exec(src)) !== null) {
      var body = m[1] || m[2] || m[3] || '';
      if (isInstruction(body)) add('md-comment', m.index, m.index + m[0].length, body.slice(0, 300));
    }
    if (/<[a-zA-Z]/.test(src)) cssHidden(src, add);

    // Invisible characters, tag characters, bidi controls
    INVIS_RUN.lastIndex = 0;
    while ((m = INVIS_RUN.exec(src)) !== null) {
      if (m.index === 0 && m[0] === '﻿') continue; // byte order mark
      add('invisible', m.index, m.index + m[0].length, m[0].length + ' invisible characters');
    }
    TAGS.lastIndex = 0;
    while ((m = TAGS.exec(src)) !== null) {
      var before = m.index >= 2 ? src.codePointAt(m.index - 2) : 0;
      if (before === 0x1F3F4 && /^(?:\uDB40[\uDC30-\uDC39\uDC61-\uDC7A]){2,6}󠁿$/.test(m[0])) continue; // subdivision flag emoji
      add('unicode-tags', m.index, m.index + m[0].length, decodeTags(m[0]));
    }
    BIDI.lastIndex = 0;
    while ((m = BIDI.exec(src)) !== null) add('bidi', m.index, m.index + m[0].length, m[0].length + ' control characters');

    if (full) {
      var i, re, span;
      for (i = 0; i < OVERRIDE.length; i++) {
        re = OVERRIDE[i];
        re.lastIndex = 0;
        while ((m = re.exec(src)) !== null) {
          span = sentenceAround(src, m.index, m.index + m[0].length);
          add('override', span[0], span[1], null, CUT);
        }
      }
      for (i = 0; i < REMOTE.length; i++) {
        re = REMOTE[i];
        re.lastIndex = 0;
        while ((m = re.exec(src)) !== null) {
          // context: this line and the line before it
          var lineStart = src.lastIndexOf('\n', m.index - 1) + 1;
          var prevStart = lineStart > 0 ? src.lastIndexOf('\n', lineStart - 2) + 1 : lineStart;
          var lineEnd = src.indexOf('\n', m.index + m[0].length);
          // the line before only counts when the command starts its own line ("AI agents:\ncurl ... | sh")
          var startsLine = /^[\s`$>]*$/.test(src.slice(lineStart, m.index));
          var context = src.slice(startsLine ? prevStart : lineStart, lineEnd === -1 ? src.length : lineEnd);
          if (!agentCue(context.replace(m[0], ' '))) continue;
          span = sentenceAround(src, m.index, m.index + m[0].length);
          add('remote-exec', span[0], span[1], null, CUT);
        }
      }
      MD_IMAGE.lastIndex = 0;
      while ((m = MD_IMAGE.exec(src)) !== null) if (suspiciousUrl(m[1], false)) add('exfil-link', m.index, m.index + m[0].length, null, CUT_LINK);
      HTML_IMG.lastIndex = 0;
      while ((m = HTML_IMG.exec(src)) !== null) if (suspiciousUrl(m[1], false)) add('exfil-link', m.index, m.index + m[0].length, null, CUT_LINK);
      MD_LINK.lastIndex = 0;
      while ((m = MD_LINK.exec(src)) !== null) {
        var off = m[0].charAt(0) === '[' ? 0 : 1;
        if (suspiciousUrl(m[1], true)) add('exfil-link', m.index + off, m.index + m[0].length, null, CUT_LINK);
      }
    }

    // Keep one finding per region: drop findings fully inside an earlier, larger one.
    var order = findings.map(function (f, k) { return k; }).sort(function (a, b) {
      return findings[a].start - findings[b].start || (findings[b].end - findings[b].start) - (findings[a].end - findings[a].start);
    });
    var keptF = [];
    var keptC = [];
    var lastEnd = -1;
    for (var k = 0; k < order.length; k++) {
      var f = findings[order[k]];
      if (f.start < lastEnd) continue;
      keptF.push(f);
      keptC.push(cuts[order[k]]);
      lastEnd = f.end;
    }

    var clean = src;
    var changed = false;
    if (opts.mode === 'block' && keptF.length) {
      for (var j = keptC.length - 1; j >= 0; j--) clean = clean.slice(0, keptC[j].start) + keptC[j].rep + clean.slice(keptC[j].end);
      clean = NOTE + '\n' + clean;
      changed = true;
    }
    return { findings: keptF, count: keptF.length, clean: clean, changed: changed };
  }

  return { scan: scan, reveal: reveal, isInstruction: isInstruction, NOTE: NOTE, LABELS: LABELS, version: '0.1.0' };
});
