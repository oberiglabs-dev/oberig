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
 *   isInstruction(text) -> true when (hidden) text reads like an instruction to an agent
 *
 * JSON tool results are read through their string escapes, so an encoder that
 * writes "<" or an invisible character as a unicode escape does not hide it.
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
    'hidden-attr': 'alt, title or similar attribute with instructions',
    'invisible': 'zero-width or invisible characters',
    'unicode-tags': 'Unicode tag characters (hidden text)',
    'bidi': 'bidirectional control characters',
    'override': 'instruction override',
    'remote-exec': 'instruction to run a remote script',
    'exfil-link': 'link or image that sends data out'
  };

  // ---- characters (built from code points, so this file has no invisible characters) ----
  function ch(n) { return String.fromCharCode(n); }
  function span(a, b) { return ch(a) + '-' + ch(b); }
  var HI = ch(0xDB40); // high surrogate of U+E0000..U+E01FF
  // zero-width and invisible: U+200B..U+200F, U+2060..U+2064, U+180E, U+FEFF, U+00AD, U+034F,
  // variation selectors U+FE00..U+FE0F and U+E0100..U+E01EF
  var INVIS_CLASS = span(0x200B, 0x200F) + span(0x2060, 0x2064) + ch(0x180E) + ch(0xFEFF) + ch(0x00AD) + ch(0x034F) + span(0xFE00, 0xFE0F);
  var VS_SUPP = HI + '[' + span(0xDD00, 0xDDEF) + ']';
  var BIDI_CLASS = span(0x202A, 0x202E) + span(0x2066, 0x2069);
  // Runs of four or more. Ordinary text (emoji sequences, Persian ZWNJ, soft hyphens,
  // anchor spacers) uses these one or two at a time; hidden payloads need long runs.
  var INVIS_RUN = new RegExp('(?:[' + INVIS_CLASS + ']|' + VS_SUPP + '){4,}', 'g');
  var INVIS_ANY = new RegExp('[' + INVIS_CLASS + ']|' + VS_SUPP, 'g');
  var BIDI = new RegExp('[' + BIDI_CLASS + ']+', 'g');
  var TAGS = new RegExp('(?:' + HI + '[' + span(0xDC00, 0xDC7F) + '])+', 'g'); // U+E0000..U+E007F
  var FLAG_TAGS = new RegExp('^(?:' + HI + '[' + span(0xDC30, 0xDC39) + span(0xDC61, 0xDC7A) + ']){2,6}' + HI + ch(0xDC7F) + '$'); // subdivision flags
  // what reveal() shows (the emoji presentation selectors U+FE0E/U+FE0F are left alone)
  var REVEAL = new RegExp('[' + span(0x200B, 0x200F) + span(0x2060, 0x2064) + ch(0x180E) + ch(0xFEFF) + ch(0x00AD) + ch(0x034F) + span(0xFE00, 0xFE0D) + BIDI_CLASS + ']|' + HI + '[' + span(0xDC00, 0xDC7F) + span(0xDD00, 0xDDEF) + ']', 'g');
  var LETTERS = new RegExp('[A-Za-z' + span(0xC0, 0x24F) + span(0x370, 0x3FF) + span(0x400, 0x4FF) + span(0x590, 0x6FF) + span(0x900, 0x97F) + ']{2,}', 'g');
  var CJK = new RegExp('[' + span(0x3040, 0x30FF) + span(0x3400, 0x9FFF) + span(0xAC00, 0xD7AF) + ']', 'g');

  function hex(cp) { return 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'); }

  function reveal(s) {
    return String(s).replace(REVEAL, function (c) { return '<' + hex(c.codePointAt(0)) + '>'; });
  }

  function decodeTags(run) {
    var out = '';
    for (var i = 0; i < run.length; i += 2) {
      var cp = run.codePointAt(i) - 0xE0000;
      if (cp >= 0x20 && cp < 0x7F) out += String.fromCharCode(cp);
    }
    return out;
  }

  // word count; CJK, kana and Hangul count one word per two characters
  function words(s) {
    var t = String(s);
    return (t.match(LETTERS) || []).length + Math.floor((t.match(CJK) || []).length / 2);
  }

  var ENTITY = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  // text as a reader would take it: no invisible characters, entities decoded, spaces collapsed
  function plain(s) {
    return String(s == null ? '' : s)
      .replace(INVIS_ANY, '')
      .replace(/&(?:#(\d{1,7})|#x([0-9a-f]{1,6})|(amp|lt|gt|quot|apos|nbsp));/gi, function (m, d, x, n) {
        if (n) return ENTITY[n.toLowerCase()];
        var cp = d ? parseInt(d, 10) : parseInt(x, 16);
        return cp > 0 && cp < 0x110000 ? String.fromCodePoint(cp) : m;
      })
      .replace(/\s+/g, ' ')
      .trim();
  }

  // ---- does a hidden text read like an instruction to an agent? ----
  // Words for an AI agent in several languages. Group 1 of every rule that uses it.
  var AG = '(' + [
    '\\b(?:llms?|gpts?|chatgpt|claude|codex|copilot|cursor|gemini|opencode|devin|aider|windsurf|cline|chat-?bots?|bots?)\\b',
    '\\bassist(?:ant|ent|ente)[a-z]*\\b', '\\basist(?:ente|ent|en|an)[a-z]*', '\\basysten[a-z]*\\b',
    '\\bagent(?:s|e|en|es|i)?\\b', '\\bajan[a-z]*',
    '\\b(?:language|coding|ai)\\s+models?\\b', '\\bsprachmodell[a-z]*', '\\btaalmodel[a-z]*', '\\bmod(?:e|è)le\\s+de\\s+langage',
    '\\bmodelo\\s+de\\s+(?:lenguaje|linguagem)', '\\bmodello\\s+linguistico', '\\byapay\\s+zek(?:a|â)',
    '\\bautomated\\s+(?:reviewers?|tools?|systems?|agents?|assistants?)\\b',
    '\\b(?:ai|a\\.i\\.|ki|ia)\\b', '(?:^|[^а-яёіїєґ])(?:ии|ші)(?![а-яёіїєґ])',
    'ассистент', 'асистент', 'агент', 'помощник', 'помічник', 'языков\\S*\\s+модел', 'мовн\\S*\\s+модел', 'нейросет',
    '助手', '智能体', '语言模型', '大模型', '人工智能', 'アシスタント', 'エージェント', '言語モデル', '人工知能',
    '어시스턴트', '에이전트', '언어\\s?모델', '인공지능', 'مساعد', 'الذكاء الاصطناعي', 'نموذج لغوي'
  ].join('|') + ')';

  // short acronyms (AI, KI, IA, ИИ) count only in capitals: "ai" is also an Italian word
  function agentOk(term) {
    var letters = String(term || '').replace(/[^A-Za-zА-Яа-яЁёІіЇї]/g, '');
    return letters.length > 2 || letters === letters.toUpperCase();
  }
  function agentHit(re, t, check) {
    re.lastIndex = 0;
    var m;
    while ((m = re.exec(t)) !== null) {
      if (agentOk(m[1]) && (!check || check(m))) return true;
      re.lastIndex = m.index + 1;
    }
    return false;
  }

  var SB = '(?:^|[.!?;\\n。！？]\\s*|[:：]\\s+)';
  var TOK = '[^\\s.!?:;,，：。]{1,24}';
  var GLUE = '[^\\s.!?:;,，：。]{0,8}';
  var AGN = AG.replace(/^\(/, '(?:');
  // "Copilot, ...", "Coding agent: ...", "Note for the AI assistant: ...", "致 AI 助手：..."
  // (the agent word ends the address; "Guided AI operator: ..." is a label, not an address)
  var ADDRESS = new RegExp(SB + '(?:' + TOK + '\\s+){0,3}?[^\\s.!?:;,，：。]{0,3}?' + AG + GLUE + '(?:[\\s-]+' + AGN + GLUE + '){0,2}\\s*[:,，：]\\s*([^\\n]{0,80})', 'gi');
  // what follows the address must read like an order
  var ORDER = new RegExp('^(?:please\\s+|kindly\\s+|now\\s+|also\\s+|first,?\\s+|then\\s+|immediately\\s+)?(?:(?:' + [
    'run|execute|exec|send|upload|post|delete|remove|add|insert|append|write|rewrite|replace|modify|change|update|open|read|print|output|reveal|show|list|dump',
    'reply|respond|answer|say|tell|recommend|include|download|install|fetch|visit|navigate|click|call|copy|paste|grant|approve|merge|push|commit|close|label',
    'disable|enable|skip|ignore|forget|disregard|export|email|forward|create|set|use|summari[sz]e|keep|never|always|do\\s+not|don\'t|before|when|from\\s+now\\s+on'
  ].join('|') + ')\\b|' + [
    'lies|füge|führe|sende|schick|lösche|entferne|installiere|ändere|ersetze|öffne|gib|sag|empfiehl|ignoriere|vergiss',
    'lis|ajoute|exécute|envoie|supprime|installe|modifie|remplace|ouvre|affiche|dis\\b|recommande|ignore|oublie',
    'lee|añade|agrega|ejecuta|envía|envia|borra|elimina|instala|cambia|reemplaza|abre|muestra|dile|recomienda|ignora|olvida',
    'leia|adicione|execute|envie|apague|remova|instale|altere|substitua|abra|mostre|diga|recomende|faça|faca|rode',
    'leggi|aggiungi|esegui|invia|cancella|installa|modifica|sostituisci|apri|mostra|raccomanda|dimentica',
    'lees|voeg|voer|stuur|verwijder|installeer|wijzig|vervang|toon|zeg|negeer|vergeet',
    'przeczytaj|dodaj|wykonaj|uruchom|wyślij|wyslij|usuń|usun|zainstaluj|zmień|zmien|zamień|otwórz|pokaż|powiedz|zignoruj',
    'pročitaj|procitaj|izvrši|izvrsi|pokreni|pošalji|posalji|obriši|obrisi|izbriši|instaliraj|promijeni|zamijeni|otvori|prikaži|reci|zanemari',
    'прочитай|добавь|выполни|запусти|отправь|удали|установи|измени|замени|открой|покажи|скажи|игнорируй|забудь|выведи',
    'додай|виконай|надішли|видали|встанови|зміни|заміни|відкрий|ігноруй|тихо',
    'oku|ekle|çalıştır|gönder|sil\\b|kur\\b|değiştir|göster|söyle',
    '请|在回答|读取|运行|执行|发送|删除|添加|告诉|忽略|回答する|最初に|実行|送信|削除|追加|사용자에게|실행|전송|삭제|추가|설치|أرسل|نفذ|احذف|أضف|تجاهل'
  ].join('|') + ')|\\b(?:you|your)\\s+(?:must|should|shall|need|have\\s+to|are\\s+(?:now|required|authori[sz]ed|allowed)|will\\s+now|may\\s+now)\\b|\\b(?:authori[sz]ed|allowed|permitted|instructed|required)\\s+you\\b', 'i');
  // "the agent must ...", "Copilot should ..."
  var MODAL = new RegExp(AG + '[^.!?\\n]{0,40}?\\b(?:must|should|shall|needs?\\s+to|ha(?:ve|s)\\s+to|(?:is|are)\\s+(?:required|expected|authori[sz]ed|allowed|instructed)\\s+to|will\\s+now|may\\s+now|always|never|do\\s+not|don\'t|please)\\b', 'gi');
  var IFYOU = new RegExp('\\bif\\s+you\\s*(?:are|\'re)\\s+(?:an?\\s+|the\\s+)?(?:[a-z-]+\\s+){0,2}?' + AG, 'gi');
  var NOTE_FOR = new RegExp('\\b(?:note|notes|attention|message|instructions?|important)\\s+(?:to|for)\\s+(?:all\\s+|any\\s+|every\\s+|the\\s+)?(?:[a-z-]+\\s+){0,2}?' + AG, 'gi');
  var ROLE = /\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:[a-z-]+\s+)?(?:ai|assistant|agent|language model|llm|chatbot)\b/i;

  // overriding earlier instructions, fake chat-template markers
  var OVR = [
    /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:instructions?|prompts?|rules?|guidelines?|directions?|directives?|guidance|constraints?|above|previous|prior|earlier)\b/i,
    /\b(?:previous|prior|earlier|above|original|system|developer)\s+(?:instructions?|prompts?|rules?|guidelines?|messages?)\s+(?:are|is)\s+(?:void|null|cancel+ed|obsolete|invalid|revoked)\b/i,
    /\b(?:instructions?|guidelines?|rules?)\s+(?:no\s+longer|do\s+not|don't)\s+apply\b/i,
    /\btreat\s+this\s+(?:comment|note|text|file|message|page)\s+as\s+(?:the\s+|a\s+)?(?:system|developer)\b/i,
    /(?:^|\n)\s*(?:\[\s*)?(?:SYSTEM|DEVELOPER)\s*(?:\]|:)/,
    /###\s*(?:new|updated|system|developer)\s+(?:instructions?|message|prompt)/i,
    /\b(?:new|updated|real|actual)\s+(?:system\s+)?instructions?\s*:/i,
    /<\|im_start\|>|<\|im_end\|>|\[\/?INST\]|<<\/?SYS>>|<\/?system>/i,
    /\b(?:ignorier\w*|vergiss|vergessen\s+sie|missachte\w*)\b[^.\n]{0,40}(?:anweisung|instruktion|regel|vorgabe|befehl)/i,
    /\b(?:ignore[zr]?|oublie[zr]?)\b[^.\n]{0,40}(?:instructions?|consignes?|r(?:è|e)gles?|directives?)/i,
    /\b(?:ignor[ae]\w*|olvida\w*|esque(?:ç|c)a\w*|desconsider\w*|dimentica\w*)\b[^.\n]{0,40}(?:instruc|instru(?:ç|c)|istruzion|indicaci|regla|regra|regol|directri|diretriz)/i,
    /\b(?:negeer|vergeet)\b[^.\n]{0,40}(?:instructie|regel|aanwijzing)/i,
    /\b(?:zignoruj|ignoruj|zapomnij)\b[^.\n]{0,40}(?:instrukcj|polece|zasad|wytyczn)/i,
    /\b(?:zanemari\w*|ignori(?:š|s)i|ignoriraj\w*|zaboravi\w*)\b[^.\n]{0,40}(?:upute|uputstv|instrukcij|pravil|naredb)/i,
    /(?:игнорир|проигнорир|забудь|ігнор|проігнор|не\s+обращай)[^.\n]{0,40}(?:инструкц|указани|правил|промпт|інструкц|вказівк)/i,
    /(?:talimat|kural|komut)[^.\n]{0,30}(?:yok\s+say|görmezden\s+gel|unut)/i,
    /(?:忽略|无视|忘记|忘掉|不要理会)[^。\n]{0,20}(?:指令|指示|规则|提示|说明|设定)/,
    /(?:指示|命令|ルール|プロンプト)[^。\n]{0,20}(?:無視|忘れ)/,
    /(?:지시|지침|명령|규칙|프롬프트)[^.\n]{0,20}(?:무시|잊)/,
    /(?:تجاهل|انس)[^.\n]{0,40}(?:التعليمات|الأوامر|القواعد|تعليمات)/
  ];
  // hiding things from the person
  var SECRECY = [
    /\b(?:do|must|should)\s+not\s+(?:tell|inform|mention|reveal|show|alert|notify)\b[^.\n]{0,40}\b(?:user|human|anyone|this|it)\b/i,
    /\b(?:don't|never)\s+(?:tell|inform|mention|reveal|show|alert|notify)\b[^.\n]{0,40}\b(?:user|human|anyone|this|it)\b/i,
    /\bwithout\s+(?:telling|asking|informing|notifying|alerting|mentioning|confirm\w*)\b/i,
    /\b(?:secretly|silently|quietly|covertly|discreetly)\s+(?:\w+\s+){0,2}?(?:run|execute|send|add|install|replace|upload|delete|remove|commit|push|change|modify|insert|append|copy|post|download|update|rewrite)\b/i,
    /\b(?:run|execute|send|add|install|replace|upload|delete|commit|push|insert|append)\b[^.\n]{0,60}\b(?:secretly|silently|quietly|covertly)\b/i,
    /\bkeep\s+this\s+(?:secret|hidden)\b/i,
    /\b(?:erw(?:ä|ae)hne|sag)\b[^.\n]{0,30}\bnicht\b/i, /\bohne\s+(?:es\s+)?(?:dem\s+)?(?:nutzer|benutzer|anwender)/i,
    /\bsans\s+(?:le\s+dire|pr(?:é|e)venir|en\s+informer|demander)/i, /\bne\s+(?:le\s+)?(?:dis|mentionne)\s+pas\b/i,
    /\bsin\s+(?:dec(?:í|i)rselo|avisar|informar|preguntar)/i, /\bno\s+(?:se\s+lo\s+)?(?:digas|menciones)\b/i,
    /\bsem\s+(?:pedir|avisar|informar|perguntar)/i, /\bsenza\s+(?:dirlo|avvisare|chiedere)/i, /\bnon\s+(?:dirlo|menzionare)/i,
    /(?:не\s+упоминай|не\s+говори|не\s+сообщай|незаметно|не\s+кажи|непомітно|тихо\s+замін)/i,
    /\bnie\s+(?:m(?:ó|o)w|wspominaj|informuj)\b/i, /\bnoem\b[^.\n]{0,30}\bniet\b/i, /\bzonder\s+(?:het\s+)?(?:te\s+)?(?:zeggen|vragen|melden)/i,
    /\bne\s+(?:spominji|govori|reci)\b/i, /\bbez\s+(?:da\s+)?(?:pita|ka(?:ž|z)e)/i,
    /(?:belirtme|söyleme|haber\s+verme)\b/i,
    /(?:不要|别|勿)(?:提及|提到|告诉|透露|通知)|悄悄|偷偷|暗中/, /(?:知らせず|伝えず|言わず|内緒|こっそり)/, /(?:알리지\s*말|말하지\s*말|몰래)/, /(?:لا\s+تخبر|دون\s+(?:إخبار|علم))/
  ];
  // addressed to whoever writes the reply
  var REPLY = [
    /\b(?:when|before|after|while)\s+(?:you\s+)?(?:reply|respond|answer|summari[sz]e|writ(?:e|ing)\s+(?:your|the)\s+(?:answer|reply|response|summary))/i,
    /\bin\s+your\s+(?:reply|response|answer|summary)\b/i,
    /\b(?:at\s+the\s+)?(?:end|start|top|bottom)\s+of\s+(?:your|each|every)\s+(?:answer|reply|response)\b/i,
    /\bbefore\s+(?:answering|responding|replying|you\s+(?:answer|respond|reply|continue|do\s+anything)|doing\s+anything\s+else|running\s+any(?:thing|\s+other))/i,
    /\b(?:print|reveal|show|output|repeat|dump|leak)\s+(?:your|the)\s+(?:system\s+prompt|instructions|hidden\s+(?:prompt|instructions))/i,
    /\b(?:in\s+deine[rn]?\s+antwort|vor\s+(?:der|deiner)\s+antwort|bevor\s+du\s+antwortest)/i,
    /\b(?:avant\s+de\s+r(?:é|e)pondre|dans\s+ta\s+r(?:é|e)ponse|quand\s+tu\s+r(?:é|e)sumes)/i,
    /\b(?:antes\s+de\s+responder|en\s+tu\s+respuesta)/i, /\b(?:quando\s+riassumi|prima\s+di\s+rispondere|nella\s+tua\s+risposta)/i,
    /(?:перед\s+ответом|в\s+конце\s+ответа|в\s+(?:своём|своем|твоём|твоем)\s+ответе)/i, /\bprije\s+odgovora\b/i,
    /(?:在回答之前|回答前|回复里|回答末尾|回复中)/, /(?:回答する前に|回答の最後)/, /قبل\s+الرد/
  ];
  // telling the person something on someone else's behalf
  var DECEIVE = [
    /\b(?:tell|inform|assure|convince|remind)\s+the\s+user\b/i,
    /\bdis\s+(?:à\s+)?l'utilisateur/i, /скажи\s+пользовател/i, /告诉用户/, /zeg\s+tegen\s+de\s+gebruiker/i,
    /(?:sag|teile)\s+dem\s+(?:nutzer|benutzer)/i, /dile\s+al\s+usuario/i, /kullan(?:ı|i)c(?:ı|i)ya[^.\n]{0,40}s(?:ö|o)yle/i
  ];
  // running remote code, reading or sending secrets (language-independent parts)
  var REMOTE_H = [
    /\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/i,
    /\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b/i,
    /\b(?:bash|sh|zsh)\s+(?:-c\s+)?["']?(?:\$\(|<\()\s*(?:curl|wget)\b/i,
    /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(?:iex|invoke-expression)\b/i,
    /\b(?:iex|invoke-expression)\s*\(?\s*(?:\(?\s*new-object\s+net\.webclient\)?\.downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i,
    /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,80}https?:\/\//i
  ];
  var SECRET = [
    /\b(?:send|upload|post|exfiltrate|leak|email|forward|transmit|paste|copy|append|attach|export|pipe)\b[^\n]{0,60}?(?:\b(?:secrets?|api[\s_-]?keys?|tokens?|passwords?|credentials?|cookies?|private\s+keys?|deploy\s+keys?|ssh\s+keys?|environment\s+variables?)\b|\.env\b|id_rsa|id_ed25519|~\/\.)/i,
    /\b(?:read|cat|open|print|output|reveal|show|dump|list|display)\b[^\n]{0,40}?(?:~\/|\.env\b|id_rsa|id_ed25519|\.ssh\b|\.aws\b|\bsecrets?\b|\bcredentials?\b|private\s+keys?\b|api\s+keys?\b|passwords?\b|environment\s+variables?\b)/i,
    /(?:~\/\.ssh|id_rsa|id_ed25519|~\/\.aws|\.aws\/credentials|\.git-credentials|\.netrc|\.env\b)[^\n]{0,120}?(?:https?:\/\/|\b[\w.+-]+@[\w-]+\.[\w.]+)/i
  ];

  function any(list, t) { for (var i = 0; i < list.length; i++) if (list[i].test(t)) return true; return false; }

  // opts.strict: only the signals that address an agent (used for UI panels such as tabs,
  // which legitimately hide install commands until clicked)
  function isInstruction(s, opts) {
    var t = plain(s);
    if (t.length < 8) return false;
    if (agentHit(ADDRESS, t, function (m) { return ORDER.test(m[2]); })) return true;
    if (agentHit(MODAL, t) || agentHit(IFYOU, t) || agentHit(NOTE_FOR, t) || ROLE.test(t)) return true;
    if (any(OVR, t) || any(SECRECY, t) || any(REPLY, t) || any(DECEIVE, t)) return true;
    if (opts && opts.strict) return false;
    return any(REMOTE_H, t) || any(SECRET, t);
  }

  // ---- visible directives (tool results only) ----
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
  var MD_DEF = /^[ \t]{0,3}\[[^\]\n]{1,100}\]:[ \t]*<?(https?:\/\/[^\s>]{1,2000})>?/gim;
  var HTML_IMG = /<img\b[^>]{0,500}?\bsrc\s*=\s*["'](https?:\/\/[^"']{1,2000})["'][^>]{0,500}>/gi;
  var SAFE_PARAMS = /^(?:style|branch|logo|logocolor|logowidth|color|colora|colorb|label|labelcolor|message|cacheseconds|cache_seconds|link|v|version|sanitize|raw|width|height|w|h|s|u|size|format|auto|fit|q|quality|ixlib|ixid|fm|crop|dpr|theme|t|ref|tab|path|file|lang|locale|utm_[a-z]+|event|workflow|job|query|search|page|page_id|sort|per_page|plastic|flat|url|server|repos?|type|id|user|username|owner|name|title|prefix|suffix|include_prereleases|filter|tag|display_name|display_timestamp|show_icons|hide|hide_border|layout|langs_count|count_private|include_all_commits|bg_color|title_color|text_color|icon_color|border_color|legend|tomlfilepath|registry_uri)$/i;
  var EXFIL_KEYS = /^(?:data|d|c|secret|token|key|password|payload|leak|exfil|env|content|msg|info|x)$/i;
  var TEMPLATE = /[{}<>]|%7B|%7D|%3C|%3E|\$\{|\$[A-Z_]{3,}|%24[A-Z_]{3,}|\b(?:INSERT|REPLACE|SECRETS?|CONVERSATION|HISTORY|CONTEXT|API_?KEY|TOKEN|PASSWORD|DATA)\b/;
  // links (clicked, not loaded) often prefill an issue body with markup; only placeholders count there
  var TEMPLATE_LINK = /[{}]|%7B|%7D|\$\{|\$[A-Z_]{3,}|%24[A-Z_]{3,}|\b(?:INSERT|REPLACE|SECRETS?|CONVERSATION|HISTORY|CONTEXT|API_?KEY|TOKEN|PASSWORD|DATA)\b/;
  // signed image URLs carry long random tokens that are not conversation data
  var SIGNATURE_KEY = /token|sig|signature|hash|policy|credential|expires|nonce/i;
  var SECRETISH = /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.)/;

  function suspiciousUrl(url, strict) {
    url = url.replace(/&amp;/gi, '&');
    var q = url.indexOf('?');
    if (q === -1) return false;
    var query = url.slice(q + 1).split('#')[0];
    if (SECRETISH.test(query)) return true;
    var pairs = query.split('&');
    for (var i = 0; i < pairs.length; i++) {
      var eq = pairs[i].indexOf('=');
      var key = eq === -1 ? pairs[i] : pairs[i].slice(0, eq);
      var val = eq === -1 ? '' : pairs[i].slice(eq + 1);
      if ((strict ? TEMPLATE_LINK : TEMPLATE).test(val)) return true;
      if (SAFE_PARAMS.test(key)) continue;
      var dec = val;
      try { dec = decodeURIComponent(val.replace(/\+/g, ' ')); } catch (e) { /* keep raw */ }
      // nested URLs (badges, redirects), hex ids and hashes, UUIDs carry no conversation data
      if (/^(?:https?|ftp):/i.test(dec) || /^[0-9a-f]{6,64}$/i.test(val) || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(val)) continue;
      var readable = /\s/.test(dec) && !/[A-Za-z0-9+\/=_-]{20,}/.test(dec);
      if (!readable && EXFIL_KEYS.test(key) && val.length >= (strict ? 24 : 12)) return true;
      if (!strict && val.length >= 32 && !SIGNATURE_KEY.test(key) && /^[A-Za-z0-9+\/=_%.-]+$/.test(val) && ((/[A-Z]/.test(val) && /[a-z]/.test(val) && /\d/.test(val)) || /=$/.test(val))) return true;
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

  // ---- CSS-hidden HTML ----
  var VOID = /^(?:area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/i;
  // tabs, dialogs and menus: hidden until the person clicks, so only agent-addressed text counts there
  var UI_PANEL = /\brole\s*=\s*["']?(?:tabpanel|tab|dialog|alertdialog|menu|menubar|tooltip|listbox|combobox|navigation)\b|\baria-(?:labelledby|modal|expanded|controls)\s*=/i;
  var NAMED = { white: [255, 255, 255], snow: [255, 250, 250], ivory: [255, 255, 240], ghostwhite: [248, 248, 255], whitesmoke: [245, 245, 245], black: [0, 0, 0] };
  var COLOUR = /(#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|\b(?:white|snow|ivory|ghostwhite|whitesmoke|black|transparent)\b)/i;

  function parseColour(v) {
    v = String(v || '').trim().toLowerCase();
    var m = /^#([0-9a-f]{3,8})\b/.exec(v);
    if (m) {
      var h = m[1];
      if (h.length === 3 || h.length === 4) return [parseInt(h[0] + h[0], 16), parseInt(h[1] + h[1], 16), parseInt(h[2] + h[2], 16), h.length === 4 ? parseInt(h[3] + h[3], 16) / 255 : 1];
      if (h.length === 6 || h.length === 8) return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16), h.length === 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1];
      return null;
    }
    m = /^rgba?\(\s*(\d{1,3})[\s,]+(\d{1,3})[\s,]+(\d{1,3})(?:\s*[,\/]\s*([\d.]+%?))?\s*\)/.exec(v);
    if (m) return [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : /%$/.test(m[4]) ? parseFloat(m[4]) / 100 : parseFloat(m[4])];
    if (v === 'transparent') return [0, 0, 0, 0];
    var w = /^[a-z]+/.exec(v);
    return w && NAMED[w[0]] ? NAMED[w[0]].concat(1) : null;
  }
  function decls(style) {
    var out = {};
    String(style).replace(/\/\*[\s\S]*?\*\//g, '').split(';').forEach(function (d) {
      var i = d.indexOf(':');
      if (i > 0) out[d.slice(0, i).trim().toLowerCase()] = d.slice(i + 1).replace(/!\s*important/i, '').trim().toLowerCase();
    });
    return out;
  }
  function px(v) {
    var m = /^(-?\d*\.?\d+)\s*(px|pt|em|rem|%|vw|vh)?/.exec(String(v == null ? '' : v).trim());
    if (!m) return NaN;
    var n = parseFloat(m[1]);
    var u = m[2] || 'px';
    return u === 'pt' ? n * 1.33 : u === 'em' || u === 'rem' ? n * 16 : u === '%' ? n * 0.16 : n;
  }
  function background(d, attrs) {
    var m = COLOUR.exec(d['background-color'] || d.background || '');
    if (!m && attrs) {
      var b = /\bbgcolor\s*=\s*["']?([^"'\s>]+)/i.exec(attrs);
      if (b) m = [b[1], b[1]];
    }
    return m ? parseColour(m[1]) : null;
  }
  function light(c) { return !!c && c[3] > 0.5 && 0.299 * c[0] + 0.587 * c[1] + 0.114 * c[2] >= 200; }
  function near(a, b) { return Math.abs(a[0] - b[0]) + Math.abs(a[1] - b[1]) + Math.abs(a[2] - b[2]) <= 24; }

  // Is the text of an element with this style hidden? `inherited` is the nearest background above it.
  function styleHides(style, attrs, inherited, layoutOnly) {
    var d = decls(style);
    if (d.display === 'none' || /^(?:hidden|collapse)/.test(d.visibility || '')) return true;
    var fs = d['font-size'] === undefined ? NaN : px(d['font-size']);
    if (fs < 2) return true;
    if (d.opacity !== undefined && parseFloat(d.opacity) <= 0.05) return true;
    var clipped = /hidden|clip/.test((d.overflow || '') + (d['overflow-y'] || '') + (d['overflow-x'] || ''));
    if (clipped && (px(d.height) === 0 || px(d['max-height']) === 0 || px(d.width) === 0 || px(d['max-width']) === 0)) return true;
    if (/absolute|fixed/.test(d.position || '') && (px(d.left) <= -500 || px(d.top) <= -500 || px(d.right) <= -500 || px(d.bottom) <= -500)) return true;
    if (px(d['text-indent']) <= -500 || px(d['margin-left']) <= -500 || px(d['margin-top']) <= -500) return true;
    if (/translate[xy]?\(\s*-\d{3,}/.test(d.transform || '') || /scale\(\s*0(?:\.0+)?\s*\)/.test(d.transform || '')) return true;
    if (/rect\(\s*0/.test(d.clip || '') || /inset\(\s*(?:[5-9]\d|100)(?:\.\d+)?%|circle\(\s*0/.test(d['clip-path'] || '')) return true;
    if (layoutOnly || d.color === undefined) return false;
    var c = parseColour(d.color);
    if (!c) return false;
    if (c[3] <= 0.05) return true; // transparent text
    var own = background(d, attrs);
    if (own) return near(c, own); // same colour as its own background
    if (!light(c)) return false;
    if (fs <= 3) return true; // tiny near-white text
    return near(c, inherited || [255, 255, 255]); // near-white text on a white (or default) background
  }

  function styleClasses(text) {
    if (!/<style\b/i.test(text)) return null;
    var set = null;
    var st = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;
    var m, r;
    while ((m = st.exec(text)) !== null) {
      var css = m[1].replace(/\/\*[\s\S]*?\*\//g, '');
      var rule = /([^{}]{1,300})\{([^{}]{0,2000})\}/g;
      while ((r = rule.exec(css)) !== null) {
        if (!styleHides(r[2], '', null, true)) continue;
        var sels = r[1].split(',');
        for (var i = 0; i < sels.length; i++) {
          var s = /^\s*(?:[a-z][a-z0-9]*)?([.#])([A-Za-z0-9_-]{1,60})\s*$/.exec(sels[i]);
          if (!s) continue;
          set = set || { '.': Object.create(null), '#': Object.create(null) };
          set[s[1]][s[2]] = true;
        }
      }
    }
    return set;
  }
  function hiddenByClass(attrs, set) {
    if (!set) return false;
    var c = /\bclass\s*=\s*["']([^"']*)["']/i.exec(attrs);
    if (c && c[1].split(/\s+/).some(function (x) { return set['.'][x]; })) return true;
    var id = /\bid\s*=\s*["']([^"']*)["']/i.exec(attrs);
    return !!(id && set['#'][id[1]]);
  }

  // end of the element that starts at `from` (counting nested elements of the same name)
  function closeOf(text, tag, from, start) {
    var re = new RegExp('<(/?)' + tag + '\\b[^>]{0,1000}>', 'gi');
    re.lastIndex = from;
    var depth = 1;
    var t;
    while ((t = re.exec(text)) !== null) {
      if (t[1]) depth--; else if (t[0].slice(-2) !== '/>') depth++;
      if (depth === 0) return re.lastIndex;
      if (re.lastIndex - start > 20000) break;
    }
    return -1;
  }

  function cssHidden(text, add) {
    var classes = styleClasses(text);
    var tagRe = /<(\/?)([a-zA-Z][a-zA-Z0-9-]{0,20})\b([^<>]{0,2000})>/g;
    var stack = [];
    var m;
    while ((m = tagRe.exec(text)) !== null) {
      var tag = m[2].toLowerCase();
      if (m[1]) {
        for (var k = stack.length - 1; k >= 0; k--) if (stack[k].tag === tag) { stack.length = k; break; }
        continue;
      }
      if (tag === 'script' || tag === 'style') {
        var endRaw = text.toLowerCase().indexOf('</' + tag, tagRe.lastIndex);
        if (endRaw !== -1) tagRe.lastIndex = endRaw;
        continue;
      }
      var attrs = m[3];
      var single = /\/\s*$/.test(attrs) || VOID.test(tag);
      var styleM = /\bstyle\s*=\s*(["'])([\s\S]*?)\1/i.exec(attrs);
      var style = styleM ? styleM[2] : '';
      var inherited = null;
      for (var j = stack.length - 1; j >= 0; j--) if (stack[j].bg) { inherited = stack[j].bg; break; }
      var ui = (stack.length && stack[stack.length - 1].ui) || UI_PANEL.test(attrs);
      var bare = attrs.replace(/"[^"]*"|'[^']*'/g, '""');
      var hidden = /(?:^|\s)hidden(?:\s|=|\/|$)/i.test(bare) || (style && styleHides(style, attrs, inherited, false)) || hiddenByClass(attrs, classes);
      if (hidden && !single) {
        var end = closeOf(text, tag, tagRe.lastIndex, m.index);
        if (end !== -1) {
          var inner = stripTags(text.slice(tagRe.lastIndex, end));
          if (words(inner) >= 3 && isInstruction(inner, { strict: ui })) {
            add('css-hidden', m.index, end, plain(inner).slice(0, 300));
            tagRe.lastIndex = end;
            continue;
          }
        }
      }
      if (!single) stack.push({ tag: tag, bg: style || /\bbgcolor\s*=/i.test(attrs) ? background(decls(style), attrs) : null, ui: ui });
    }
  }

  // ---- instructions in attributes nobody sees: alt, title, aria-label, hidden inputs, meta ----
  var ATTR_TAG = /<([a-zA-Z][a-zA-Z0-9-]{0,20})\b([^<>]{1,4000})>/g;
  var ATTR = /(?:^|\s)(alt|title|aria-label|aria-description|placeholder|value|content|label)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
  var MD_ALT = /!\[([^\[\]\n]{16,1000})\](?:\(|\[)/g;
  var MD_TITLE = /\]\(\s*<?[^()\s>]+>?\s+(?:"([^"\n]{16,1000})"|'([^'\n]{16,1000})')\s*\)/g;

  function hiddenAttrs(text, add) {
    var m, a;
    function check(start, val) {
      if (val.length >= 16 && words(val) >= 4 && isInstruction(val)) add('hidden-attr', start, start + val.length, plain(val).slice(0, 300));
    }
    if (/<[a-zA-Z]/.test(text)) {
      ATTR_TAG.lastIndex = 0;
      while ((m = ATTR_TAG.exec(text)) !== null) {
        var tag = m[1].toLowerCase();
        var attrs = m[2];
        var base = m.index + 1 + m[1].length;
        ATTR.lastIndex = 0;
        while ((a = ATTR.exec(attrs)) !== null) {
          var name = a[1].toLowerCase();
          var val = a[2] !== undefined ? a[2] : a[3];
          if (name === 'value' && !(tag === 'input' && /\btype\s*=\s*["']?hidden/i.test(attrs))) continue;
          if (name === 'content' && tag !== 'meta') continue;
          check(base + a.index + a[0].length - 1 - val.length, val);
        }
      }
    }
    MD_ALT.lastIndex = 0;
    while ((m = MD_ALT.exec(text)) !== null) check(m.index + 2, m[1]);
    MD_TITLE.lastIndex = 0;
    while ((m = MD_TITLE.exec(text)) !== null) {
      var t = m[1] !== undefined ? m[1] : m[2];
      check(m.index + m[0].lastIndexOf(t), t);
    }
  }

  // ---- JSON tool results: read the strings through their escapes ----
  var JSON_SIMPLE = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', '"': '"', '/': '/' };
  JSON_SIMPLE[ch(92)] = ch(92);
  function jsonView(src) {
    var out = [];
    var map = [];
    for (var i = 0; i < src.length; i++) {
      var c = src[i];
      if (c === ch(92) && i + 1 < src.length) {
        var n = src[i + 1];
        if (n === 'u' && /^[0-9a-fA-F]{4}$/.test(src.substr(i + 2, 4))) {
          out.push(String.fromCharCode(parseInt(src.substr(i + 2, 4), 16)));
          map.push(i);
          i += 5;
          continue;
        }
        if (JSON_SIMPLE[n] !== undefined) {
          out.push(JSON_SIMPLE[n]);
          map.push(i);
          i += 1;
          continue;
        }
      }
      // a quote that is not escaped ends or starts a string: read it as a line break
      out.push(c === '"' ? '\n' : c);
      map.push(i);
    }
    map.push(src.length);
    return { text: out.join(''), map: map };
  }

  function scan(text, opts) {
    opts = opts || {};
    var raw = typeof text === 'string' ? text : String(text == null ? '' : text);
    var view = /^\s*[\[{]/.test(raw) && /\\(?:u[0-9a-fA-F]{4}|[nrt"\\\/])/.test(raw) ? jsonView(raw) : null;
    var src = view ? view.text : raw;
    var full = opts.scope !== 'hidden';
    var findings = [];
    var cuts = [];
    function add(rule, start, end, hiddenText, replacement) {
      findings.push({ rule: rule, label: LABELS[rule], start: start, end: end, excerpt: reveal(src.slice(start, end)).slice(0, 160), hidden: hiddenText || null });
      cuts.push({ start: start, end: end, rep: replacement || '' });
    }
    var m;

    // HTML comments carrying instructions
    var hc = /<!--([\s\S]*?)-->/g;
    while ((m = hc.exec(src)) !== null) {
      if (isInstruction(m[1])) add('html-comment', m.index, m.index + m[0].length, plain(m[1]).slice(0, 300));
    }
    // Markdown link reference definitions are never rendered: [//]: # (text), [any label]: <> "text"
    var mc = /^[ \t]{0,3}\[([^\]\n]{1,100})\]:[ \t]*(?:<[^>\n]*>|\S+)[ \t]*(?:"([^"\n]*)"|'([^'\n]*)'|\(([^)\n]*)\))[ \t]*$/gm;
    while ((m = mc.exec(src)) !== null) {
      var body = m[2] || m[3] || m[4] || '';
      if (isInstruction(body)) add('md-comment', m.index, m.index + m[0].length, plain(body).slice(0, 300));
    }
    if (/<[a-zA-Z]/.test(src)) cssHidden(src, add);
    hiddenAttrs(src, add);

    // Invisible characters, tag characters, bidi controls
    INVIS_RUN.lastIndex = 0;
    while ((m = INVIS_RUN.exec(src)) !== null) add('invisible', m.index, m.index + m[0].length, [...m[0]].length + ' invisible characters');
    TAGS.lastIndex = 0;
    while ((m = TAGS.exec(src)) !== null) {
      var before = m.index >= 2 ? src.codePointAt(m.index - 2) : 0;
      if (before === 0x1F3F4 && FLAG_TAGS.test(m[0])) continue; // subdivision flag emoji
      add('unicode-tags', m.index, m.index + m[0].length, decodeTags(m[0]));
    }
    BIDI.lastIndex = 0;
    while ((m = BIDI.exec(src)) !== null) add('bidi', m.index, m.index + m[0].length, m[0].length + ' control characters');

    if (full) {
      var i, re, sp;
      for (i = 0; i < OVERRIDE.length; i++) {
        re = OVERRIDE[i];
        re.lastIndex = 0;
        while ((m = re.exec(src)) !== null) {
          sp = sentenceAround(src, m.index, m.index + m[0].length);
          add('override', sp[0], sp[1], null, CUT);
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
          sp = sentenceAround(src, m.index, m.index + m[0].length);
          add('remote-exec', sp[0], sp[1], null, CUT);
        }
      }
      MD_IMAGE.lastIndex = 0;
      while ((m = MD_IMAGE.exec(src)) !== null) if (suspiciousUrl(m[1], false)) add('exfil-link', m.index, m.index + m[0].length, null, CUT_LINK);
      HTML_IMG.lastIndex = 0;
      while ((m = HTML_IMG.exec(src)) !== null) if (suspiciousUrl(m[1], false)) add('exfil-link', m.index, m.index + m[0].length, null, CUT_LINK);
      MD_DEF.lastIndex = 0;
      while ((m = MD_DEF.exec(src)) !== null) if (suspiciousUrl(m[1], true)) add('exfil-link', m.index, m.index + m[0].length, null, CUT_LINK);
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
    // positions refer to the text as given (JSON escapes included)
    for (var p = 0; p < keptF.length; p++) {
      if (view) {
        keptF[p].start = keptC[p].start = view.map[keptF[p].start];
        keptF[p].end = keptC[p].end = view.map[keptF[p].end];
      }
      keptF[p].line = lineOf(raw, keptF[p].start);
    }

    var clean = raw;
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
