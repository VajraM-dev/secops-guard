'use strict';
// Hook stdin/stdout helpers. Each emit writes exactly one JSON object; nothing else may reach stdout.

function readStdin(stream = process.stdin) {
  return new Promise((resolve) => {
    let data = '';
    stream.setEncoding('utf8');
    stream.on('data', (c) => { data += c; });
    stream.on('error', () => resolve(null));
    stream.on('end', () => {
      try {
        const v = JSON.parse(data);
        resolve(v && typeof v === 'object' ? v : null);
      } catch {
        resolve(null);
      }
    });
  });
}

const out = (obj) => process.stdout.write(JSON.stringify(obj));

const preDeny = (reason) => out({
  hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason },
});

const preAllowWithInput = (updatedInput, context) => out({
  hookSpecificOutput: {
    hookEventName: 'PreToolUse',
    permissionDecision: 'allow',
    updatedInput,
    ...(context ? { additionalContext: context } : {}),
  },
});

const preContext = (context) => out({ hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: context } });

const postBlock = (reason) => out({
  decision: 'block',
  reason,
  hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: reason },
});

const postContext = (context) => out({ hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: context } });

const sessionMessage = (userMsg, claudeContext) => out({
  ...(userMsg ? { systemMessage: userMsg } : {}),
  ...(claudeContext ? { hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: claudeContext } } : {}),
});

module.exports = { readStdin, preDeny, preAllowWithInput, preContext, postBlock, postContext, sessionMessage };
