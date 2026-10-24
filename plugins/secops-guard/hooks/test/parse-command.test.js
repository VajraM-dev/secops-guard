'use strict';
const test = require('node:test');
const assert = require('node:assert');
const P = require('../lib/parse-command.js');

// compact form of an intent list for table-driven cases
function sum(intents) {
  return intents.flatMap((i) => {
    const cwd = i.cwd ? ` cwd=${i.cwd}` : '';
    if (i.kind === 'explicit') return i.packages.map((p) => `${i.ecosystem}:${p.name}@${p.spec}${cwd}`);
    if (i.kind === 'lockfile') return [`lock:${i.ecosystem}${i.files ? ` files=${i.files.join(',')}` : ''}${cwd}`];
    if (i.kind === 'image') return [`image:${i.image}`];
    if (i.kind === 'compose') return [`compose${i.files && i.files.length ? ` files=${i.files.join(',')}` : ''}${cwd}`];
    return [`build:${i.tag}`];
  });
}

const CASES = [
  // npm family
  ['npm install lodash', ['npm:lodash@']],
  ['npm i lodash@4.17.21', ['npm:lodash@4.17.21']],
  ['npm isntall left-pad', ['npm:left-pad@']],
  ['npm add -D @types/node@^20', ['npm:@types/node@^20']],
  ['npm i -g typescript', ['npm:typescript@']],
  ['npm install --save-dev eslint prettier', ['npm:eslint@', 'npm:prettier@']],
  ['npm install --registry https://r.example.com foo', ['npm:foo@']],
  ['npm i alias@npm:real-pkg@1.0.0', ['npm:real-pkg@1.0.0']],
  ['npm install', ['lock:npm']],
  ['npm ci', ['lock:npm']],
  ['npm install --prefix web', ['lock:npm cwd=web']],
  ['pnpm add zod', ['npm:zod@']],
  ['pnpm i', ['lock:npm']],
  ['pnpm install --frozen-lockfile', ['lock:npm']],
  ['pnpm --filter web add react', ['npm:react@']],
  ['yarn', ['lock:npm']],
  ['yarn install', ['lock:npm']],
  ['yarn add react@18.3.1', ['npm:react@18.3.1']],
  ['yarn global add serve', ['npm:serve@']],
  ['bun add hono', ['npm:hono@']],
  ['bun install', ['lock:npm']],
  ['bun i elysia', ['npm:elysia@']],
  // runners / create
  ['npx cowsay hi', ['npm:cowsay@']],
  ['npx -y create-react-app my-app', ['npm:create-react-app@']],
  ['npx --yes prettier@3.0.0 --write .', ['npm:prettier@3.0.0']],
  ['npx -p typescript tsc --init', ['npm:typescript@']],
  ['npx eslint -p notapkg', ['npm:eslint@']],
  ['npm exec -- vitest run', ['npm:vitest@']],
  ['pnpm dlx degit user/repo', ['npm:degit@']],
  ['pnpx tsx script.ts', ['npm:tsx@']],
  ['yarn dlx create-next-app', ['npm:create-next-app@']],
  ['bunx cowsay', ['npm:cowsay@']],
  ['bun x cowsay', ['npm:cowsay@']],
  ['npm create vite@latest my-app -- --template react', ['npm:create-vite@latest']],
  ['npm init @eslint/config', ['npm:@eslint/create-config@']],
  ['npm init -y', []],
  ['pnpm create astro', ['npm:create-astro@']],
  ['yarn create @scope', ['npm:@scope/create@']],
  // pypi
  ['pip install requests', ['pypi:requests@']],
  ['pip install requests==2.19.0', ['pypi:requests@==2.19.0']],
  ['pip3 install "fastapi[all]>=0.100"', ['pypi:fastapi@>=0.100']],
  ["pip install 'foo~=1.4; python_version<\"3.11\"'", ['pypi:foo@~=1.4']],
  ['python -m pip install -U pip', ['pypi:pip@']],
  ['python3 -m pip install --user httpx', ['pypi:httpx@']],
  ['py -m pip install black', ['pypi:black@']],
  ['pip install -r requirements.txt', ['lock:pypi files=requirements.txt']],
  ['pip install -r req.txt flask', ['lock:pypi files=req.txt', 'pypi:flask@']],
  ['pip install -e .', []],
  ['pip install .', []],
  ['pip install ./dist/pkg-1.0.whl', []],
  ['pip install git+https://github.com/x/y.git', []],
  ['pip install -i https://test.pypi.org/simple foo', ['pypi:foo@']],
  ['pip install --target vendor numpy', ['pypi:numpy@']],
  ['uv pip install polars', ['pypi:polars@']],
  ['uv pip sync requirements.lock', ['lock:pypi files=requirements.lock']],
  ['uv add "pydantic>=2"', ['pypi:pydantic@>=2']],
  ['uv add --dev pytest', ['pypi:pytest@']],
  ['uv sync', ['lock:pypi']],
  ['uv tool install ruff', ['pypi:ruff@']],
  ['uvx ruff check', ['pypi:ruff@']],
  ['uvx ruff@0.3.0 check', ['pypi:ruff@==0.3.0']],
  ['uvx --from httpie http GET x', ['pypi:httpie@']],
  ['uv tool run black .', ['pypi:black@']],
  ['uv run --with rich script.py', ['pypi:rich@']],
  ['pipx install poetry', ['pypi:poetry@']],
  ['pipx run cowsay', ['pypi:cowsay@']],
  ['poetry add django@^4.2', ['pypi:django@>=4.2,<5']],
  ['poetry add "requests>=2.0"', ['pypi:requests@>=2.0']],
  ['poetry install', ['lock:pypi']],
  ['pipenv install', ['lock:pypi']],
  ['pipenv sync', ['lock:pypi']],
  ['pipenv install flask', ['pypi:flask@']],
  // crates
  ['cargo add serde', ['crates:serde@']],
  ['cargo add serde@1.0.190 tokio', ['crates:serde@1.0.190', 'crates:tokio@']],
  ['cargo add --git https://github.com/x/y foo', []],
  ['cargo install ripgrep', ['crates:ripgrep@']],
  ['cargo install ripgrep@13.0.0', ['crates:ripgrep@=13.0.0']],
  ['cargo install ripgrep --version 13.0.0', ['crates:ripgrep@=13.0.0']],
  ['cargo install --path .', ['lock:crates cwd=.']],
  ['cargo build --release', ['lock:crates']],
  ['cargo +nightly test', ['lock:crates']],
  ['cargo fmt', []],
  // docker
  ['docker pull nginx:1.27', ['image:nginx:1.27']],
  ['docker run -it --rm -p 8080:80 -v data:/data --name web nginx bash', ['image:nginx']],
  ['docker run -d -e A=1 --network=host ghcr.io/org/app@sha256:abc', ['image:ghcr.io/org/app@sha256:abc']],
  ['docker run -dp 80:80 redis:7', ['image:redis:7']],
  ['docker create --platform linux/amd64 postgres:16', ['image:postgres:16']],
  ['docker container run alpine', ['image:alpine']],
  ['docker compose up -d', ['compose']],
  ['docker compose -f prod.yml pull', ['compose files=prod.yml']],
  ['docker-compose up', ['compose']],
  ['docker build -t myapp:dev .', ['build:myapp:dev']],
  ['docker ps', []],
  // wrappers / chaining / cwd
  ['cd web && npm ci', ['lock:npm cwd=web']],
  ['cd api; cd sub && pip install -r requirements.txt', ['lock:pypi files=requirements.txt cwd=api/sub']],
  ['npm test && npm i lodash', ['npm:lodash@']],
  ['ls | npm i foo || echo no', ['npm:foo@']],
  ['FOO=1 BAR=2 npm i foo', ['npm:foo@']],
  ['sudo -E pip install requests', ['pypi:requests@']],
  ['time npm ci', ['lock:npm']],
  ['env NODE_ENV=prod npm install express', ['npm:express@']],
  ['bash -c "npm i left-pad"', ['npm:left-pad@']],
  ["sh -c 'pip install six && npm ci'", ['pypi:six@', 'lock:npm']],
  ['cmd /c "npm i foo"', ['npm:foo@']],
  ['cmd.exe /c npm install bar', ['npm:bar@']],
  ['powershell -NoProfile -Command "npm i foo; pip install bar"', ['npm:foo@', 'pypi:bar@']],
  ['pwsh -c "uv add httpx"', ['pypi:httpx@']],
  // PowerShell syntax
  ['Set-Location web; npm install', ['lock:npm cwd=web']],
  ['$env:CI="1"; npm ci', ['lock:npm']],
  ['& npm.cmd install lodash', ['npm:lodash@']],
  ['& "C:\\Program Files\\nodejs\\npm.cmd" install lodash', ['npm:lodash@']],
  ['C:\\Python312\\python.exe -m pip install flask', ['pypi:flask@']],
  ['npm i foo 2>&1 | Out-Null', ['npm:foo@']],
  ['npm i foo `\n  bar', ['npm:foo@', 'npm:bar@']],
  // not packages
  ['npm i ./local-pkg', []],
  ['npm i ../pkg.tgz', []],
  ['npm i user/repo', []],
  ['npm i github:user/repo', []],
  ['npm i https://x.org/a.tgz', []],
  ['npm i file:../x', []],
  ['npm i foo@workspace:*', []],
  ['npm i $PKG', []],
  ['npm run build', []],
  ['npm test', []],
  ['pytest -q', []],
  // false positives that must not parse
  ['echo "npm install x"', []],
  ['grep -r "pip install" .', []],
  ['git commit -m "npm i foo"', []],
  ['# npm install evil', []],
  ['ls # ; npm install evil', []],
  ["echo 'cargo add x' > notes.txt", []],
  ['Write-Output "pip install requests"', []],
  ['cat README.md | grep npm', []],
  ['node -e "require(\'child_process\')"', []],
];

for (const [cmd, want] of CASES) {
  test(`parse: ${cmd.replace(/\n/g, '\\n')}`, () => assert.deepStrictEqual(sum(P.parseInstallIntents(cmd)), want));
}

test('table has 80+ cases', () => assert.ok(CASES.length >= 80, String(CASES.length)));

test('splitSegments respects quotes and redirects', () => {
  assert.deepStrictEqual(P.splitSegments('a && b; c | d || e & f\ng'), ['a', 'b', 'c', 'd', 'e', 'f', 'g']);
  assert.deepStrictEqual(P.splitSegments('echo "a && b"; x 2>&1'), ['echo "a && b"', 'x 2>&1']);
  assert.deepStrictEqual(P.splitSegments("echo 'x;y' && z"), ["echo 'x;y'", 'z']);
});

test('tokenize handles quotes, escapes and redirects', () => {
  assert.deepStrictEqual(P.tokenize('pip install "a b" c\\ d \'e\''), ['pip', 'install', 'a b', 'c d', 'e']);
  assert.deepStrictEqual(P.tokenize('cd C:\\Users\\x'), ['cd', 'C:\\Users\\x']);
  assert.deepStrictEqual(P.tokenize('npm i foo > log.txt 2>&1'), ['npm', 'i', 'foo']);
});

test('explicit intent carries segmentIndex and tokenIndexes', () => {
  const [it] = P.parseInstallIntents('ls; npm i a b');
  assert.strictEqual(it.segmentIndex, 1);
  assert.deepStrictEqual(it.tokenIndexes, [2, 3]);
  assert.strictEqual(it.manager, 'npm');
});

test('registries are recorded', () => {
  assert.deepStrictEqual(P.parseInstallIntents('pip install -i https://evil.example/simple foo')[0].registries, ['https://evil.example/simple']);
  assert.deepStrictEqual(P.parseInstallIntents('npm i --registry=https://r.x foo')[0].registries, ['https://r.x']);
});

const pins = (o) => new Map(Object.entries(o));
const REWRITES = [
  ['npm install lodash', { lodash: 'lodash@4.17.21' }, 'npm install lodash@4.17.21'],
  ['npm i -D a b && echo done', { a: 'a@1.0.0', b: 'b@2.0.0' }, 'npm i -D a@1.0.0 b@2.0.0 && echo done'],
  ['pip install requests', { requests: 'requests==2.31.0' }, 'pip install requests==2.31.0'],
  // Always single-quoted now, whatever the original quoting: one quoting rule is auditable,
  // "preserve what the user typed" is how the injection bug got in.
  ['pip install "fastapi[all]"', { 'fastapi[all]': 'fastapi[all]==0.110.0' }, "pip install 'fastapi[all]==0.110.0'"],
  ['pip install fastapi[all]', { 'fastapi[all]': 'fastapi[all]==0.110.0' }, "pip install 'fastapi[all]==0.110.0'"],
  ['bash -c "npm i left-pad"', { 'left-pad': 'left-pad@1.3.0' }, 'bash -c "npm i left-pad@1.3.0"'],
  // Inside an existing quoted string the value goes in bare: the outer quotes already protect
  // it, and adding our own would close them. If it contained the outer quote char we refuse.
  ["bash -c 'pip install foo[x]'", { 'foo[x]': 'foo[x]==1.0' }, "bash -c 'pip install foo[x]==1.0'"],
  ['cargo install ripgrep --version 13.0.0 --locked', { ripgrep: 'ripgrep@13.0.0' }, 'cargo install ripgrep@13.0.0  --locked'],
  ['npx --package=typescript tsc', { typescript: 'typescript@5.4.5' }, 'npx --package=typescript@5.4.5 tsc'],
  ['echo lodash && npm i lodash', { lodash: 'lodash@1.0.0' }, 'echo lodash && npm i lodash@1.0.0'],
  ['npm i foo', {}, 'npm i foo'],
];
for (const [cmd, map, want] of REWRITES) {
  test(`rewrite: ${cmd}`, () => assert.strictEqual(P.rewriteCommand(cmd, pins(map)), want));
}

test('nested escaped strings cannot be mapped -> start is null', () => {
  const [it] = P.parseInstallIntents('bash -c "npm i \\"foo\\""');
  assert.strictEqual(it.packages[0].name, 'foo');
  assert.strictEqual(it.packages[0].start, null);
});

test('pinToken formats per ecosystem', () => {
  const [npm] = P.parseInstallIntents('npm i a@npm:b')[0].packages;
  assert.strictEqual(P.pinToken(npm, '1.0.0'), 'a@npm:b@1.0.0');
  const [cr] = P.parseInstallIntents('npm create vite')[0].packages;
  assert.strictEqual(P.pinToken(cr, '5.0.0'), 'vite@5.0.0');
  const [py] = P.parseInstallIntents("pip install 'x[y]>=1; os_name==\"nt\"'")[0].packages;
  assert.strictEqual(P.pinToken(py, '1.2'), 'x[y]==1.2; os_name=="nt"');
  const [ca] = P.parseInstallIntents('cargo add serde')[0].packages;
  assert.strictEqual(P.pinToken(ca, '1.0.0'), 'serde@=1.0.0');
  const [uv] = P.parseInstallIntents('uvx ruff')[0].packages;
  assert.strictEqual(P.pinToken(uv, '0.4.0'), 'ruff@0.4.0');
});

test('poetryToPep440', () => {
  assert.strictEqual(P.poetryToPep440('^1.2.3'), '>=1.2.3,<2');
  assert.strictEqual(P.poetryToPep440('^0.2.3'), '>=0.2.3,<0.3');
  assert.strictEqual(P.poetryToPep440('~1.2'), '>=1.2,<1.3');
  assert.strictEqual(P.poetryToPep440('1.2.3'), '==1.2.3');
  assert.strictEqual(P.poetryToPep440('*'), '');
  assert.strictEqual(P.poetryToPep440('>=1, <2'), '>=1,<2');
  assert.strictEqual(P.poetryToPep440('1.2.*'), null);
});

test('linear time on hostile input', () => {
  const evil = [`npm i ${'a'.repeat(50000)}`, `${'"'.repeat(30000)}`, `pip install ${'['.repeat(20000)}`, `${'\\'.repeat(30000)}`, `${'a=b '.repeat(5000)}npm i x`];
  const t = Date.now();
  for (const e of evil) P.parseInstallIntents(e);
  assert.ok(Date.now() - t < 1000, `${Date.now() - t} ms`);
});
