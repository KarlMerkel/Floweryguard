import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('./worker.js', import.meta.url), 'utf8');
const { default: worker } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

test('Административный маршрут не раскрывает обновления Telegram без авторизации', async () => {
  let requested = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    requested = true;
    return Response.json({ result: [{ message: { text: 'private-message' } }] });
  };
  try {
    for (const env of [{ TELEGRAM_BOT_TOKEN: 'test-only' }, { TELEGRAM_BOT_TOKEN: 'test-only', ADMIN_TOKEN: 'local-test-secret' }]) {
      const response = await worker.fetch(new Request('https://example.com/my-chat-id'), env, {});
      assert.ok([401, 404].includes(response.status));
      assert.equal((await response.text()).includes('private-message'), false);
    }
    assert.equal(requested, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Авторизованный администратор может получить идентификатор чата', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ ok: true, result: [{ message: { chat: { id: 123 } } }] });
  try {
    const env = { TELEGRAM_BOT_TOKEN: 'test-only', ADMIN_TOKEN: 'local-test-secret' };
    const invalid = await worker.fetch(new Request('https://example.com/my-chat-id', {
      headers: { Authorization: 'Bearer wrong-secret' },
    }), env, {});
    assert.equal(invalid.status, 401);
    const response = await worker.fetch(new Request('https://example.com/my-chat-id', {
      headers: { Authorization: 'Bearer local-test-secret' },
    }), env, {});
    assert.equal(response.status, 200);
    assert.equal((await response.json()).result[0].message.chat.id, 123);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
