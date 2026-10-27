/**
 * Flowery (Glue) — Cloudflare Worker Relay (Шлюз отчётов)
 * 
 * Назначение: Принимает диагностические логи от клиентов Flowery и безопасно пересылает
 * их разработчику в Telegram.
 * 
 * Безопасность:
 * - Токен бота и ID чата хранятся ТОЛЬКО в Cloudflare Environment Variables / Secrets.
 * - Пользователи и клиенты видят только публичный URL воркера и не могут украсть токен.
 * - Ограничение размера файла (макс. 5 МБ) для защиты от спама.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Заголовки CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, User-Agent',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Проверка статуса (Health Check)
    if (url.pathname === '/' || url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'online',
        service: 'Flowery Log Relay',
        version: '1.3.0',
        configured: Boolean(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID)
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Вспомогательный эндпоинт для разработчика: помогает узнать свой chat_id из Telegram
    if (url.pathname === '/my-chat-id') {
      // Обновления бота содержат сообщения и идентификаторы пользователей.
      if (!env.ADMIN_TOKEN) {
        return new Response('Not Found', { status: 404 });
      }
      if (request.headers.get('Authorization') !== `Bearer ${env.ADMIN_TOKEN}`) {
        return new Response('Unauthorized', { status: 401 });
      }
      if (!env.TELEGRAM_BOT_TOKEN) {
        return new Response(JSON.stringify({ error: 'TELEGRAM_BOT_TOKEN not configured in Worker Secrets' }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
      try {
        const tgRes = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getUpdates`);
        const data = await tgRes.json();
        return new Response(JSON.stringify(data, null, 2), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // Основной эндпоинт приёма логов от клиента
    if (url.pathname === '/report' && request.method === 'POST') {
      const botToken = env.TELEGRAM_BOT_TOKEN;
      const chatId = env.TELEGRAM_CHAT_ID;

      if (!botToken || !chatId) {
        return new Response(JSON.stringify({
          ok: false,
          error: 'Воркер ещё не настроен: добавьте TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID в Variables/Secrets Cloudflare.'
        }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }

      try {
        let filename = `Flowery_Report_${Date.now()}.txt`;
        let caption = '🌸 Flowery Диагностический отчёт';
        let fileContent = '';

        const contentType = request.headers.get('content-type') || '';

        if (contentType.includes('application/json')) {
          const body = await request.json();
          filename = body.filename || filename;
          caption = body.caption || caption;
          fileContent = body.content || '';
        } else if (contentType.includes('multipart/form-data')) {
          const formData = await request.formData();
          caption = formData.get('caption') || caption;
          const file = formData.get('file') || formData.get('document');
          if (file && typeof file === 'object') {
            filename = file.name || filename;
            fileContent = await file.text();
          } else {
            fileContent = formData.get('content') || '';
          }
        } else {
          fileContent = await request.text();
        }

        if (!fileContent || fileContent.trim().length === 0) {
          return new Response(JSON.stringify({ ok: false, error: 'Лог-файл пуст' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        // Защита от перегрузки (до 5 МБ)
        if (fileContent.length > 5 * 1024 * 1024) {
          fileContent = fileContent.slice(-4 * 1024 * 1024); // берём последние 4 МБ
        }

        // Формируем запрос к Telegram Bot API sendDocument
        const tgFormData = new FormData();
        tgFormData.append('chat_id', chatId);
        tgFormData.append('caption', caption.slice(0, 1024));

        const blob = new Blob([fileContent], { type: 'text/plain; charset=utf-8' });
        tgFormData.append('document', blob, filename);

        const tgResp = await fetch(`https://api.telegram.org/bot${botToken}/sendDocument`, {
          method: 'POST',
          body: tgFormData
        });

        const tgResult = await tgResp.json();

        if (tgResult.ok) {
          return new Response(JSON.stringify({
            ok: true,
            message: 'Отчёт успешно доставлен разработчику!',
            report_id: tgResult.result?.message_id || Date.now()
          }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        } else {
          return new Response(JSON.stringify({
            ok: false,
            error: tgResult.description || 'Ошибка Telegram API'
          }), {
            status: 502,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }
      } catch (err) {
        return new Response(JSON.stringify({
          ok: false,
          error: `Ошибка обработки шлюзом: ${err.message}`
        }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
    }

    return new Response(JSON.stringify({ error: 'Not Found' }), { status: 404, headers: corsHeaders });
  }
};
