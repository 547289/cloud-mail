import app from '../hono/hono';
import result from '../model/result';
import publicService from '../service/public-service';
import KvConst from '../const/kv-const';

app.post('/public/genToken', async (c) => {
	const data = await publicService.genToken(c, await c.req.json());
	return c.json(result.ok(data));
});

app.post('/public/emailList', async (c) => {
	const list = await publicService.emailList(c, await c.req.json());
	return c.json(result.ok(list));
});

app.post('/public/addUser', async (c) => {
	await publicService.addUser(c, await c.req.json());
	return c.json(result.ok());
});

// ====== 适配注册控制器的接口 ======

// 获取当前配置的所有域名
app.get('/public/domains', async (c) => {
	const token = c.req.header('x-api-token');
	const storedToken = await c.env.kv.get(KvConst.PUBLIC_KEY);
	if (!token || token !== storedToken) {
		return c.json({ success: false, message: 'Unauthorized' }, 401);
	}
	const domains = c.env.domain || [];
	return c.json({ success: true, data: { domains } });
});

// 轮询邮件获取验证码
app.get('/public/mailbox/:email/messages', async (c) => {
	// 验证 x-api-token
	const token = c.req.header('x-api-token');
	const storedToken = await c.env.kv.get(KvConst.PUBLIC_KEY);
	if (!token || token !== storedToken) {
		return c.json({ success: false, message: 'Unauthorized' }, 401);
	}

	const emailAddr = c.req.param('email');
	const list = await publicService.emailList(c, { toEmail: emailAddr, size: 5 });

	if (!list || list.length === 0) {
		return c.json({ success: false, message: 'No emails found' });
	}

	// 最新邮件原文（含 HTML，可能带验证链接）
	const latest = list[0];
	const content = latest.content || latest.text || latest.subject || '';
	const code = extractCode(content);

	// 是否附加验证链接/原文：仅当调用方显式带 ?link=1（或 ?include=link）时才返回，
	// 保证其它只取 6 位验证码的老项目调用行为【完全不变】
	const wantLink = c.req.query('link') === '1' || c.req.query('include') === 'link';
	if (wantLink) {
		const link = extractVerifyLink(content);
		if (code || link) {
			return c.json({ success: true, data: { code: code || '', link: link || '', content } });
		}
		return c.json({ success: false, message: 'No verification code or link found' });
	}

	// ===== 以下为原有行为，与改动前逐字节一致 =====
	if (code) {
		return c.json({ success: true, data: { code } });
	}

	return c.json({ success: false, message: 'No verification code found' });
});

// 提取6位数字验证码
function extractCode(text) {
	if (!text) return null;
	// 去除HTML标签
	const plain = text.replace(/<[^>]+>/g, ' ');
	// 匹配独立的6位数字
	const match = plain.match(/(?<!\d)\d{6}(?!\d)/);
	return match ? match[0] : null;
}

// 从邮件正文提取验证/确认链接（用于 Cloudflare 等基于链接的邮箱验证）
function extractVerifyLink(text) {
	if (!text) return null;
	// 反转义常见 HTML/JSON 编码，还原真实 URL
	const s = String(text)
		.replace(/&amp;/g, '&')
		.replace(/&#61;/g, '=')
		.replace(/\\\//g, '/');
	const urls = s.match(/https?:\/\/[^\s"'<>)\\]+/gi) || [];
	// 优先：含 verify/confirm/activate/validate/token 的链接（不限域名）
	for (const u of urls) {
		const clean = u.replace(/[.,);"']+$/, '');
		if (/verif|confirm|activate|validate|token=/i.test(clean)) {
			return clean;
		}
	}
	// 次选：任意 cloudflare.com 域名链接
	for (const u of urls) {
		const clean = u.replace(/[.,);"']+$/, '');
		if (/cloudflare\.com/i.test(clean)) {
			return clean;
		}
	}
	return null;
}
