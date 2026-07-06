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

	// 从最新邮件中提取6位数字验证码
	const latest = list[0];
	const content = latest.content || latest.text || latest.subject || '';
	const code = extractCode(content);

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
