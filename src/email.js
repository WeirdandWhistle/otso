import * as db from './databaseInteraction.js';

export async function updateDBWithVerifiedEmail(env, userID, email) {
	if (!email) return;
	if (!userID) return;

	const emailVerified = await isEmailVerified(env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_EMAIL_TOKEN, email);

	db.setEmailVerified(env, userID, emailVerified ? 1 : 0);
}
export async function isEmailVerified(USERID, TOKEN, email) {
	const json = await getEmailsJson(USERID, TOKEN, email);
	console.log('json', json);
	for (const obj of json) {
		if (obj.email == email && obj.verified) return true;
	}
	return false;
}
async function getEmailsJson(USERID, TOKEN) {
	const requestURL = `https://api.cloudflare.com/client/v4/accounts/${USERID}/email/routing/addresses`;
	const res = await fetch(requestURL, {
		method: 'GET',
		headers: {
			Authorization: `Bearer ${TOKEN}`,
		},
	});
	if (!res.ok) throw new Error('CLOUDFLARE email api ERROR: ' + (await res.text()));
	return (await res.json()).result;
}

export async function verifyAddress(USERID, TOKEN, email) {
    const requestURL = `https://api.cloudflare.com/client/v4/accounts/${USERID}/email/routing/addresses`;
	const res = await fetch(requestURL, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${TOKEN}`,
            'Content-Type': 'application/json'
		},
        body:JSON.stringify({
            email: email,
        }),
	});
    if (!res.ok) throw new Error('CLOUDFLARE email api ERROR: ' + (await res.text()));    
}