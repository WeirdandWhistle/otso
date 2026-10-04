import * as session from './sessions.js';
import * as db from './databaseInteraction.js';
import * as emailAPI from './email.js';
import { generateRandomString, base64SHA256, validUsername, correctUsername, generateUserID, generateSecureChars } from './randomData.js';

export async function createAccount(request, env, KV, ctx) {
	if (request.method != 'POST') return new Response('405 Method Not Allowed', { status: 405 });
	const postJson = await request.json();
	const state = postJson.state;

	const OAuthState = await KV.get(`state.${state}`);
	if (!OAuthState) return new Response(`{"ok":false,"error":"invalid_state"}`, { status: 400 });
	await KV.put(`state.${state}`, OAuthState, 60 * 5);

	let username = OAuthState.issuerInfo.username;

	if (validUsername(postJson.username)) username = postJson.username;
	if (!validUsername(username)) username = correctUsername(username);

	let email = OAuthState.issuerInfo.email;
	const id = OAuthState.issuerInfo.id;
	const issuer = OAuthState.auth;
	const access_token = OAuthState.issuerInfo.access_token;
	const refresh_token = OAuthState.issuerInfo.refresh_token;

	const otherUser = await db.getUserFromUsername(env, username);
	if (otherUser)
		return new Response(
			JSON.stringify({
				ok: false,
				error: `Someone has already taken that username. This you? <a href="/api/account/link?type=create-username&state=${state}">Link Account</a>.`,
			}),
		);

	const userID = generateUserID();
	const isAdmin = await db.firstUser(env);
	await db.createUser(
		env,
		userID,
		username,
		email,
		issuer,
		id,
		OAuthState.issuerInfo.username,
		email,
		access_token,
		refresh_token,
		isAdmin ? 'admin' : 'basic',
	);
	// ctx.waitUntil(emailAPI.updateDBWithVerifiedEmail(env, userID, email));
	const headers = new Headers();

	const sessionID = await session.issueSession(env, userID, request.headers);
	const sessionCookie = session.getCookie(sessionID);
	headers.append('Set-Cookie', sessionCookie);
	headers.append('Content-Type', 'application/json');

	return new Response(
		JSON.stringify({
			ok: true,
			redirect_uri: OAuthState.redirect_from,
		}),
		{
			status: 200,
			headers: headers,
		},
	);
}
export async function deleteAccount(request, env, KV) {
	if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. CSRFToken is wrong.', { status: 401 });
	const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. Session is invalid.', { status: 401 });
	if (request.method == 'GET') {
		const url = new URL(request.url);
		const chall = url.searchParams.get('chall').toUpperCase();
		const letter = url.searchParams.get('letter').toUpperCase();
		const enge = generateRandomString(3).toUpperCase();

		if (chall.length != 3 && letter.length != 1) return new Response('bad', { status: 400 });
		await KV.put(`deleteAccount.${user.userID}`, { challenge: `${chall}${enge}`.toUpperCase(), letter: letter }, 60);
		return new Response(enge);
	} else if (request.method == 'DELETE') {
		if (request.headers.get('Authorization') == 'admin') {
			if (!session.isAdmin(user.userType)) return new Response('401 Unauthorized. User is not an Admin.', { status: 401 });
			const userID = await request.text();
			await db.deleteUser(env, userID);
			return new Response('lets take a walk.');
		}
		const nonce = await request.text();
		if (!nonce) return new Response('bad', { status: 400 });
		const data = await KV.get(`deleteAccount.${user.userID}`);
		if (!data) return new Response('bad', { status: 400 });
		const hash = await base64SHA256(data.challenge + '-' + nonce);
		const l = data.letter;
		if (hash.startsWith(`${l}${l}${l}`)) {
			await db.deleteUser(env, user.userID);
			return new Response('consider it done.');
		}
		return new Response('**Bugs bunny no face** NO!', { status: 400 });
	}
}
export async function setUserEmailMasking(request, env, KV, ctx) {
	if (request.method != 'PATCH') return new Response('405 Method Not Allowed. Try using "patch".', { status: 405 });
	if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. Wrong CSRFToken.', { status: 401 });
	const loggedInUser = await session.getUserIfSession(request, env);
	if (!loggedInUser) return new Response('401 Unauthorized. User is not logged in.', { status: 401 });
	if (!session.isAdmin(loggedInUser.userType)) return new Response('401 Unauthorized. User is not an Admin.', { status: 401 });

	const inputs = new URL(request.url).pathname.split('/');
	if (inputs.length < 6) return new Response('400 Bad Request. 2 inputs must be present.', { status: 400 });
	const userID = inputs[4];
	const setEmailMasking = inputs[5] === 'true';

	const user = await db.getUserFromUserID(env, userID);
	if (user == null) return new Response('404 Not Found. User Does Not Exist.', { status: 404 });

	const currentUserType = user.userType.split('-');
	const currentEmailMasking = currentUserType.includes('emailMasking');
	const updateUser = currentEmailMasking != setEmailMasking;
	// console.log('updateuser',updateUser,'curenttype',currentUserType);

	if (setEmailMasking) ctx.waitUntil(emailAPI.updateDBWithVerifiedEmail(env, userID, user.email));
	else ctx.waitUntil(db.setEmailVerified(env, userID, null));

	if (!updateUser) return new Response('200 OK', { status: 200 });

	let newUserType = '';
	currentUserType.forEach((v) => {
		if (v == 'emailMasking' || v.trim() == '') return;
		newUserType += v + '-';
	});

	if (setEmailMasking) newUserType += 'emailMasking';

	await db.updateUser(env, userID, user.authenticationMethods, user.authorizedApps, user.email, user.username, newUserType);

	return new Response('200 OK.');
}
export async function verifyUserEmail(request, env, KV, ctx) {
	if (request.method != 'POST') return new Response('405 Method Not Allowed. Try using "POSR".', { status: 405 });
	if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. CSRFToken is wrong.', { status: 401 });
	const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. Session is invalid.', { status: 401 });
	if (!user.userType.split('-').includes('emailMasking'))
		return new Response('401 Unauthorized. User is not allowed to verify an email.', { status: 401 });

	const emailVerifyed = await emailAPI.isEmailVerified(env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_EMAIL_TOKEN);
	if(emailVerifyed) {
		await db.setEmailVerified(env, user.userID, 1);
		return new Response(JSON.stringify({
			verify: true,
			emailSent: false
		}));
	}

	await emailAPI.verifyAddress(env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_EMAIL_TOKEN, user.email);
	return new Response(JSON.stringify({
		verify: false,
		emailSent: true,
	}))
}
