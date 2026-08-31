import * as session from './sessions.js';
import * as db from './databaseInteraction.js';
import { generateRandomString, base64SHA256 } from './randomData.js';

export async function createAccount(request, env, KV){
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
				await db.createUser(env, userID, username, email, issuer, id, OAuthState.issuerInfo.username, email, access_token, refresh_token);
	
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
export async function deleteAccount(request, env, KV){
	if(await session.useCSRFToken(request, env, KV) != true)
		return new Response("401 Unauthorized. CSRFToken is wrong.",{status:401});
	const user = await session.getUserIfSession(request, env);
	if(!user)
		return new Response("401 Unauthorized. Session is invalid.",{status:401});
	 if(request.method == 'GET'){
		const url = new URL(request.url);
		const chall = url.searchParams.get("chall").toUpperCase();
		const letter = url.searchParams.get("letter").toUpperCase();
		const enge = generateRandomString(3).toUpperCase();

		if(chall.length != 3 && letter.length != 1)
			return new Response('bad',{status:400});
		 await KV.put(`deleteAccount.${user.userID}`, {challenge: `${chall}${enge}`.toUpperCase(), letter: letter}, 60);
		return new Response(enge);
	 } else if(request.method == 'DELETE'){
		 const nonce = await request.text();
		 if(!nonce)
			 return new Response('bad',{status:400});
		 const data = await KV.get(`deleteAccount.${user.userID}`);
		 if(!data)
			 return new Response('bad',{status:400});
		 const hash = await base64SHA256(data.challenge + '-' + nonce);
		 const l = data.letter;
		 if(hash.startsWith(`${l}${l}${l}`)){
			 await db.deleteUser(env, user.userID);
			 return new Response("consider it done.");
		 }
		 return new Response("**Bugs bunny no face** NO!",{status:400});
	 }
}
