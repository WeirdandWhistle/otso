import { getGithubUserEmail, getGithubUser, getGoogleUser, getSlackUser, getDiscordUser, getTwitchUser } from './getUserData.js';
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateUserID } from './randomData.js';
import * as db from './databaseInteraction.js';
import * as session from './sessions.js';

export async function linkAccounts(request, env, KV) {
	if (request.method == 'GET') {
		const query = new URL(request.url).searchParams;
		const typeParam = query.get('type');

		if (typeParam.startsWith('create')) {
			const state = query.get('state');
			const OAuthState = await KV.get(`state.${state}`);
			if (!OAuthState) return new Response('State is invalid. Basicly your session timed out.', { status: 400 });
			const user = await session.getUserIfSession(request, env);
			let link = OAuthState.link;
			if (!link) {
				link = {
					redirect_from: OAuthState.redirect_from,
					loginMethod: OAuthState.auth,
					issuerInfo: OAuthState.issuerInfo,
				};
				OAuthState.redirect_from = request.url;
				OAuthState.link = link;
				await KV.put(`state.${state}`, OAuthState, 60 * 5);
			}

			if (!user) {
				const loginURL = new URL(request.url);
				loginURL.pathname = '/login';
				loginURL.searchParams.set('state', state);
				loginURL.searchParams.set('message', `Please login to the account you want to link. (NOT the one you just created)`);
				const temp = loginURL.toString();
				return new Response(`You are being redirected to ${temp}`, {
					status: 302,
					headers: {
						Location: temp,
					},
				});
			}
			link.user = user;
			OAuthState.link = link;
			await KV.put(`state.${state}`, OAuthState, 60 * 5);
			const data = {
				username: user.username,
				email1: user.email,
				email2: link.issuerInfo.email,
			};
			const replaceString = `{"where":"RIGHT HERE! INSERT DATA RIGHT HERE! [insert data here!]"}`;
			const tempURL = new URL(request.url);
			tempURL.pathname = '/linkAccount';
			const res = await env.ASSETS.fetch(tempURL);
			let html = await res.text();
			html = html.replace(replaceString, JSON.stringify(data));
			return new Response(html, {
				headers: {
					'Content-Type': 'text/html',
				},
			});
		}
	} else if (request.method == 'POST') {
		if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. Wrong CSRFToken.', { status: 401 });

		//console.log("post on linking accounts!");
		const json = await request.json();
		if (!json.username && !json.email && !json.state) return new Response('400 Bad Request. missing an argument.', { status: 400 });

		const OAuthState = await KV.get(`state.${json.state}`);
		if (!OAuthState) return new Response('400 Bad Request. invalid state', { status: 400 });
		if (!OAuthState.link) return new Response('400 Bad Request. forgot GET request before confirming.', { status: 400 });

		const user = OAuthState.link.user;
		const email = json.email;
		if (email != user.email && email != OAuthState.issuerInfo.email)
			return new Response('400 Bad Request. email is not either login option.', { status: 400 });
		const username = json.username;
		if (!validUsername(username)) return new Response('400 Bad Request. username is not valid.', { status: 400 });
		if (username != user.username) {
			const otherUser = await db.getUserFromUsername(env, username);
			if (otherUser && otherUser.userID != user.userID)
				return new Response('400 Bad Request. That username is already taken.', { status: 400 });
		}
		const authenticationMethods = user.authenticationMethods + ' ' + OAuthState.link.loginMethod;

		const issuerInfo = OAuthState.link.issuerInfo;
		await db.createOAuthIssuer(
			env,
			issuerInfo.id,
			OAuthState.link.loginMethod,
			issuerInfo.username,
			issuerInfo.email,
			issuerInfo.access_token,
			issuerInfo.refresh_token,
			user.userID,
		);

		await db.updateUser(env, user.userID, authenticationMethods, user.authorizedApps, email, username);

		return new Response(
			JSON.stringify({
				ok: true,
				redirect_uri: OAuthState.link.redirect_from ?? '/account',
			}),
		);
	}
}
