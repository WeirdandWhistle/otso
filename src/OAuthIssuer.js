import { getGithubUserEmail, getGithubUser, getGoogleUser, getSlackUser, getDiscordUser, getTwitchUser } from './getUserData.js';
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateUserID } from './randomData.js';
import { parseScopes, stringifyScopes } from './parseScopes.js';
import * as appControl from './appControl.js';
import * as db from './databaseInteraction.js';
import * as KV from './customKV.js';
import * as session from './sessions.js';
import * as OAuthProvider from './OAuthProviderAPI.js';
import * as OAuthClients from './OAuthClients.js';
import * as linker from './linkAccounts.js';
import * as userControl from './userControl.js';
import * as userInfo from './userInfo.js';

export async function OAuthIssue(request, env, KV) {
	const pathname = new URL(request.url).pathname;
	const redirect_uri = new URL(request.url).origin + '/callback';

	if (pathname.startsWith('/oauth/')) {
		let forward_url;
		const query = new URLSearchParams();
		const response_type = 'code';
		query.set('response_type', response_type);
		query.set('redirect_uri', redirect_uri);
		const urlQuery = new URL(request.url).searchParams;
		let state = urlQuery.get('state');
		const redirect_from = urlQuery.get('redirect_from');

		if (!state) state = generateRandomString(32);
		query.set('state', state);
		let client_id;
		let provider;
		if (pathname.endsWith('/github')) {
			forward_url = new URL('https://github.com/login/oauth/authorize');
			client_id = env.GITHUB_CLIENT_ID;
			provider = 'github';
		} else if (pathname.endsWith('/google')) {
			forward_url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
			client_id = env.GOOGLE_CLIENT_ID;
			query.set('scope', 'email profile');
			provider = 'google';
		} else if (pathname.endsWith('/slack')) {
			forward_url = new URL('https://slack.com/oauth/v2/authorize');
			client_id = env.SLACK_CLIENT_ID;
			query.set('scope', 'users:read');
			provider = 'slack';
		} else if (pathname.endsWith('/discord')) {
			forward_url = new URL('https://discord.com/oauth2/authorize');
			client_id = env.DISCORD_CLIENT_ID;
			query.set('scope', 'identify email');
			provider = 'discord';
		} else if (pathname.endsWith('/twitch')) {
			forward_url = new URL('https://id.twitch.tv/oauth2/authorize');
			client_id = env.TWITCH_CLIENT_ID;
			query.set('scope', 'user:read:email');
			provider = 'twitch';
		} else {
			throw new Error('That OAuth 2.0 provider is currently not supported');
		}
		let stateJson = KV.get(`state.${state}`);
		if (!stateJson) stateJson = {};
		if (redirect_from) stateJson.redirect_from = redirect_from;
		stateJson.auth = provider;
		KV.put(`state.${state}`, stateJson, 60 * 3);
		query.set('client_id', client_id);
		forward_url.search = query.toString();
		return new Response('You are currently being redirected to ' + forward_url.toString(), {
			status: 302,
			headers: {
				Location: forward_url.toString(),
			},
		});
	} else if (pathname == '/callback') {
		const githubTokenEndpoint = 'https://github.com/login/oauth/access_token';
		const googleTokenEndpoint = 'https://oauth2.googleapis.com/token';
		const slackTokenEndpoint = 'https://slack.com/api/oauth.v2.access';
		const discordTokenEndpoint = 'https://discord.com/api/oauth2/token';
		const twitchTokenEndpoint = 'https://id.twitch.tv/oauth2/token';
		const query = new URL(request.url).searchParams;
		const code = query.get('code');
		const state = query.get('state');
		const grant_type = 'authorization_code';
		if (!code || !state)
			return new Response("No client should ever be here without the quary params 'code' and 'state' for OAuth 2.0.", { status: 400 });
		// const KVstateTemp = await env.OAUTH_STATE.get(state);
		let OAuthState = KV.get(`state.${state}`);
		if (!OAuthState) return new Response('Invalid State', { status: 400 });
		const body = new URLSearchParams();
		body.set('grant_type', grant_type);
		body.set('code', code);
		body.set('redirect_uri', redirect_uri);
		let endpoint;
		if (OAuthState.auth == 'github') {
			body.set('client_id', env.GITHUB_CLIENT_ID);
			body.set('client_secret', env.GITHUB_CLIENT_SECRET);
			endpoint = githubTokenEndpoint;
		} else if (OAuthState.auth == 'google') {
			body.set('client_id', env.GOOGLE_CLIENT_ID);
			body.set('client_secret', env.GOOGLE_CLIENT_SECRET);
			endpoint = googleTokenEndpoint;
		} else if (OAuthState.auth == 'slack') {
			body.set('client_id', env.SLACK_CLIENT_ID);
			body.set('client_secret', env.SLACK_CLIENT_SECRET);
			endpoint = slackTokenEndpoint;
		} else if (OAuthState.auth == 'discord') {
			body.set('client_id', env.DISCORD_CLIENT_ID);
			body.set('client_secret', env.DISCORD_CLIENT_SECRET);
			endpoint = discordTokenEndpoint;
		} else if (OAuthState.auth == 'twitch') {
			body.set('client_id', env.TWITCH_CLIENT_ID);
			body.set('client_secret', env.TWITCH_CLIENT_SECRET);
			endpoint = twitchTokenEndpoint;
		}
		const res = await fetch(endpoint, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: body.toString(),
		});
		const resText = await res.text();
		if (!res.ok) {
			return new Response('Sorry, the authorization code exchanged failed :( Text: ' + resText);
		}
		let tokens = {};
		switch (res.headers.get('content-type').split(';')[0]) {
			case 'application/x-www-form-urlencoded':
				const s = new URLSearchParams(resText);
				s.forEach((value, key) => (tokens[key] = value));
				break;
			case 'application/json':
				tokens = JSON.parse(resText);
				break;
			default:
				return new Response('Could not detect a usable format for token exchange');
		}
		let issuerInfo; // {username, id, email, issuer}
		if (OAuthState.auth == 'github') {
			issuerInfo = await getGithubUser(tokens.access_token);
			issuerInfo.email = await getGithubUserEmail(tokens.access_token);
		} else if (OAuthState.auth == 'google') {
			issuerInfo = await getGoogleUser(tokens.access_token);
		} else if (OAuthState.auth == 'slack') {
			issuerInfo = await getSlackUser(tokens);
		} else if (OAuthState.auth == 'discord') {
			issuerInfo = await getDiscordUser(tokens.access_token);
		} else if (OAuthState.auth == 'twitch') {
			issuerInfo = await getTwitchUser(tokens.access_token, env.TWITCH_CLIENT_ID);
		} else {
			throw new Error('Huh..?');
		}
		issuerInfo.access_token = tokens.access_token;
		issuerInfo.refresh_token = tokens.refresh_token;
		const user = await db.getUserFromIssuer(env, issuerInfo.id, issuerInfo.issuer);
		console.log('after authed: user from db, ', user);
		if (!user) {
			OAuthState.issuerInfo = issuerInfo;
			KV.put(`state.${state}`, OAuthState, 60 * 5);
			const sp = new URLSearchParams();
			sp.set('state', state);
			sp.set('username', issuerInfo.username);
			sp.set('provider-username', issuerInfo.username);
			sp.set('email', issuerInfo.email);
			const otherUsername = await db.getUserFromUsername(env, issuerInfo.username);
			const otherEmail = await db.getUserFromEmail(env, issuerInfo.email);
			if (otherUsername) {
				sp.set('username', `unfun.username-${generateRandomString(24)}`);
				sp.set('otherUsername', otherUsername.username);
				sp.set('linkURL', `/api/account/link?type=create-username&userID=${otherUsername.username}&state=${state}`);
			} else if (otherEmail) {
				sp.set('otherEmail', otherEmail.length);
				sp.set('linkURL', `/api/account/link?type=create-email&email=${issuerInfo.email}&state=${state}`);
			}
			const toURL = '/firstTime?' + sp.toString();
			return new Response('You are currently being redirected to ' + toURL, {
				status: 302,
				headers: {
					Location: toURL,
				},
			});
		} else {
			const sessionID = await session.issueSession(env, user.userID, request.headers);
			const sessionCookie = session.getCookie(sessionID);
			if (OAuthState.redirect_from) {
				try {
					const realURL = new URL(OAuthState.redirect_from);
					return new Response(
						`
                            <p>You are being redirect to <a href="${realURL.toString()}">${realURL.toString()}</a>.</p>
                            <script>
                                window.location = '${realURL.toString()}';
                            </script>
                                `,
						{
							headers: {
								'Set-Cookie': sessionCookie,
								'Content-Type': 'text/html',
							},
						},
					);
				} catch (error) {
					//console.log("url is not valid trying bad redirect",error);
				}
				return new Response('You are currently being redirected to: ' + OAuthState.redirect_from, {
					status: 302,
					headers: {
						Location: OAuthState.redirect_from,
						'Set-Cookie': sessionCookie,
					},
				});
			} else {
				KV.remove(state);
				return new Response(null, {
					status: 302,
					headers: {
						Location: '/account',
						'Set-Cookie': sessionCookie,
					},
				});
			}
		}
		throw new Error('this code is unreachable');
	}
}
