import { getGithubUserEmail, getGithubUser, getGoogleUser, getSlackUser, getDiscordUser, getTwitchUser } from "./getUserData.js";
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateUserID } from './randomData.js';
import { parseScopes, stringifyScopes } from './parseScopes.js';
import * as appControl from './appControl.js';
import * as db from "./databaseInteraction.js";
import * as KV from "./customKV.js";
import * as session from "./sessions.js";
import * as OAuthProvider from "./OAuthProviderAPI.js";
import * as OAuthClients from './OAuthClients.js';
import * as linker from './linkAccounts.js';
import * as userControl from './userControl.js';
import * as userInfo from './userInfo.js';
import * as OAuthIssuer from './OAuthIssuer.js';
import * as OIDCEndpoints from './OIDCEndpoints.js';
import * as jwt from "./JWT.js";
import cypto from 'crypto';

let OIDC_KEY_PAIR = null;

export async function handle(request, env) {
	KV.init(env);
    const pathname = new URL(request.url).pathname;
    if(pathname.startsWith("/oauth/") || pathname.startsWith("/callback")){
        return await OAuthIssuer.OAuthIssue(request, env, KV);
    }

	if (pathname.startsWith('/api/')) {
		if (await ratelimit(KV, `${request.headers.get('CF-Connecting-IP')}`, 45)) return new Response('429 Too Many Requets', { status: 429 });
		if (pathname.startsWith('/api/account/createAccount')){
			return await userControl.createAccount(request, env, KV);
		} else if (pathname.startsWith('/api/account/info')) {
			return await userInfo.info(request, env, KV);
		} else if (pathname.startsWith('/api/account/authorizeApp')) {
			return await appControl.authorizeApp(request, env, KV);
		} else if (pathname.startsWith('/api/account/revokeApp')) {
			return await appControl.revokeApp(request, env, KV);
		} else if(pathname.startsWith('/api/account/revokeSession')){
			return await session.revokeSessionAPI(request, env, KV);
		} else if (pathname.startsWith('/api/account/link')) {
			return await linker.linkAccounts(request, env, KV);
		} else if (pathname.startsWith('/api/account/logout')) {
			return await session.clearSession(request, env, KV);
		} else if (pathname.startsWith('/api/account/delete')) {
			return await userControl.deleteAccount(request, env, KV);
		} else if (pathname.startsWith('/api/oauth2/client')) {
			return await OAuthClients.client(request, env, KV);
		} else if (pathname.startsWith('/api/oauth2/authorize')) {
			OIDC_KEY_PAIR = await OIDCEndpoints.getActiveKeypair(env, OIDC_KEY_PAIR);
			return await OAuthProvider.authorize(request, env, KV, OIDC_KEY_PAIR); // http://localhost:8787/api/oauth2/authorize
		} else if (pathname.startsWith('/api/oauth2/token')) {
			OIDC_KEY_PAIR = await OIDCEndpoints.getActiveKeypair(env, OIDC_KEY_PAIR);
			return await OAuthProvider.token(request, env, KV, OIDC_KEY_PAIR);
		} else if (pathname.startsWith('/api/oauth2/tempToken')) {
			return await OAuthProvider.tempToken(request, env, KV);
		} else if (pathname.startsWith('/api/CSRFToken')) {
			return await session.CSRFTokenEndpoint(request, env, KV);
		}
	} else if(pathname.startsWith('/.well-known')){
		OIDC_KEY_PAIR = await OIDCEndpoints.getActiveKeypair(env, OIDC_KEY_PAIR);
		return await OIDCEndpoints.endpoint(request, env, KV, OIDC_KEY_PAIR);
	} else if(pathname == "/enviorment")
		return new Response(env.ENVIORMENT,{
			headers:{
				'Cache-Control':`max-age=${60 * 60 * 24 * 7}`
			},
		});

	return new Response('404 Not Found', {
		status: 404,
		headers: {
			'Content-Type': 'text/plain',
		},
	});
}

// returns true/false. true for being ratelimited, and false when under the limit
const ratelimit = async (KV, key, perMinute) => {
	const lookupKey = `Ratelimiter.${key}`;
	let timestamps = await KV.get(lookupKey);
	if (!timestamps) {
		timestamps = [];
	}
	for (let i = 0; i < timestamps.length; i++) {
		if (Date.now() - timestamps[i] > 60 * 1000) {
			timestamps.splice(i, 1);
		}
	}

	if (timestamps.length + 1 > perMinute) {
		await KV.put(lookupKey, timestamps, 60);
		return true;
	}
	timestamps.push(Date.now());
	await KV.put(lookupKey, timestamps, 60);
	return false;
};
