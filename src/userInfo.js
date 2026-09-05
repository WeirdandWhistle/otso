import {
	validUsername,
	correctUsername,
	base64SHA256,
	generateRandomString,
	generateSecureChars,
	generateUserID,
	safeCompareString,
} from './randomData.js';
import { parseScopes, stringifyScopes } from './parseScopes.js';
import * as db from './databaseInteraction.js';
import * as session from './sessions.js';


export async function adminInfo(request, env, KV) {
	if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. Wrong CSRFToken.', { status: 401 });
	const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. User is not logged in.', { status: 401 });
	if (!session.isAdmin(user.userType)) return new Response('401 Unauthorized. User is not an Admin.', { status: 401 });

	const out = {};

	out.userList = await packUserList(env);

	return new Response(JSON.stringify(out), {
		status: 200,
	});
}
async function packUserList(env) {
	const list = await db.getUserList(env);
	const out = [];
	for(const user of list){
		out.push({username: user.username, userID: user.userID});
	}
	return out;
}
export async function adminUserLookup(request, env, KV) {
	if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. Wrong CSRFToken.', { status: 401 });
	const user = await session.getUserIfSession(request, env);
	if (!user) return new Response('401 Unauthorized. User is not logged in.', { status: 401 });
	if (!session.isAdmin(user.userType)) return new Response('401 Unauthorized. User is not an Admin.', { status: 401 });

	const query = new URL(request.url).searchParams;
	let json = {};
	json.userID = query.get("userID");
	if(!json.userID)return new Response('400 Bad Request. No UserID was sent.', {status:400});

	const targetUser = await db.getUserFromUserID(env, json.userID);
	if (!targetUser) return new Response('404 Not Found. User does not exist.', { status: 404 });
	const out = {};

	out.userID = targetUser.userID;
	out.username = targetUser.username;
	out.userType = targetUser.userType;
	out.email = targetUser.email;
	out.created_at = targetUser.created_at;
	out.authenticationMethods = targetUser.authenticationMethods;
	
	out.authorizedApps = [];
	const scopes = parseScopes(targetUser.authorizedApps);
	scopes.forEach((value, key, map)=>out.authorizedApps.push(key));

	const sessions = await db.getSessionsFromUserID(env, targetUser.userID) ?? [];
	console.log("sessions",sessions);
	out.sessions = [];
	sessions.forEach((v)=>{
		const data = JSON.parse(v.sessionData);
		data.created_at = v.created_at;
		console.log("data",data);
		out.sessions.push(data);
	});

	return new Response(JSON.stringify(out));
}

export async function info(request, env, KV) {
	if (request.method == 'OPTIONS') {
		return new Response('', {
			headers: {
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Request-Method': 'POST, GET, OPTIONS',
				'Access-Control-Allow-Headers': 'Authorization',
			},
		});
	}
	if (request.method != 'GET') return new Response("405 Method Not Allowed. Try using the 'GET' method.", { status: 405 });

	const authHeader = request.headers.get('Authorization');
	const authType = authHeader.split(' ')[0].toLowerCase();
	if (authType == 'session') {
		if ((await session.useCSRFToken(request, env, KV)) != true) return new Response('401 Unauthorized. Wrong CSRFToken.', { status: 401 });
		return await privateInfo(request, env);
	} else if (authType == 'bearer') {
		return await publicInfo(request, env);
	} else {
		return new Response("401 Unauthorized. Unknown auth-scheme. Try 'Bearer' or 'Session'.", { status: 401 });
	}
}
async function publicInfo(request, env) {
	const tokens = await session.getScopesFromAccessToken(request, env);
	if (!tokens) return new Response('401 Unauthorized. access_token error.', { status: 401 });

	const scopes = new Set(tokens.scopes.split(' '));
	const user = await db.getUserFromUserID(env, tokens.userID);
	const out = {};
	if (scopes.has('sub')) out.userID = user.userID;
	if (scopes.has('preferred_username')) out.username = user.username;
	if (scopes.has('email')) out.email = user.email;

	return new Response(JSON.stringify(out), {
		headers: {
			'Access-Control-Allow-Origin': '*',
		},
	});
}
async function privateInfo(request, env) {
	const user = await session.getUserIfSession(request, env);
	if (!user) return new Response(`401 Unauthorized. Session is invalid.`, { status: 401 });

	const out = {};
	out.username = user.username;
	out.userID = user.userID;
	out.email = user.email;
	out.created_at = user.created_at;
	out.loginMethods = user.authenticationMethods.split(' ');
	out.authorizedApps = [];
	out.isAdmin = session.isAdmin(user.userType);

	const apps = parseScopes(user.authorizedApps);
	apps.forEach(async (value, key) => {
		const client = await db.getOAuthClientFromClientID(env, key);
		if (!client) {
			return;
		}
		out.authorizedApps.push({
			name: client.name,
			client_id: client.client_id,
			scopes: Array.from(value),
		});
	});
	out.ownedClients = [];
	const ownedClients = await db.getOAuthClientsFromUserID(env, user.userID);
	if (ownedClients) {
		for (const client of ownedClients) {
			out.ownedClients.push({
				name: client.name,
				client_id: client.client_id,
				redirect_uri: client.redirection_URIs.split(' '),
				client_type: client.client_type,
			});
		}
	}
	out.sessions = [];
	const sessions = await db.getSessionsFromUserID(env, user.userID);
	if (sessions) {
		const currentSessionID = session.getSessionID(request);
		for (const s of sessions) {
			const data = JSON.parse(s.sessionData);
			data.created_at = s.created_at;
			if (s.sessionID == currentSessionID) data.current_session = true;
			out.sessions.push(data);
		}
	}
	return new Response(JSON.stringify(out));
}
