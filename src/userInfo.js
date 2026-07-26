import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateUserID, safeCompareString } from './randomData.js';
import { parseScopes, stringifyScopes } from './parseScopes.js';
import * as db from "./databaseInteraction.js";
import * as session from "./sessions.js";

export async function info(request, env, KV) {
	if(request.method != 'GET')
		return new Response("405 Method Not Allowed. Try using the 'GET' method.",{status: 405});

	const authHeader = request.headers.get("Authorization");
	const authType = authHeader.split(" ")[0].toLowerCase();
	if(authType == "session"){
		if(await session.useCSRFToken(request, env, KV) != true)
			return new Response("401 Unauthorized. Wrong CSRFToken.",{status:401});
		return await privateInfo(request, env);
	} else if(authType == "bearer"){
		return await publicInfo(request, env);
	} else {
		return new Response("401 Unauthorized. Unknown auth-scheme. Try 'Bearer' or 'Session'.", {status: 401});
	}
}
async function publicInfo(request, env){
	const tokens = await session.getScopesFromAccessToken(request, env);
	if(!tokens)
		return new Response('401 Unauthorized. access_token error.',{status:401});

	const scopes = new Set(tokens.scopes.split(' '));
	const user = await db.getUserFromUserID(env, tokens.userID);
	const out = {};
	if(scopes.has('id')) out.userID = user.userID;
	if(scopes.has('username')) out.username = user.username;
	if(scopes.has('email')) out.email = user.email;

	return new Response(JSON.stringify(out));
}
async function privateInfo(request, env) {
	const user = await session.getUserIfSession(request, env);
	if(!user)
		return new Response(`401 Unauthorized. Session is invalid.`, {status: 401});

	const out = {};
	out.username = user.username;
	out.userID = user.userID;
	out.email = user.email;
	out.loginMethods = user.authenticationMethods.split(" ");
	out.authorizedApps = [];

	const apps = parseScopes(user.authorizedApps);
	apps.forEach(async (value, key)=>{
		const client = await db.getOAuthClientFromClientID(env, key);
		if(!client){
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
	if(ownedClients){
		for(const client of ownedClients){
			out.ownedClients.push({
				name: client.name,
				client_id: client.client_id,
				redirect_uri: client.redirection_URIs.split(" "),
				client_type: client.client_type,
			});
		}
	}
	return new Response(JSON.stringify(out));
}
