import { parseScopes, stringifyScopes } from './parseScopes.js';
import * as db from './databaseInteraction.js';
import * as session from './sessions.js';

export async function authorizeApp(request, env, KV){
	if(await session.useCSRFToken(request, env, KV) != true)
		return new Response("401 Unauthorized. Wrong CSRFToken.",{status:401});
	if(request.method != 'POST')
		return new Response("405 Method Not Allowed. Try using 'POST'", {status:405});

	const user = await session.getUserIfSession(request, env);
	if(!user)
		return new Response("401 Unauthorized. That session does not exist or is invalid.", {status: 401});

	const requestJson = await request.json();
	if(!requestJson.client_id)
		return new Response("400 Bad Request. This endpoint requires a 'client_id' in the JSON.", {status: 400});

	const client = await db.getOAuthClientFromClientID(env, requestJson.client_id);
	if(!client)
		return new Response("400 Bad Request. Client does not exist.",{status: 400});


	const referer = new URL(request.headers.get("Referer"));
	if(referer.searchParams.get("scope").includes(";"))
		return new Respose("400 Bad Requets. Referer header scope can not contain ';'.",{status:400});

	const scopes = parseScopes(user.authorizedApps);
	console.log("scopes",scopes);
	if(scopes.has(client.client_id)){
		const temp = scopes.get(client.client_id);
		referer.searchParams.get("scope").split(" ").forEach((e)=>temp.add(e));
		scopes.set(client.client_id, temp);
	} else {
		scopes.set(client.client_id, new Set(referer.searchParams.get("scope").split(" ")));
	}
	const authorizedApps = stringifyScopes(scopes);

	await db.setAuthorizedApp(env, user.userID, authorizedApps);
	return new Response(`{"ok":true,"message":"App has been Authorized."}`);
}
export async function revokeApp(request, env, KV){
	if(await session.useCSRFToken(request, env, KV) != true)
		return new Response("401 Unauthorized. Wrong CSRFToken.",{status:401});

	if(request.method != 'POST')
		return new Response("405 Method Not Allowed. Try using 'POST'.",{status:405});
	const user = await session.getUserIfSession(request, env);
	if(!user)
		return new Response("401 Unauthorized. That session does not exist or is invalid.", {status: 401});
	const requestJson = await request.json();
	if(!requestJson.client_id)
		return new Response("400 Bad Request. This endpoint requires a 'client_id' in the JSON.", {status: 400});

	const client = await db.getOAuthClientFromClientID(env, requestJson.client_id);
	if(!client)
		return new Response("400 Bad Request. Client does not exist.",{status: 400});

	const scopes = parseScopes(user.authorizedApps);
	scopes.delete(client.client_id);

	await db.setAuthorizedApp(env, user.userID, stringifyScopes(scopes));
	return new Response(`{"ok":true,"message":"App Authorization has been revoked."}`);
}
