import * as session from './sessions.js';
import * as db from './databaseInteraction.js';
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, generateUserID } from './randomData.js';

export async function client(request, env) {
	if(request.method != "POST" && request.method != "DELETE" && request.method != 'PATCH')
			return new Response("405 Method Not Allowed. Try using the 'POST' or 'DELETE' or 'PATCH' method.",{status: 405});
		const authHeader = request.headers.get("Authorization");
		if(!authHeader)
			return new Response("401 Unauthorized. Must use some sort of authorization.",{status:401});
		const authType = authHeader.split(" ")[0].toLowerCase();
		if(authType != "session")
			return new Response("401 Unauthorized. Try using the 'Session' authorization header.", {status: 401});

		const user = await session.getUserIfSession(request, env);
		if(!user)
			return new Response("401 Unauthorized. That session does not exist or is invalid.", {status: 401});

		const json = await request.json();
		if(request.method == "POST"){
			if(!json.name || !json.redirect_uri || !json.client_type)
				return new Response("400 Bad Request. Missing a parameter. Either name, redirect_uri, or client_type.", {status: 400});
			if(!validUsername(json.name))
				return new Response("400 Bad Request. Name is not valid.", {status: 400});
			try {
				const url = new URL(json.redirect_uri);
				if(url.protocol != 'https:' && url.hostname != 'localhost')
					return new Response("400 Bad Request. Must use 'https' OR 'localhost'. If you used '127.0.0.1' just change it to 'localhost'.",{status:400});
			} catch (error) {
				return new Response("400 Bad Request. Not A valid URL.", {status:400});
			}
			if(json.client_type != 'public' && json.client_type != 'confidential')
				return new Response("400 Bad Request. There are only two types of OAuth 2.0 Clients.", {status:400});
			const oldClient = await db.getOAuthClientFromName(env, json.name);
			if(oldClient)
				return new Response("400 Bad Request. Client name is already in use.",{status:400});

			const client_id = generateSecureChars(32);
			const client_secret = "shh-" + generateSecureChars(16) + "-" + generateSecureChars(16);
			const client_secret_hash = await base64SHA256(client_secret);

			await db.createOAuthClient(env, client_id, client_secret_hash, json.redirect_uri, json.client_type, json.name, user.userID);
			return new Response(JSON.stringify({
				client_secret: client_secret,
				client_id: client_id,
				name: json.name,
		}));

	} else if(request.method == 'DELETE'){
		if(!json.client_id)
			return new Response("400 Bad Request. Missing the client_id parameter.",{status:400});

		const client = await db.getOAuthClientFromClientID(env, json.client_id);
		if(!client)
			return new Response("400 Bad Request. Client does not exist.");
		if(client.ownerUserID != user.userID)
			return new Response("400 Bad Request. User does not own client.",{status:401});

		await db.deleteOAuthClientFromClientID(env, client.client_id);
		return new Response("ok");
	} else if(request.method == 'PATCH'){
		if(!json.name || !json.redirect_uri || !json.client_type || !json.client_id)
			return new Response("400 Bad Request. Missing a parameter. Either name, redirect_uri, client_id, or client_type.", {status: 400});
		if(!validUsername(json.name))
			return new Response("400 Bad Request. Name is not valid.", {status: 400});
		try {
			const url = new URL(json.redirect_uri);
			if(url.protocol != 'https:' && url.hostname != 'localhost')
				return new Response("400 Bad Request. Must use 'https' OR 'localhost'. If you used '127.0.0.1' just change it to 'localhost'.",{status:400});
		} catch (error) {
			return new Response("400 Bad Request. Not A valid URL.", {status:400});
		}
		if(json.client_type != 'public' && json.client_type != 'confidential')
			return new Response("400 Bad Request. There are only two types of OAuth 2.0 Clients.", {status:400});

		const client = await db.getOAuthClientFromClientID(env, json.client_id);
		if(!client)
			return new Response("400 Bad Request. Client does not exist.");
		if(client.ownerUserID != user.userID)
			return new Response("400 Bad Request. User does not own client.",{status:401});
		if(json.name != client.name){
			const oldClient = await db.getOAuthClientFromName(env, json.name);
			if(oldClient && oldClient.client_id != client.client_id)
				return new Response("400 Bad Request. Client name is already in use.",{status:400});
		}

		await db.updateOAuthClient(env, client.client_id, json.redirect_uri, json.client_type, json.name);
		return new Response("Sounds good!");
	}
}
