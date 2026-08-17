import * as db from "./databaseInteraction.js"
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars, safeCompareString } from './randomData.js';
var platform = require('platform');

export async function issueSession(env, userID, headers){
	const sessionID = generateSecureChars(64);
	
	const info = platform.parse(headers.get("User-Agent"));
	const sessionData = JSON.stringify({
		browser: info.name,
		browserVersion: info.version,
		os: info.os,
		ip: headers.get("CF-Connecting-IP"),
	});

	await db.createSession(env, sessionID, userID, sessionData);
	return sessionID;
}
export function getCookie(sessionID){
    return `session=${sessionID}; HttpOnly; Path=/; SameSite=Lax`;
}
export function getSessionID(request){
	const cookiesArray = request.headers.get("Cookie") ? request.headers.get("Cookie").split(";") : null;
	if(!cookiesArray)
		return null;
	let sessionID;
	for(const cookie of cookiesArray){
		if(cookie.split("=")[0] == "session")
			sessionID = cookie.split("=")[1];
	}

	if(!sessionID)
		return null;
	return sessionID;

}
// if request has valid session then get the user profile ELSE null
export async function getUserIfSession(request, env){
	const sessionID = getSessionID(request);
	if(!sessionID)
		return null;
	const userID = await db.getUserIDFromSession(env, sessionID);
	if(!userID)
		return null;
	const temp = await db.getUserFromUserID(env, userID);
	return temp;
}
export async function clearSession(request, env){
	const cookiesArray = request.headers.get("Cookie") ? request.headers.get("Cookie").split(";") : null;
	if(!cookiesArray)
			return null;
	let sessionID;
	for(const cookie of cookiesArray){
		if(cookie.split("=")[0] == "session")
			sessionID = cookie.split("=")[1];
	}
	if(sessionID)
		await db.deleteSession(env, sessionID);
	return new Response("good to go :)",{
		status: 200,
		headers:{
			'Set-Cookie': 'session=deleted; Path=/; HttpOnly; expires=Thu, 01 Jan 1970 00:00:00 GMT'
		}
	});
}

export async function createCSRFToken(KV, userID, sessionID){
	const token = `${generateRandomString(10)}.${generateRandomString(10)}.${generateRandomString(10)}`;
	await KV.put(`CSRFToken.${token}`, token + '.' + userID + '.' + sessionID, 1 * 60);
	return token;
}
export async function useCSRFToken(request, env, KV){
	const token = request.headers.get('CSRFToken');
	if(!token)
		return false;
	const data = await KV.get(`CSRFToken.${token}`);
	if(!data)
		return false;
	await KV.remove(token);
	const sessionID = getSessionID(request);
	if(!sessionID)
		return false;
	const user = await getUserIfSession(request, env);
	if(!user)
		return false;
	if(!safeCompareString(data, `${token}.${user.userID}.${sessionID}`))
		return false;
	return true;
}
export async function revokeSessionAPI(request, env, KV){
	if(await useCSRFToken(request, env, KV) != true)
		return new Response("401 Unauthorized. Wrong CSRFToken.",{status:401});
	const user = await getUserIfSession(request, env);
	if(!user)
		return new Response(`401 Unauthorized. Session is invalid.`, {status: 401});
	if(request.method != 'DELETE')
		return new Response(`405 Method Not Allowed. Try using 'DELETE'.`, {status: 405});
	const timestamp = await request.text();

	await db.deleteSessionFromTimestamp(env, timestamp);

	return new Response('OK');
}
export async function CSRFTokenEndpoint(request, env, KV){
	if(request.method == 'OPTIONS'){
		return new Response(null,{
			status: 204,
			headers:{
				'Access-Control-Allow-Origin': env.HOST,
				'Access-Control-Allow-Methods': 'OPTIONS, PUT'
			}
		});
	}
	if(request.method != 'PUT')
		return new Response("405 Method Not Allowed.",{status:405});
	const referer = new URL(request.headers.get('Referer'));
	if(new URL(request.url).origin != referer.origin)
		return new Response("401 Unauthorized.",{status:401});

	const sessionID = getSessionID(request);
	if(!sessionID)
		return new Response("401 Unauthorized. No session.",{status:401});
	const user =  await getUserIfSession(request, env);
	if(!user)
		return new Response("401 Unauthorized. Invalid session.",{status:401});

	const token = await createCSRFToken(KV, user.userID, sessionID);

	return new Response(token);
}
export async function getScopesFromAccessToken(request, env){
	if(request.headers.get('Authorization').split(" ").length < 2) return null;
	const access_token = request.headers.get('Authorization').split(" ")[1];
	const tokens = await db.getOAuthTokenFromAccessToken(env, access_token);
	if(!tokens) return null;
	if(tokens.expires <= Date.now()/1000) return null;
	return tokens;
}

