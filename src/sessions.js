import * as db from "./databaseInteraction.js"
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars } from './randomData.js';
import crypto from 'crypto';

export async function issueSession(env, userID, headers){
	const sessionID = generateSecureChars(64);
	const sessionData = "{}";
	await db.createSession(env, sessionID, userID, sessionData);
	return sessionID;
}
export function getCookie(sessionID){
    return `session=${sessionID}; HttpOnly; Path=/; SameSite=Strict`;
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
	KV.put(`CSRFToken.${token}`, token + '.' + userID + '.' + sessionID, 1 * 60);
	return token;
}
export async function useCSRFToken(request, env, KV){
	const token = request.headers.get('CSRFToken');
	if(!token)
		return false;
	const data = KV.get(`CSRFToken.${token}`);
	if(!data)
		return false;
	KV.remove(token);
	const sessionID = getSessionID(request);
	if(!sessionID)
		return false;
	const user = await getUserIfSession(request, env);
	if(!user)
		return false;
	const bufA = Buffer.from(data);
	const bufB = Buffer.from(`${token}.${user.userID}.${sessionID}`)
	if(!crypto.timingSafeEqual(bufA, bufB))
		return false;
	return true;
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
	console.log(new URL(env.HOST).origin,'and',referer.origin);
	if(new URL(env.HOST).origin != referer.origin)
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

