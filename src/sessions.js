import * as db from "./databaseInteraction.js"
import { validUsername, correctUsername, base64SHA256, generateRandomString, generateSecureChars } from './randomData.js';

export async function issueSession(env, userID, headers){
	const sessionID = generateSecureChars(64);
	const sessionData = "{}";
	await db.createSession(env, sessionID, userID, sessionData);
	return sessionID;
}
export function getCookie(sessionID){
    return `session=${sessionID}; HttpOnly; Path=/`;
}
// if request has valid session then get the user profile ELSE null
export async function getUserIfSession(request, env){
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
	const userID = await db.getUserIDFromSession(env, sessionID);
	if(!userID)
		return null;
	return await db.getUserFromUserID(env, userID);
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
