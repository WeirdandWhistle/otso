import * as db from "./databaseInteraction.js"

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
    console.log(userID);
    if(!userID)
        return null;
    return await db.getUserFromUserID(env, userID);
}

const generateSecureChars = (length) => {
	const buf = new Uint8Array(length+1);
	crypto.getRandomValues(buf);
    // console.log("base64 secureChars", buf.toBase64({alphabet: "base64url", omitPadding: true}));
	return buf.toBase64({alphabet: "base64url", omitPadding: true}).substring(0,length-1);
};