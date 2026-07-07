import * as db from "./databaseInteraction.js"

export async function issueSession(env, userID, headers){
    const sessionID = generateSecureChars(64);
    const sessionData = "{}";
    await db.createSession(env, sessionID, userID, sessionData);
    return sessionID;
}
export function getCookie(sessionID){
    return `session=${sessionID}; HttpOnly`;
}

const generateSecureChars = (length) => {
	const buf = new Uint8Array(length+1);
	crypto.getRandomValues(buf);
    // console.log("base64 secureChars", buf.toBase64({alphabet: "base64url", omitPadding: true}));
	return buf.toBase64({alphabet: "base64url", omitPadding: true}).substring(0,length-1);
};