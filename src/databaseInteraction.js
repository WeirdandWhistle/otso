function returnResults(raw){
    if(raw.results.length > 0)
        return raw.results[0];
    return null;
}
// user
export async function getUserFromIssuer(env, id, issuer) {
    return returnResults(await env.OTSO_DB
        .prepare("SELECT * FROM users WHERE userID=(SELECT userID FROM OAuthIssuers WHERE id=? AND issuer=? LIMIT 1) LIMIT 1;")
        .bind(id, issuer)
        .run());
}
export async function getUserFromUserID(env, userID) {
    return returnResults(await env.OTSO_DB
        .prepare("SELECT * FROM users WHERE userID=? LIMIT 1;")
        .bind(userID)
        .run());
}
export async function createUser(env, userID, username, email, issuer, id, issuerUsername, issuerEmail, access_token, refresh_token){
    await env.OTSO_DB
        .prepare(`
            INSERT INTO Users (userID, authenticationMethods, email, username)
                VALUES (?, ?, ?, ?);
            `)
        .bind(userID, issuer, email, username) // id, issuer, issuerUsername, issuerEmail, access_token, refresh_token, userID
        .run();
    await env.OTSO_DB
        .prepare(`
            INSERT INTO OAuthIssuers (ID, issuer, username, email, access_token, refresh_token, userID)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            `)
        .bind(id, issuer, issuerUsername, issuerEmail, access_token, refresh_token, userID)
        .run();
}
export async function addAuthorizedApp(env, userID, client_id) {
    await env.OTSO_DB
        .prepare(`
            UPDATE Users SET authorizedApps = authorizedApps || ' ' || ? WHERE userID=?;
            `)
        .bind(client_id, userID)
        .run();
}

export async function getUserIDFromSession(env, sessionID) {
    const temp = returnResults(await env.OTSO_DB
        .prepare(`
                SELECT userID FROM Sessions WHERE sessionID=? LIMIT 1;
            `)
        .bind(sessionID)
        .run());
		if(!temp)
			return null;
		return temp.userID;
}
export async function createSession(env, sessionID, userID, sessionData) {
    await env.OTSO_DB
        .prepare(`
            INSERT INTO Sessions (sessionID, userID, sessionData)
            VALUES (?, ?, ?);
            `)
        .bind(sessionID, userID, sessionData)
        .run();
}

// OAuthClients
export async function getOAuthClientFromClientID(env, client_id) {
    return returnResults(await env.OTSO_DB
        .prepare(`
            SELECT * FROM OAuthClients WHERE client_id=? LIMIT 1;
            `)
        .bind(client_id)
        .run()
    );
}
export async function getOAuthClientsFromUserID(env, userID){
	const raw = await env.OTSO_DB
		.prepare(`
			SELECT * FROM OAuthClients WHERE ownerUserID=?;
			`)
		.bind(userID)
		.run();
	if(!raw)
		return null;
	const results = raw.results;
	if(results.length <= 0)
		return null;
	return results;

}
// OAuthTokens
export async function createOAuthToken(env, access_token, expires, scopes, refresh_token, userID, client_id) {
    await env.OTSO_DB
        .prepare(`
            INSERT INTO OAuthTokens (access_token, expires, scopes, refresh_token, userID, client_id)
            VALUES (?, ?, ?, ?, ?, ?);
            `)
        .bind(access_token, expires, scopes, refresh_token, userID, client_id)
        .run()
}
