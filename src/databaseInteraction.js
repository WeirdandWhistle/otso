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
export async function getUserFromUsername(env, username){
	return returnResults(await env.OTSO_DB
		.prepare(`
			SELECT * FROM Users WHERE username=? LIMIT 1;
			`)
		.bind(username)
		.run());
}
export async function getUserFromEmail(env, email){
	const raw = await env.OTSO_DB
		.prepare(`
			SELECT * FROM Users WHERE email=? LIMIT 1;
			`)
		.bind(email)
		.run();
	if(raw.results.length <= 0)
		return null;
	return raw.results;

}
export async function updateUser(env, userID, authenticationMethods, authorizedApps, email, username) {
	await env.OTSO_DB
		.prepare(`
			UPDATE Users
			SET authenticationMethods=?, authorizedApps=?, email=?, username=?
			WHERE userID=?;
			`)
		.bind(authenticationMethods ?? '', authorizedApps ?? '', email ?? null, username, userID)
		.run();
}
export async function createOAuthIssuer(env, ID, issuer, username, email, access_token, refresh_token, userID) {
	await env.OTSO_DB
		.prepare(`
			INSERT INTO OAuthIssuers (ID, issuer, username, email, access_token, refresh_token, userID)
			VALUES (?, ?, ?, ?, ?, ?, ?);
			`)
		.bind(ID, issuer, username ?? null, email ?? null, access_token ?? null, refresh_token ?? null, userID)
		.run();
}
export async function createUser(env, userID, username, email, issuer, id, issuerUsername, issuerEmail, access_token, refresh_token){
	if(!issuer)
		throw new Error("issuer is null");
	if(!userID)
		throw new Error("userID is null");
	if(!id)
		throw new Error("issuer id is null");
    await env.OTSO_DB
        .prepare(`
            INSERT INTO Users (userID, authenticationMethods, email, username)
                VALUES (?, ?, ?, ?);
            `)
        .bind(userID, issuer, email ?? null, username ?? null) // id, issuer, issuerUsername, issuerEmail, access_token, refresh_token, userID
        .run();
    await env.OTSO_DB
        .prepare(`
            INSERT INTO OAuthIssuers (ID, issuer, username, email, access_token, refresh_token, userID)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            `)
        .bind(id, issuer, issuerUsername ?? null, issuerEmail ?? null, access_token ?? null, refresh_token ?? null, userID)
        .run();
}
export async function setAuthorizedApp(env, userID, authorizedApps) {
    await env.OTSO_DB
        .prepare(`
            UPDATE Users SET authorizedApps=? WHERE userID=?;
            `)
        .bind(authorizedApps, userID)
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
export async function createSession(env, sessionID, userID, sessionData){
    await env.OTSO_DB
        .prepare(`
            INSERT INTO Sessions (sessionID, userID, sessionData)
            VALUES (?, ?, ?);
            `)
        .bind(sessionID, userID, sessionData)
        .run();
}
export async function deleteSession(env, sessionID){
	await env.OTSO_DB
		.prepare(`
			DELETE FROM Sessions WHERE sessionID=?;
			`)
		.bind(sessionID)
		.run()
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
export async function deleteOAuthClientFromClientID(env, client_id){
	await env.OTSO_DB
		.prepare(`
			DELETE FROM OAuthTokens WHERE client_id=?;
			`)
		.bind(client_id)
		.run();
	await env.OTSO_DB
		.prepare(`
			DELETE FROM OAuthClients WHERE client_id=? LIMIT 1;
			`)
		.bind(client_id)
		.run();
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
export async function getOAuthClientFromName(env, name){
	return returnResults(await env.OTSO_DB
		.prepare(`
			SELECT * FROM OAuthClients WHERE name=? LIMIT 1;
			`)
		.bind(name)
		.run()
	);
}
export async function createOAuthClient(env, client_id, client_secret_hash, redirection_URIs, client_type, name, ownerUserID) {
	await env.OTSO_DB
		.prepare(`
			INSERT INTO OAuthClients (client_id, client_secret_hash, redirection_URIs, client_type, name, ownerUserID)
			VALUES (?, ?, ?, ?, ?, ?);
			`)
		.bind(client_id, client_secret_hash, redirection_URIs, client_type, name, ownerUserID)
		.run();
}
export async function updateOAuthClient(env, client_id, redirection_URIs, client_type, name){
	await env.OTSO_DB
		.prepare(`
			UPDATE OAuthClients
			SET redirection_URIs=?, client_type=?, name=?
			WHERE client_id=?;
			`)
		.bind(redirection_URIs, client_type, name, client_id)
		.run();
}
export async function updateOAuthClientSecretHash(env, client_id, client_secret_hash){
	await env.OTSO_DB
		.prepare(`
			UPDATE OAuthClients
			SET client_secret_hash=?
			WHERE client_id=?;
			`)
		.bind(client_secret_hash, client_id)
		.run()
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
