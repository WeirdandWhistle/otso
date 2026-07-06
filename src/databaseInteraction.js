// oauth state
export async function oauthStatePut(env, k, v){
    await env.OTSO_DB
        // .prepare("INSERT INTO OAuthState (stateID, stateData) VALUES (?, ?);")
        // .prepare(`
        //     MERGE INTO OAuthState AS target
        //     USING (SELECT ? AS stateID, ? AS stateData) AS source
        //     ON target.stateID = source.stateID
        //     WHEN MATCHED THEN
        //         UPDATE SET stateData=source.stateData
        //     WHEN NOT MATCHED THEN
        //         INSERT (stateID, stateData) VALUES (?, ?);
        //     `)
        .prepare("INSERT OR REPLACE INTO OAuthState (stateID, stateData) VALUES (?, ?);")
        .bind(k, v)
        .run();
}
export async function oauthStateGet(env, k){
    const res = await env.OTSO_DB
        .prepare("SELECT stateData FROM OAuthState WHERE stateID=? LIMIT 1;")
        .bind(k)
        .run();
    return res.results[0].stateData;
}
export async function oauthStateDelete(env, k) {
    await env.OTSO_DB
        .prepare("DELETE FROM OAuthState WHERE stateID=?;")
        .bind(k)
        .run();
}
// user
export async function getUser(env, id, provider) {
    const { results } = await env.OTSO_DB
        .prepare("SELECT * FROM users WHERE userID=(SELECT userID FROM OAuthIssuers WHERE id=? AND issuer=? LIMIT 1) LIMIT 1;")
        .bind(id, provider)
        .run();

    if(results.length > 0)
        return results[0];
    return null;
}